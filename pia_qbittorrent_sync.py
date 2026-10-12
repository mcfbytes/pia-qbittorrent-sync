#!/usr/bin/env python3
"""
PIA Port Updater Service

Retrieves the forwarded port from Private Internet Access (PIA) and keeps
qBittorrent's listening port in sync with it. If the PIA gateway stays
unreachable for too long, the service fails over to another port-forwarding
capable PIA WireGuard server.
"""

import base64
import concurrent.futures
import json
import logging
import os
import re
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Set

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger('pia_updater')

# PIA auth tokens are valid for 24 hours. Treat a cached token as spent slightly
# early so one never expires between getSignature and the requests that follow.
TOKEN_MAX_AGE_SECONDS = 23 * 60 * 60
# Floor on how often we may ask PIA for a new token. Without this, a token that
# PIA keeps rejecting would turn the retry path into a tight loop against PIA's
# auth API.
MIN_TOKEN_REQUEST_INTERVAL_SECONDS = 60
# PIA wants the port binding refreshed at least every 15 minutes; we do it every 5.
BIND_REFRESH_SECONDS = 300
# Refresh the signature this long before the port expires.
EXPIRY_MARGIN = timedelta(minutes=15)

TOKEN_URL = 'https://www.privateinternetaccess.com/api/client/v2/token'
SERVER_LIST_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
PF_API_PORT = 19999
WG_API_PORT = 1337
HTTP_TIMEOUT = 10

# Tags the /etc/hosts line this service manages.
HOSTS_MARKER = '# managed by pia-qbittorrent-sync'

# Stored in normalized (casefolded) form; the password is normalized before comparison.
INSECURE_PASSWORDS = {'admin', 'adminadmin', 'password', 'change_me', 'changeme'}


class ConfigError(Exception):
    """Invalid or missing configuration; holds one message per problem."""

    def __init__(self, errors: List[str]):
        super().__init__('; '.join(errors))
        self.errors = errors


class PIAAuthError(Exception):
    """PIA rejected a token it had just issued.

    This is a configuration/account problem (bad credentials, a gateway that
    isn't the port-forwarding server for this session, a region without port
    forwarding), not a transient one: retrying cannot fix it, so the service
    exits with EX_CONFIG rather than restart-looping.
    """


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class Config:
    pia_username: Optional[str]
    pia_password: Optional[str]
    gateway: str
    hostname: Optional[str]
    ca_cert: str
    token_file: str
    qbt_host: str
    qbt_username: Optional[str]
    qbt_password: Optional[str]
    check_interval: int
    retry_interval: int
    failover_timeout: int
    config_file: Optional[str]
    hosts_file: str
    wg_config: str
    wg_down_cmd: List[str]
    wg_up_cmd: List[str]
    log_level: str
    log_file: str

    @property
    def wg_interface(self) -> str:
        return Path(self.wg_config).stem

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> 'Config':
        errors: List[str] = []

        def integer(name: str, default: int, lo: int, hi: int) -> int:
            raw = env.get(name, str(default))
            try:
                value = int(raw)
            except ValueError:
                errors.append(f"{name} must be an integer, got {raw!r}")
                return default
            if not lo <= value <= hi:
                errors.append(f"{name} must be between {lo} and {hi}, got {value}")
                return default
            return value

        log_level = env.get('LOG_LEVEL', 'INFO').upper()
        if not isinstance(getattr(logging, log_level, None), int):
            errors.append(
                f"Invalid LOG_LEVEL {env.get('LOG_LEVEL')!r}. "
                "Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
            )

        check_interval = integer('CHECK_INTERVAL', 300, 1, 86400)
        retry_interval = min(integer('RETRY_INTERVAL', 30, 1, 3600), check_interval)
        failover_timeout = integer('FAILOVER_TIMEOUT', 300, 0, 86400)

        token_file = env.get('PIA_TOKEN_FILE', '/var/run/pia_token')
        username, password = env.get('PIA_USERNAME'), env.get('PIA_PASSWORD')
        if not (username and password) and not _is_readable_file(token_file):
            errors.append(
                "PIA credentials not configured. Set PIA_USERNAME and PIA_PASSWORD, "
                "or provide a readable regular file in PIA_TOKEN_FILE."
            )

        ca_cert = env.get('PIA_CA_CERT', '')
        if not ca_cert:
            # Connecting to the PIA gateway without a CA certificate would
            # silently disable verification and allow man-in-the-middle attacks.
            errors.append(
                "PIA_CA_CERT is required. Set it to the path of the PIA CA certificate "
                "file (e.g. ca.rsa.4096.crt). Running without one is not permitted."
            )
        elif not _is_readable_file(ca_cert):
            errors.append(
                f"PIA_CA_CERT {ca_cert!r} is not a readable regular file. "
                "Check the path, permissions and ownership."
            )

        if not (env.get('QBITTORRENT_USERNAME') or '').strip():
            errors.append("QBITTORRENT_USERNAME is not set")
        qbt_password = (env.get('QBITTORRENT_PASSWORD') or '').strip().casefold()
        if not qbt_password:
            errors.append("QBITTORRENT_PASSWORD is not set")
        elif qbt_password in INSECURE_PASSWORDS:
            errors.append("QBITTORRENT_PASSWORD is set to a known insecure default value")

        if errors:
            raise ConfigError(errors)

        wg_config = env.get('PIA_WG_CONFIG', '/etc/wireguard/wg0.conf')
        interface = Path(wg_config).stem
        return cls(
            pia_username=username,
            pia_password=password,
            gateway=env.get('PIA_GATEWAY', '10.0.0.1'),
            hostname=env.get('PIA_HOSTNAME') or None,
            ca_cert=ca_cert,
            token_file=token_file,
            qbt_host=env.get('QBITTORRENT_HOST', 'http://localhost:8080'),
            qbt_username=env.get('QBITTORRENT_USERNAME'),
            qbt_password=env.get('QBITTORRENT_PASSWORD'),
            check_interval=check_interval,
            retry_interval=retry_interval,
            failover_timeout=failover_timeout,
            config_file=env.get('PIA_CONFIG_FILE') or None,
            hosts_file=env.get('PIA_HOSTS_FILE', '/etc/hosts'),
            wg_config=wg_config,
            wg_down_cmd=shlex.split(env.get('PIA_WG_DOWN_CMD', f'sudo -n wg-quick down {interface}')),
            wg_up_cmd=shlex.split(env.get('PIA_WG_UP_CMD', f'sudo -n wg-quick up {interface}')),
            log_level=log_level,
            log_file=env.get('LOG_FILE', '/var/log/pia_updater.log'),
        )


def _is_readable_file(path: str) -> bool:
    p = Path(path)
    return p.is_file() and os.access(p, os.R_OK)


def setup_logging(log_file: str, level: str) -> None:
    """Log to log_file (mode 0600) when its directory is writable, else to stderr."""
    handler: logging.Handler = logging.StreamHandler()
    if os.access(os.path.dirname(log_file) or '.', os.W_OK):
        try:
            # Enforce 0600 even if the file already existed with broader permissions.
            fd = os.open(log_file, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.fchmod(fd, 0o600)
                handler = logging.StreamHandler(os.fdopen(fd, 'a'))
            except OSError:
                os.close(fd)
        except OSError:
            pass
    logging.basicConfig(
        level=getattr(logging, level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[handler],
    )


# --------------------------------------------------------------------------- #
# File helpers
# --------------------------------------------------------------------------- #

def write_private_file(path: str, data: str) -> None:
    """Atomically replace path with data (mode 0600); never leaves a partial file."""
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.token_')
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data.encode())
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        tmp = ''
    finally:
        if fd != -1:
            os.close(fd)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def write_in_place(path: str, text: str) -> None:
    """Overwrite an existing file without replacing its inode.

    /etc/hosts and /etc/wireguard live in directories the service user cannot
    write to, so a rename-based replace is impossible; only the files
    themselves are made group-writable.
    """
    with open(path, 'r+', encoding='utf-8') as f:
        f.seek(0)
        f.write(text)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


def read_text(path: str) -> str:
    with open(path, encoding='utf-8') as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Config-file rewriting (pure functions)
# --------------------------------------------------------------------------- #

def render_hosts(text: str, hostname: str, ip: str) -> str:
    """Return hosts-file text mapping hostname to ip via a single managed line.

    Drops any earlier managed line, and any unmanaged line whose only name is
    hostname (it would otherwise shadow ours). The name is written lowercase,
    since HTTP clients lowercase hostnames and musl matches hosts entries
    case-sensitively; certificate validation is case-insensitive.
    """
    hostname = hostname.lower()
    kept = []
    for line in text.splitlines():
        if line.rstrip().endswith(HOSTS_MARKER):
            continue
        fields = line.split('#', 1)[0].split()
        if len(fields) == 2 and fields[1].lower() == hostname:
            continue
        kept.append(line)
    kept.append(f'{ip} {hostname} {HOSTS_MARKER}')
    return '\n'.join(kept) + '\n'


def update_env_file(text: str, values: Mapping[str, str]) -> str:
    """Set KEY=value pairs in a shell/EnvironmentFile-style config.

    Keeps `export `, the quoting style and trailing comments of existing lines;
    keys that are absent are appended.
    """
    remaining = dict(values)
    out = []
    for line in text.splitlines():
        for key in list(remaining):
            m = re.match(rf'^(\s*(?:export\s+)?{re.escape(key)}=)("[^"]*"|\'[^\']*\'|\S*)(.*)$', line)
            if m:
                quote = m.group(2)[:1] if m.group(2)[:1] in '"\'' else ''
                line = f'{m.group(1)}{quote}{remaining.pop(key)}{quote}{m.group(3)}'
                break
        out.append(line)
    out.extend(f'{key}="{value}"' for key, value in remaining.items())
    return '\n'.join(out) + '\n'


def _wg_lines(text: str):
    """Yield (section, key, value, raw_line) for each line of a wg-quick config."""
    section = None
    for raw in text.splitlines():
        m = re.match(r'^\s*\[(\w+)\]\s*$', raw)
        if m:
            section = m.group(1).lower()
            yield section, None, None, raw
            continue
        m = re.match(r'^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$', raw)
        yield section, (m.group(1).lower() if m else None), (m.group(2) if m else None), raw


def wg_private_key(text: str) -> Optional[str]:
    return next((v for s, k, v, _ in _wg_lines(text) if (s, k) == ('interface', 'privatekey')), None)


def rewrite_wg_config(text: str, address: str, server_pubkey: str, endpoint: str) -> str:
    """Point a wg-quick config at a new server, leaving all other settings alone."""
    replacements = {
        ('interface', 'address'): address,
        ('peer', 'publickey'): server_pubkey,
        ('peer', 'endpoint'): endpoint,
    }
    done = set()
    out = []
    for section, key, _, raw in _wg_lines(text):
        if (section, key) in replacements:
            raw = f'{raw.split("=", 1)[0].strip()} = {replacements[(section, key)]}'
            done.add((section, key))
        out.append(raw)
    missing = set(replacements) - done
    if missing:
        names = ', '.join(f'[{s.capitalize()}] {k}' for s, k in sorted(missing))
        raise ValueError(f"WireGuard config is missing {names}")
    return '\n'.join(out) + '\n'


class _PIACAAdapter(HTTPAdapter):
    """Verify TLS against the PIA CA, minus Python's strict X.509 profile.

    Python 3.13+ enables VERIFY_X509_STRICT by default, which rejects PIA's CA
    certificate ("Basic Constraints of CA cert not marked critical"). OpenSSL's
    own defaults, which curl and PIA's scripts use, accept it. The chain and the
    server name are still verified.
    """

    def __init__(self, ca_cert: str):
        self._context = ssl.create_default_context(cafile=ca_cert)
        self._context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self._context
        super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        pass  # the CA is already in self._context


def pia_session(ca_cert: str) -> requests.Session:
    """A requests session that trusts only the PIA CA."""
    session = requests.Session()
    session.mount('https://', _PIACAAdapter(ca_cert))
    return session


# --------------------------------------------------------------------------- #
# PIA server list
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class WireGuardServer:
    region_id: str
    region_name: str
    hostname: str
    ip: str


def parse_server_list(raw: str) -> List[dict]:
    """Return the regions from a serverlist response.

    The response is the JSON document on the first line followed by a signature.
    """
    first_line = raw.split('\n', 1)[0]
    return json.loads(first_line)['regions']


def rank_candidates(regions: Iterable[dict], current_hostname: Optional[str],
                    avoid: Set[str], latencies: Mapping[str, float]) -> List[WireGuardServer]:
    """Order port-forwarding WireGuard servers by preference.

    Only online regions with port_forward=true qualify, as in the `.port_forward`
    filter of manual-connections' get_region.sh. Other servers in the current
    region come first (same location), then other regions by lowest latency.
    Regions that did not answer the latency probe are skipped.
    """
    current_region = None
    candidates: List[WireGuardServer] = []
    for region in regions:
        if not region.get('port_forward') or region.get('offline'):
            continue
        for wg in region.get('servers', {}).get('wg', []):
            if wg['cn'].lower() == (current_hostname or '').lower():
                current_region = region['id']
            elif wg['cn'].lower() not in avoid:
                candidates.append(WireGuardServer(region['id'], region.get('name', region['id']),
                                                  wg['cn'], wg['ip']))
    reachable = [c for c in candidates if c.region_id in latencies]
    reachable.sort(key=lambda c: (c.region_id != current_region, latencies[c.region_id]))
    return reachable


def tcp_latency(ip: str, port: int = 443, timeout: float = 2.0) -> Optional[float]:
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return time.monotonic() - start
    except OSError:
        return None


def measure_region_latencies(regions: Iterable[dict]) -> Dict[str, float]:
    """TCP connect time to each port-forwarding region's first meta server."""
    targets = {r['id']: r['servers']['meta'][0]['ip'] for r in regions
               if r.get('port_forward') and not r.get('offline') and r.get('servers', {}).get('meta')}
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = dict(zip(targets, pool.map(tcp_latency, targets.values())))
    return {region: t for region, t in results.items() if t is not None}


# --------------------------------------------------------------------------- #
# PIA port forwarding
# --------------------------------------------------------------------------- #

class PIAPortForwarder:
    """Handles PIA authentication and the port forwarding API (getSignature / bindPort)."""

    def __init__(self, cfg: Config):
        self.token_file = cfg.token_file
        self.username = cfg.pia_username
        self.password = cfg.pia_password
        self.gateway = cfg.gateway
        self.hostname = cfg.hostname
        self.session = pia_session(cfg.ca_cert)

        self.token: Optional[str] = None
        # True when self.token was just minted by PIA rather than loaded from
        # disk. If PIA rejects a token this fresh, re-authenticating won't help.
        self.token_is_fresh = False
        self.last_token_request: Optional[float] = None
        # False once a request failed to get a usable HTTP answer from the
        # gateway (timeout, refused, 5xx): the signal that the tunnel is down.
        self.reachable = True
        self._reset_port_state()

    def _reset_port_state(self) -> None:
        self.payload: Optional[str] = None
        self.signature: Optional[str] = None
        self.current_port: Optional[int] = None
        self.port_expiry: Optional[datetime] = None
        self.last_refresh: Optional[datetime] = None

    def set_server(self, hostname: str, gateway: str) -> None:
        """Switch to another server; its signature and port are unrelated to the old one's."""
        self.hostname, self.gateway = hostname, gateway
        self._reset_port_state()
        self.reachable = True

    @property
    def base_url(self) -> str:
        # With a hostname the TLS certificate matches (the name resolves to the
        # gateway through /etc/hosts); otherwise the certificate must cover the IP.
        return f'https://{self.hostname or self.gateway}:{PF_API_PORT}'

    # -- token ------------------------------------------------------------- #

    def get_token(self, force_refresh: bool = False) -> Optional[str]:
        """Return a PIA token from the token file, or mint one with the account credentials.

        Set force_refresh to skip the cached token, e.g. after PIA rejected it.
        """
        if not force_refresh:
            cached = self._read_cached_token()
            if cached:
                self.token = cached
                self.token_is_fresh = False
                logger.info(f"Loaded PIA token from {self.token_file}")
                return cached
        return self._request_new_token()

    def _read_cached_token(self) -> Optional[str]:
        """Return the on-disk token, or None if it is missing, empty or expired."""
        try:
            age_seconds = time.time() - os.path.getmtime(self.token_file)
            token = read_text(self.token_file).strip()
        except OSError:
            return None

        if not token:
            logger.warning(f"Token file {self.token_file} is empty, ignoring it")
            return None

        if age_seconds > TOKEN_MAX_AGE_SECONDS:
            age_hours = age_seconds / 3600
            if self.username and self.password:
                logger.info(f"Cached PIA token is {age_hours:.1f}h old (PIA tokens last 24h), "
                            "requesting a new one")
                return None
            # Nothing to re-authenticate with, so a stale token beats no token.
            logger.warning(f"Cached PIA token is {age_hours:.1f}h old and likely expired, but "
                           "PIA_USERNAME/PIA_PASSWORD are not set to refresh it")
        return token

    def _discard_token(self) -> None:
        self.token = None
        self.token_is_fresh = False
        try:
            os.unlink(self.token_file)
            logger.info(f"Removed rejected PIA token from {self.token_file}")
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning(f"Failed to remove token file {self.token_file}: {e}")

    def _request_new_token(self) -> Optional[str]:
        """Authenticate against the PIA API for a new token, at most once a minute."""
        if not self.username or not self.password:
            logger.error("PIA username and password are required to generate token")
            return None

        now = time.monotonic()
        if self.last_token_request is not None:
            since_last = now - self.last_token_request
            if since_last < MIN_TOKEN_REQUEST_INTERVAL_SECONDS:
                logger.warning(f"Skipping token request: last one was {since_last:.0f}s ago and "
                               f"they are rate-limited to one per {MIN_TOKEN_REQUEST_INTERVAL_SECONDS}s")
                return None
        self.last_token_request = now

        try:
            logger.info("Authenticating with PIA API to get token...")
            # PIA's token API rejects URL-encoded forms (HTTP 401); it wants multipart,
            # like manual-connections' `curl --form`.
            response = requests.post(TOKEN_URL, files={'username': (None, self.username),
                                                       'password': (None, self.password)},
                                     timeout=HTTP_TIMEOUT)
            if response.status_code != 200:
                logger.error(f"Failed to get PIA token: {response.status_code} - {response.text}")
                return None
            token = response.json().get('token')
        except (requests.RequestException, ValueError) as e:
            logger.error(f"Failed to get PIA token: {e}")
            return None

        if not token:
            logger.error("No token in API response")
            return None

        self.token = token
        self.token_is_fresh = True
        try:
            write_private_file(self.token_file, token)
            logger.info(f"Saved new PIA token to {self.token_file}")
        except OSError as e:
            logger.warning(f"Failed to save token: {e}")
        return token

    # -- port forwarding API ---------------------------------------------- #

    def _api_get(self, endpoint: str, params: Dict[str, str]) -> Optional[requests.Response]:
        """GET from the gateway; None (and reachable=False) if there was no usable answer."""
        url = f'{self.base_url}/{endpoint}'
        try:
            response = self.session.get(url, params=params, timeout=HTTP_TIMEOUT)
        except requests.RequestException as e:
            self.reachable = False
            logger.error(f"Request to {url} failed: {e}")
            return None
        self.reachable = response.status_code < 500
        return response

    def get_signature(self, allow_token_refresh: bool = True) -> bool:
        """Get a port and signature from PIA, then bind the port.

        A token PIA rejects is discarded and re-minted once (allow_token_refresh
        guards against recursing further). If PIA rejects a token it has just
        issued, that is unrecoverable and raises PIAAuthError.
        """
        if not self.token and not self.get_token():
            logger.error("No PIA token available")
            return False

        logger.info("Getting signature from PIA...")
        response = self._api_get('getSignature', {'token': self.token})
        if response is None:
            return False
        if response.status_code in (401, 403):
            return self._handle_rejected_token(response, allow_token_refresh)
        if response.status_code != 200:
            logger.error(f"Failed to get signature: HTTP {response.status_code} "
                         f"- {response.text.strip()}")
            return False

        try:
            data = response.json()
            payload = json.loads(base64.b64decode(data['payload']))
            port = payload['port']
            expiry = _parse_expiry(payload.get('expires_at'))
            signature = data['signature']
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Unusable getSignature response: {e!r}")
            logger.debug(f"Response: {response.text}")
            return False

        self.payload, self.signature = data['payload'], signature
        self.current_port, self.port_expiry = port, expiry
        logger.info(f"Port {port} obtained from signature"
                    + (f", expires at {expiry}" if expiry else ""))

        # Activate the port straight away. A failure here is retried by the main loop.
        if self.bind_port():
            logger.info(f"Port {port} activated successfully")
        else:
            logger.warning("Failed to activate port with bindPort, but signature obtained")
        return True

    def _handle_rejected_token(self, response: requests.Response, allow_token_refresh: bool) -> bool:
        """Handle PIA rejecting our token on getSignature (HTTP 401/403).

        Returns False if we could not recover; raises PIAAuthError when the
        rejected token was one PIA had just issued, since no amount of retrying
        will make PIA accept it.
        """
        logger.error(f"PIA rejected the token at {self.base_url}: HTTP {response.status_code} "
                     f"- {response.text.strip()}")

        if self.token_is_fresh:
            raise PIAAuthError(
                f"PIA returned HTTP {response.status_code} for a token it had just issued. "
                "The token itself is valid, so check that: (1) PIA_USERNAME/PIA_PASSWORD are "
                "the VPN credentials (the pXXXXXXX username), not a PIA website email login; "
                f"(2) PIA_GATEWAY ({self.gateway}) is the port-forwarding gateway of the server "
                "this host is currently tunnelled through, not a stale or unrelated address; "
                f"(3) PIA_HOSTNAME ({self.hostname}) matches that same server; and (4) the "
                "region supports port forwarding."
            )
        if not allow_token_refresh:
            return False

        logger.info("Cached PIA token was rejected, requesting a new one and retrying once")
        self._discard_token()
        if not self.get_token(force_refresh=True):
            logger.error("Could not obtain a new PIA token after the cached one was rejected")
            return False
        return self.get_signature(allow_token_refresh=False)

    def bind_port(self) -> Optional[int]:
        """Bind/refresh the forwarded port using the stored signature."""
        if not (self.payload and self.signature and self.current_port):
            logger.error("No signature available. Call get_signature() first.")
            return None

        response = self._api_get('bindPort', {'payload': self.payload, 'signature': self.signature})
        if response is None:
            return None
        if response.status_code != 200:
            logger.error(f"Failed to bind port: HTTP {response.status_code}")
            logger.debug(f"Response text: {response.text}")
            return None

        try:
            status = response.json().get('status')
        except (ValueError, AttributeError):
            status = None
        if status != 'OK':
            logger.error(f"Port binding failed: {response.text}")
            return None

        self.last_refresh = datetime.now(timezone.utc)
        logger.info(f"Port {self.current_port} binding refreshed successfully")
        return self.current_port

    def forget_signature(self) -> None:
        """Drop the signature (keeping the token) so the next refresh asks for a new one."""
        self.payload = self.signature = self.last_refresh = None

    # -- lifecycle ----------------------------------------------------------- #

    def refresh(self) -> Optional[int]:
        """Do whatever is due (new signature, binding refresh, nothing); return the port or None."""
        if not self.payload or self.is_expired():
            return self.current_port if self.get_signature() else None
        if self.needs_refresh():
            logger.info("Refreshing port binding...")
            return self.bind_port()
        logger.debug(f"Port {self.current_port} still valid")
        return self.current_port

    def needs_refresh(self) -> bool:
        """True when the port was never bound, the binding is older than BIND_REFRESH_SECONDS, or expiry nears."""
        now = datetime.now(timezone.utc)
        if not self.last_refresh or (now - self.last_refresh).total_seconds() >= BIND_REFRESH_SECONDS:
            return True
        return bool(self.port_expiry and now >= self.port_expiry - EXPIRY_MARGIN)

    def is_expired(self) -> bool:
        if self.port_expiry and datetime.now(timezone.utc) >= self.port_expiry:
            logger.info(f"Port expired at {self.port_expiry}, need to get new signature")
            return True
        return False


def _parse_expiry(value: Optional[str]) -> Optional[datetime]:
    """Parse PIA's RFC 3339 expires_at (which may carry nanoseconds)."""
    if not value:
        return None
    value = re.sub(r'(\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
    return datetime.fromisoformat(value)


# --------------------------------------------------------------------------- #
# qBittorrent
# --------------------------------------------------------------------------- #

class QBittorrentClient:
    """Handles qBittorrent Web API v2 interactions."""

    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False

    def login(self) -> bool:
        try:
            response = self.session.post(f'{self.host}/api/v2/auth/login',
                                         data={'username': self.username, 'password': self.password},
                                         timeout=HTTP_TIMEOUT)
        except requests.RequestException as e:
            logger.error(f"Error logging into qBittorrent: {e}")
            return False

        # Older releases answer 200 "Ok." (or 200 "Fails."); newer ones 204 No Content on success.
        self.authenticated = (response.status_code == 204
                              or (response.status_code == 200 and response.text == 'Ok.'))
        if self.authenticated:
            logger.info("Successfully authenticated with qBittorrent")
        else:
            logger.error(f"qBittorrent authentication failed: HTTP {response.status_code} {response.text!r}")
        return self.authenticated

    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """Send an API request, logging in first and once more on HTTP 403."""
        for attempt in (1, 2):
            if not self.authenticated and not self.login():
                return None
            try:
                response = self.session.request(method, f'{self.host}/api/v2/{path}',
                                                timeout=HTTP_TIMEOUT, **kwargs)
            except requests.RequestException as e:
                logger.error(f"qBittorrent request {path} failed: {e}")
                self.authenticated = False  # re-authenticate next time
                return None
            if response.status_code == 403 and attempt == 1:
                logger.warning("qBittorrent returned 403 Forbidden, re-authenticating...")
                self.authenticated = False
                continue
            return response
        return None

    def get_current_port(self) -> Optional[int]:
        response = self._request('GET', 'app/preferences')
        if response is None or response.status_code != 200:
            if response is not None:
                logger.error(f"Failed to get qBittorrent preferences: {response.status_code}")
            return None
        prefs = response.json()
        port = prefs.get('listen_port')
        logger.info(f"Current qBittorrent listening port: {port}")
        logger.debug(f"qBittorrent random_port={prefs.get('random_port')}")
        return port

    def set_listening_port(self, port: int) -> bool:
        logger.debug(f"Setting qBittorrent port to {port}")
        response = self._request('POST', 'app/setPreferences',
                                 data={'json': json.dumps({'listen_port': port, 'random_port': False})})
        if response is None or response.status_code != 200:
            if response is not None:
                logger.error(f"Failed to set qBittorrent port: {response.status_code}")
            return False

        logger.info(f"Successfully updated qBittorrent port to {port}")
        time.sleep(1)  # Give qBittorrent a moment to apply the change
        verified = self.get_current_port()
        if verified == port:
            logger.info(f"Verified: qBittorrent port is now {port}")
        else:
            logger.warning(f"Port verification mismatch: expected {port}, got {verified}")
        return True


# --------------------------------------------------------------------------- #
# Failover to another PIA server
# --------------------------------------------------------------------------- #

class WireGuardFailover:
    """Moves the host to a different port-forwarding capable PIA WireGuard server.

    A switch means: bring the tunnel down (a dead full tunnel would swallow the
    traffic to the PIA API), pick a server, map its hostname to its IP in the
    hosts file so TLS validates, register our WireGuard key with it (addKey),
    rewrite the wg-quick config and service config, and bring the tunnel up.
    Any failure rolls the files back and restores the old tunnel.
    """

    MAX_ATTEMPTS = 5

    def __init__(self, cfg: Config, pia: PIAPortForwarder):
        self.cfg = cfg
        self.pia = pia
        self.session = pia_session(cfg.ca_cert)
        # Servers abandoned by earlier failovers, not to be picked again soon.
        self.avoid: Set[str] = set()

    def unavailable_reason(self) -> Optional[str]:
        """Why failover can't work with this configuration, or None if it can."""
        if self.cfg.failover_timeout == 0:
            return "FAILOVER_TIMEOUT=0"
        if not self.cfg.hostname:
            return "PIA_HOSTNAME is not set"
        if not _is_readable_file(self.cfg.wg_config):
            return f"WireGuard config {self.cfg.wg_config} is not readable"
        if not (self.cfg.pia_username and self.cfg.pia_password):
            return "failover needs PIA_USERNAME/PIA_PASSWORD to register a key on the new server"
        return None

    # -- hosts file ---------------------------------------------------------- #

    def sync_hosts(self, hostname: str, ip: str) -> bool:
        """Make the hosts file map hostname to ip; leaves the file alone if it already does."""
        try:
            current = read_text(self.cfg.hosts_file)
            updated = render_hosts(current, hostname, ip)
            if updated != current:
                write_in_place(self.cfg.hosts_file, updated)
                logger.info(f"Mapped {hostname} -> {ip} in {self.cfg.hosts_file}")
            return True
        except OSError as e:
            logger.error(f"Cannot update {self.cfg.hosts_file}: {e}")
            return False

    # -- tunnel control ------------------------------------------------------ #

    def _run(self, command: List[str]) -> bool:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.error(f"`{shlex.join(command)}` failed: {e}")
            return False
        if result.returncode != 0:
            logger.error(f"`{shlex.join(command)}` exited {result.returncode}: {result.stderr.strip()}")
            return False
        return True

    def _wg_public_key(self, private_key: str) -> Optional[str]:
        try:
            result = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True,
                                    text=True, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"Could not derive the WireGuard public key (is wireguard-tools installed?): {e}")
            return None
        return result.stdout.strip()

    # -- PIA APIs ------------------------------------------------------------ #

    def _fetch_regions(self) -> Optional[List[dict]]:
        try:
            response = requests.get(SERVER_LIST_URL, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            return parse_server_list(response.text)
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.error(f"Could not fetch the PIA server list: {e}")
            return None

    def _add_key(self, server: WireGuardServer, token: str, public_key: str) -> Optional[dict]:
        """Register our key with the server; returns its addKey answer on success."""
        try:
            response = self.session.get(f'https://{server.hostname}:{WG_API_PORT}/addKey',
                                        params={'pt': token, 'pubkey': public_key},
                                        timeout=HTTP_TIMEOUT)
            data = response.json()
        except (requests.RequestException, ValueError) as e:
            logger.warning(f"addKey on {server.hostname} failed: {e}")
            return None
        if data.get('status') != 'OK':
            logger.warning(f"addKey on {server.hostname} was refused: {data}")
            return None
        return data

    # -- the switch ---------------------------------------------------------- #

    def switch(self) -> Optional[WireGuardServer]:
        """Move to a new server. Returns it, or None if the old setup was left/restored."""
        old_hostname, old_gateway = self.pia.hostname, self.pia.gateway
        logger.warning(f"Failing over: bringing {self.cfg.wg_interface} down to leave {old_hostname}")
        if not self._run(self.cfg.wg_down_cmd):
            logger.warning("Continuing anyway, the interface may already be down")

        try:
            chosen = self._register_on_new_server(old_hostname)
            if chosen and self._apply(*chosen):
                self.avoid.add(old_hostname.lower())
                return chosen[0]
        except Exception:
            logger.exception("Unexpected error during failover")

        logger.error(f"Failover failed, restoring {old_hostname}")
        self.sync_hosts(old_hostname, old_gateway)
        self._run(self.cfg.wg_up_cmd)
        return None

    def _register_on_new_server(self, current_hostname: str):
        """Pick a server and register our key with it; returns (server, addKey answer)."""
        token = self.pia.get_token()
        if not token:
            logger.error("No PIA token available to register with a new server")
            return None
        private_key = wg_private_key(read_text(self.cfg.wg_config))
        public_key = private_key and self._wg_public_key(private_key)
        if not public_key:
            logger.error(f"No usable PrivateKey in {self.cfg.wg_config}")
            return None

        regions = self._fetch_regions()
        if not regions:
            return None
        latencies = measure_region_latencies(regions)
        if not latencies:
            logger.error("No PIA region responded; the internet connection itself seems to be down")
            return None
        candidates = rank_candidates(regions, current_hostname, self.avoid, latencies)
        if not candidates and self.avoid:
            logger.info("Every port-forwarding server was tried already, starting over")
            self.avoid.clear()
            candidates = rank_candidates(regions, current_hostname, self.avoid, latencies)

        for server in candidates[:self.MAX_ATTEMPTS]:
            logger.info(f"Trying {server.hostname} ({server.ip}) in {server.region_name}")
            # The hostname must resolve to the server before TLS validates.
            if self.sync_hosts(server.hostname, server.ip):
                answer = self._add_key(server, token, public_key)
                if answer:
                    return server, answer
        logger.error("No port-forwarding server accepted our key")
        return None

    def _apply(self, server: WireGuardServer, answer: dict) -> bool:
        """Write the new configuration and bring the tunnel up; roll back on failure."""
        wg_old = read_text(self.cfg.wg_config)
        env_old = read_text(self.cfg.config_file) if self.cfg.config_file else None
        try:
            write_in_place(self.cfg.wg_config, rewrite_wg_config(
                wg_old, answer['peer_ip'], answer['server_key'], f"{server.ip}:{answer['server_port']}"))
            if self.cfg.config_file:
                write_in_place(self.cfg.config_file, update_env_file(
                    env_old, {'PIA_GATEWAY': server.ip, 'PIA_HOSTNAME': server.hostname}))
            else:
                logger.warning("PIA_CONFIG_FILE is not set: PIA_GATEWAY/PIA_HOSTNAME are not "
                               "persisted and a restart of this service would use the old server")
            if self._run(self.cfg.wg_up_cmd):
                time.sleep(3)  # let the handshake complete before the next health check
                self.pia.set_server(server.hostname, server.ip)
                logger.info(f"Failed over to {server.hostname} ({server.ip})")
                return True
        except (OSError, KeyError, ValueError) as e:
            logger.error(f"Could not apply the new server configuration: {e}")

        for path, old in ((self.cfg.wg_config, wg_old), (self.cfg.config_file, env_old)):
            if path and old is not None:
                try:
                    write_in_place(path, old)
                except OSError as e:
                    logger.error(f"Could not restore {path}: {e}")
        return False


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #

class PIAUpdaterService:
    """Main service that coordinates PIA, qBittorrent and failover."""

    FAILOVER_RETRY_SECONDS = 60  # doubled after each failed attempt
    FAILOVER_RETRY_MAX_SECONDS = 900

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.pia = PIAPortForwarder(cfg)
        self.qbt = QBittorrentClient(cfg.qbt_host, cfg.qbt_username, cfg.qbt_password)
        self.failover = WireGuardFailover(cfg, self.pia)
        self.stop_event = threading.Event()
        self.down_since: Optional[float] = None
        self.next_failover_at = 0.0
        self.failover_failures = 0

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop_event.set()

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("PIA Port Updater Service started")
        logger.info(f"PIA gateway: {self.cfg.gateway} ({self.cfg.hostname or 'no hostname'})")
        logger.info(f"qBittorrent: {self.cfg.qbt_host}")
        logger.info(f"Check interval: {self.cfg.check_interval}s, retry interval: {self.cfg.retry_interval}s")

        reason = self.failover.unavailable_reason()
        if reason:
            logger.info(f"Server failover is disabled: {reason}")
        else:
            logger.info(f"Server failover enabled after {self.cfg.failover_timeout}s without the PIA gateway")

        if not self.qbt.login():
            logger.error("Failed to authenticate with qBittorrent on startup")
            return 1
        if self.cfg.hostname:
            self.failover.sync_hosts(self.cfg.hostname, self.cfg.gateway)

        while not self.stop_event.is_set():
            ok = self._sync_once()
            self._track_connectivity(failover_enabled=reason is None)
            self.stop_event.wait(self.cfg.check_interval if ok else self.cfg.retry_interval)

        logger.info("PIA Port Updater Service stopped")
        return 0

    def _sync_once(self) -> bool:
        """Bring PIA and qBittorrent up to date; True if both are in the desired state."""
        try:
            port = self.pia.refresh()
            if port is None:
                logger.error("Could not obtain or refresh the forwarded port from PIA")
                if self.pia.reachable and self.pia.payload:
                    # The gateway answered but refused the binding: start over with a new signature.
                    self.pia.forget_signature()
                return False
            if self.qbt.get_current_port() == port:
                return True
            logger.info(f"Updating qBittorrent listening port to {port}")
            return self.qbt.set_listening_port(port)
        except PIAAuthError:
            # Unrecoverable: surfaced to main() so the service exits instead
            # of retrying an authentication that cannot succeed.
            raise
        except Exception:
            logger.exception("Error in main loop")
            return False

    def _track_connectivity(self, failover_enabled: bool) -> None:
        """Fail over once the PIA gateway has been unreachable for FAILOVER_TIMEOUT."""
        now = time.monotonic()
        if self.pia.reachable:
            if self.down_since is not None:
                logger.info("PIA gateway is reachable again")
            self.down_since = None
            return

        if self.down_since is None:
            self.down_since = now
            logger.warning("PIA gateway is unreachable")
        down_for = now - self.down_since
        if not failover_enabled or down_for < self.cfg.failover_timeout or now < self.next_failover_at:
            return

        logger.warning(f"PIA gateway unreachable for {down_for:.0f}s, switching server")
        if self.failover.switch():
            self.down_since = None
            self.failover_failures = 0
        else:
            delay = min(self.FAILOVER_RETRY_SECONDS * 2 ** self.failover_failures,
                        self.FAILOVER_RETRY_MAX_SECONDS)
            self.failover_failures += 1
            self.next_failover_at = time.monotonic() + delay
            logger.info(f"Next failover attempt in {delay}s")


def main() -> int:
    try:
        cfg = Config.from_env()
    except ConfigError as e:
        for error in e.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return os.EX_CONFIG

    setup_logging(cfg.log_file, cfg.log_level)
    try:
        return PIAUpdaterService(cfg).run()
    except PIAAuthError as e:
        logger.error(f"PIA authentication failed: {e}")
        logger.error("Not retrying, as re-authenticating cannot fix this. "
                     "Correct the configuration and restart the service.")
        return os.EX_CONFIG


if __name__ == '__main__':
    sys.exit(main())
