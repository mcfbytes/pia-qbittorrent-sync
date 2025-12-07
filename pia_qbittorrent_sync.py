#!/usr/bin/env python3
"""
PIA Port Updater Service
Automatically retrieves port forwarding information from Private Internet Access
and updates qBittorrent's listening port.
"""

import os
import sys
import time
import json
import base64
import logging
import signal
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.connection import create_connection
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

# Configuration
PIA_USERNAME = os.getenv('PIA_USERNAME')  # PIA account username
PIA_PASSWORD = os.getenv('PIA_PASSWORD')  # PIA account password
PIA_GATEWAY = os.getenv('PIA_GATEWAY', '10.0.0.1')  # Default WireGuard gateway
PIA_HOSTNAME = os.getenv('PIA_HOSTNAME')  # Custom hostname for PIA API requests
PIA_CA_CERT = os.getenv('PIA_CA_CERT')  # Path to CA certificate file for PIA API
PIA_TOKEN_FILE = os.getenv('PIA_TOKEN_FILE', '/var/run/pia_token')
QBITTORRENT_HOST = os.getenv('QBITTORRENT_HOST', 'http://localhost:8080')
QBITTORRENT_USERNAME = os.getenv('QBITTORRENT_USERNAME', 'admin')
QBITTORRENT_PASSWORD = os.getenv('QBITTORRENT_PASSWORD', 'adminadmin')
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', '300'))  # 5 minutes default
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', '/var/log/pia_updater.log')

# Setup logging - use only one handler to avoid duplicates
log_handler = None
if os.access(os.path.dirname(LOG_FILE) or '.', os.W_OK):
    log_handler = logging.FileHandler(LOG_FILE)
else:
    log_handler = logging.StreamHandler()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[log_handler]
)
logger = logging.getLogger('pia_updater')


class PIAPortForwarder:
    """Handles PIA port forwarding API interactions."""
    
    def __init__(self, gateway: str, token_file: str, username: Optional[str], password: Optional[str], hostname: Optional[str] = None, ca_cert: Optional[str] = None):
        self.gateway = gateway
        self.token_file = token_file
        self.username = username
        self.password = password
        self.hostname = hostname
        self.ca_cert = ca_cert
        self.token = None
        self.payload = None
        self.signature = None
        self.current_port = None
        self.port_expiry = None
        self.last_refresh = None
        
        # Apply hostname-to-IP patching globally if both are configured
        if self.hostname and self.ca_cert:
            self._patch_urllib3_connection()
    
    def _patch_urllib3_connection(self):
        """Patch urllib3 connection to redirect hostname to gateway IP."""
        try:
            from urllib3.util import connection as urllib3_connection
            
            # Store the original if not already stored
            if not hasattr(urllib3_connection, '_orig_create_connection'):
                urllib3_connection._orig_create_connection = urllib3_connection.create_connection
            
            gateway_ip = self.gateway
            hostname = self.hostname
            
            def patched_create_connection(address, *args, **kwargs):
                """Wrap create_connection to redirect hostname to gateway IP."""
                host, port = address
                # If connecting to our PIA hostname, redirect to gateway IP
                if host == hostname:
                    logger.debug(f"Redirecting connection from {hostname} to {gateway_ip}")
                    return urllib3_connection._orig_create_connection((gateway_ip, port), *args, **kwargs)
                return urllib3_connection._orig_create_connection(address, *args, **kwargs)
            
            # Apply the patch globally
            urllib3_connection.create_connection = patched_create_connection
            logger.debug(f"Applied urllib3 connection patch for {hostname} -> {gateway_ip}")
        except Exception as e:
            logger.warning(f"Failed to patch urllib3 connection: {e}")
    
    def _create_session_with_host_override(self) -> requests.Session:
        """Create a requests session with custom hostname handling for cert verification."""
        session = requests.Session()
        
        if self.hostname and self.ca_cert:
            # Create a custom adapter for SNI hostname override
            hostname = self.hostname
            
            class HostHeaderSSLAdapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    # Override server_hostname for SNI to match the certificate
                    kwargs['server_hostname'] = hostname
                    return super().init_poolmanager(*args, **kwargs)
            
            adapter = HostHeaderSSLAdapter()
            session.mount('https://', adapter)
        
        return session
        
    def get_token(self) -> Optional[str]:
        """Retrieve PIA token from file or generate new one using PIA API."""
        # Try to read existing token
        if os.path.exists(self.token_file):
            try:
                with open(self.token_file, 'r') as f:
                    self.token = f.read().strip()
                    logger.info(f"Loaded PIA token from {self.token_file}")
                    return self.token
            except Exception as e:
                logger.warning(f"Failed to read token file: {e}")
        
        # If no token file, authenticate with PIA API to get token
        if not self.username or not self.password:
            logger.error("PIA username and password are required to generate token")
            return None
        
        try:
            logger.info("Authenticating with PIA API to get token...")
            response = requests.post(
                'https://www.privateinternetaccess.com/api/client/v2/token',
                data={
                    'username': self.username,
                    'password': self.password
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                
                if self.token:
                    # Save token for future use
                    try:
                        os.makedirs(os.path.dirname(self.token_file), exist_ok=True)
                        with open(self.token_file, 'w') as f:
                            f.write(self.token)
                        logger.info(f"Saved new PIA token to {self.token_file}")
                    except Exception as e:
                        logger.warning(f"Failed to save token: {e}")
                    return self.token
                else:
                    logger.error("No token in API response")
            else:
                logger.error(f"Failed to get PIA token: {response.status_code} - {response.text}")
        except Exception as e:
            logger.error(f"Failed to get PIA token: {e}")
        
        return None
    
    def get_signature(self) -> bool:
        """Get signature from PIA (only needed once during initialization)."""
        if not self.token:
            self.token = self.get_token()
            if not self.token:
                logger.error("No PIA token available")
                return False

        try:
            logger.info("Getting signature from PIA...")
            
            # Create session with custom hostname handling
            session = self._create_session_with_host_override()
            
            # Always connect to gateway IP, but use hostname in URL for SSL cert verification if configured
            if self.hostname and self.ca_cert:
                url = f'https://{self.hostname}:19999/getSignature'
            else:
                url = f'https://{self.gateway}:19999/getSignature'
            
            response = session.get(
                url,
                params={'token': self.token},
                verify=self.ca_cert if self.ca_cert else False,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get signature: {response.status_code}")
                logger.debug(f"Response text: {response.text}")
                return False
            
            signature_data = response.json()
            logger.debug(f"Signature response: {signature_data}")
            
            self.payload = signature_data.get('payload')
            self.signature = signature_data.get('signature')
            
            if not self.payload or not self.signature:
                logger.error("Missing payload or signature in response")
                logger.debug(f"Payload: {self.payload}, Signature: {self.signature}")
                return False
            
            # Decode the base64 payload to extract port information
            try:
                payload_decoded = base64.b64decode(self.payload)
                payload_json = json.loads(payload_decoded)
                logger.debug(f"Decoded payload: {payload_json}")
                
                port = payload_json.get('port')
                expires_at = payload_json.get('expires_at')
                
                if port:
                    self.current_port = port
                    if expires_at:
                        self.port_expiry = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                        logger.info(f"Port {port} obtained from signature, expires at {self.port_expiry}")
                    else:
                        logger.info(f"Port {port} obtained from signature")
                else:
                    logger.error("No port found in decoded payload")
                    return False
            except Exception as e:
                logger.error(f"Failed to decode payload: {e}")
                logger.debug(f"Payload value: {self.payload}")
                return False
            
            logger.info(f"Successfully obtained signature from PIA (payload length: {len(self.payload)}, signature length: {len(self.signature)})")
            
            # Call bindPort immediately after getting signature to activate the port
            logger.info("Activating port with bindPort...")
            if self.get_port_forward():
                logger.info(f"Port {self.current_port} activated successfully")
            else:
                logger.warning("Failed to activate port with bindPort, but signature obtained")
            
            return True
            
        except Exception as e:
            logger.error(f"Error getting signature: {e}")
            return False
    
    def get_port_forward(self) -> Optional[int]:
        """Bind/refresh port forwarding from PIA using stored signature."""
        if not self.payload or not self.signature:
            logger.error("No signature available. Call get_signature() first.")
            return None
        
        if not self.current_port:
            logger.error("No port available. Port should have been extracted from signature.")
            return None
        
        try:
            # Create session with custom hostname handling
            session = self._create_session_with_host_override()
            
            # Always connect to gateway IP, but use hostname in URL for SSL cert verification if configured
            if self.hostname and self.ca_cert:
                url = f'https://{self.hostname}:19999/bindPort'
            else:
                url = f'https://{self.gateway}:19999/bindPort'
            
            response = session.get(
                url,
                params={
                    'payload': self.payload,
                    'signature': self.signature
                },
                verify=self.ca_cert if self.ca_cert else False,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to bind port: {response.status_code}")
                logger.debug(f"Response text: {response.text}")
                return None
            
            logger.debug(f"bindPort response status: {response.status_code}")
            logger.debug(f"bindPort response text: {response.text}")
            
            bind_data = response.json()
            logger.debug(f"bindPort parsed data type: {type(bind_data)}")
            logger.debug(f"bindPort parsed data: {bind_data}")
            
            # Check if binding was successful
            if isinstance(bind_data, dict) and bind_data.get('status') == 'OK':
                # Update last refresh timestamp
                from datetime import timezone
                self.last_refresh = datetime.now(timezone.utc)
                logger.info(f"Port {self.current_port} binding refreshed successfully at {self.last_refresh}")
                return self.current_port
            else:
                logger.error(f"Port binding failed: {bind_data}")
                return None
            
        except Exception as e:
            logger.error(f"Error binding port: {e}")
            return None
    
    def needs_refresh(self) -> bool:
        """Check if port needs to be refreshed (every 5 minutes or when near expiry)."""
        if not self.current_port:
            logger.debug("needs_refresh: True (no current port)")
            return True
        
        from datetime import timezone
        now = datetime.now(timezone.utc)
        
        # Check if we need to refresh every 5 minutes to keep port active
        if self.last_refresh:
            time_since_refresh = (now - self.last_refresh).total_seconds()
            if time_since_refresh >= 300:  # 5 minutes
                logger.debug(f"needs_refresh: True (last refresh was {time_since_refresh:.0f} seconds ago)")
                return True
        
        if not self.port_expiry:
            logger.debug("needs_refresh: False (no expiry time set)")
            return False
        
        # Also refresh 15 minutes before expiry as safety margin
        needs_refresh = now >= (self.port_expiry - timedelta(minutes=15))
        logger.debug(f"needs_refresh: {needs_refresh} (now: {now}, expiry: {self.port_expiry}, refresh_at: {self.port_expiry - timedelta(minutes=15)})")
        return needs_refresh
    
    def is_expired(self) -> bool:
        """Check if the port has expired and needs a new signature."""
        if not self.port_expiry:
            return False
        
        from datetime import timezone
        now = datetime.now(timezone.utc)
        expired = now >= self.port_expiry
        if expired:
            logger.info(f"Port expired at {self.port_expiry}, need to get new signature")
        return expired


class QBittorrentClient:
    """Handles qBittorrent API interactions."""
    
    def __init__(self, host: str, username: str, password: str):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False
        
    def login(self) -> bool:
        """Authenticate with qBittorrent."""
        try:
            response = self.session.post(
                f'{self.host}/api/v2/auth/login',
                data={
                    'username': self.username,
                    'password': self.password
                },
                timeout=10
            )
            
            if response.status_code == 200 and response.text == 'Ok.':
                self.authenticated = True
                logger.info("Successfully authenticated with qBittorrent")
                return True
            else:
                logger.error(f"qBittorrent authentication failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error logging into qBittorrent: {e}")
            return False
    
    def get_current_port(self) -> Optional[int]:
        """Get current listening port from qBittorrent."""
        if not self.authenticated and not self.login():
            return None
        
        try:
            logger.debug(f"Fetching current port from qBittorrent: {self.host}/api/v2/app/preferences")
            response = self.session.get(
                f'{self.host}/api/v2/app/preferences',
                timeout=10
            )
            
            logger.debug(f"qBittorrent preferences response status: {response.status_code}")
            
            if response.status_code == 200:
                prefs = response.json()
                current_port = prefs.get('listen_port')
                logger.info(f"Current qBittorrent listening port: {current_port}")
                logger.debug(f"qBittorrent port preferences: listen_port={current_port}, random_port={prefs.get('random_port')}")
                return current_port
            elif response.status_code == 403:
                logger.warning(f"qBittorrent returned 403 Forbidden, re-authenticating...")
                self.authenticated = False
                if self.login():
                    # Retry once after re-authentication
                    response = self.session.get(
                        f'{self.host}/api/v2/app/preferences',
                        timeout=10
                    )
                    if response.status_code == 200:
                        prefs = response.json()
                        current_port = prefs.get('listen_port')
                        logger.info(f"Current qBittorrent listening port: {current_port}")
                        return current_port
                logger.error(f"Failed to get qBittorrent preferences after re-authentication")
                return None
            else:
                logger.error(f"Failed to get qBittorrent preferences: {response.status_code}")
                logger.debug(f"Response text: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting qBittorrent port: {e}")
            return None
    
    def set_listening_port(self, port: int) -> bool:
        """Update qBittorrent listening port."""
        if not self.authenticated and not self.login():
            return False
        
        try:
            preferences = {
                'listen_port': port,
                'random_port': False
            }
            json_prefs = json.dumps(preferences)
            
            logger.debug(f"Setting qBittorrent port to {port}")
            logger.debug(f"Request URL: {self.host}/api/v2/app/setPreferences")
            logger.debug(f"Request data: json={json_prefs}")
            
            response = self.session.post(
                f'{self.host}/api/v2/app/setPreferences',
                data={
                    'json': json_prefs
                },
                timeout=10
            )
            
            logger.debug(f"setPreferences response status: {response.status_code}")
            logger.debug(f"setPreferences response text: {response.text}")
            
            if response.status_code == 200:
                logger.info(f"Successfully updated qBittorrent port to {port}")
                # Verify the change was applied
                import time
                time.sleep(1)  # Give qBittorrent a moment to apply the change
                verified_port = self.get_current_port()
                if verified_port == port:
                    logger.info(f"Verified: qBittorrent port is now {port}")
                else:
                    logger.warning(f"Port verification mismatch: expected {port}, got {verified_port}")
                return True
            elif response.status_code == 403:
                logger.warning(f"qBittorrent returned 403 Forbidden, re-authenticating...")
                self.authenticated = False
                if self.login():
                    # Retry once after re-authentication
                    response = self.session.post(
                        f'{self.host}/api/v2/app/setPreferences',
                        data={
                            'json': json_prefs
                        },
                        timeout=10
                    )
                    if response.status_code == 200:
                        logger.info(f"Successfully updated qBittorrent port to {port} after re-authentication")
                        return True
                logger.error(f"Failed to set qBittorrent port after re-authentication")
                return False
            else:
                logger.error(f"Failed to set qBittorrent port: {response.status_code}")
                logger.debug(f"Response headers: {response.headers}")
                return False
                
        except Exception as e:
            logger.error(f"Error setting qBittorrent port: {e}")
            logger.exception("Full exception details:")
            self.authenticated = False  # Re-authenticate next time
            return False


class PIAUpdaterService:
    """Main service that coordinates PIA and qBittorrent."""
    
    def __init__(self):
        self.pia = PIAPortForwarder(PIA_GATEWAY, PIA_TOKEN_FILE, PIA_USERNAME, PIA_PASSWORD, PIA_HOSTNAME, PIA_CA_CERT)
        self.qbt = QBittorrentClient(QBITTORRENT_HOST, QBITTORRENT_USERNAME, QBITTORRENT_PASSWORD)
        self.running = False
        
    def setup_signal_handlers(self):
        """Setup graceful shutdown handlers."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def run(self):
        """Main service loop."""
        self.running = True
        self.setup_signal_handlers()
        
        logger.info("PIA Port Updater Service started")
        logger.info(f"PIA Gateway: {PIA_GATEWAY}")
        logger.info(f"qBittorrent: {QBITTORRENT_HOST}")
        logger.info(f"Check interval: {CHECK_INTERVAL} seconds")
        
        # Initial authentication
        if not self.qbt.login():
            logger.error("Failed to authenticate with qBittorrent on startup")
            return 1
        
        # Get signature from PIA (also calls bindPort to activate the port)
        if not self.pia.get_signature():
            logger.error("Failed to get signature from PIA on startup")
            return 1
        
        # Initial port setup - ensure qBittorrent is using the PIA port
        logger.info("Setting up qBittorrent with PIA port...")
        pia_port = self.pia.current_port
        if pia_port:
            current_port = self.qbt.get_current_port()
            if current_port != pia_port:
                logger.info(f"Setting qBittorrent to use PIA port {pia_port} (currently: {current_port})")
                if self.qbt.set_listening_port(pia_port):
                    logger.info(f"qBittorrent port configured successfully")
                else:
                    logger.error(f"Failed to configure qBittorrent port")
            else:
                logger.info(f"qBittorrent already using correct port: {pia_port}")
        else:
            logger.error("No port available from PIA after getting signature")
            return 1
        
        while self.running:
            try:
                # Check if port has expired - need to get new signature
                if self.pia.is_expired():
                    logger.info("Port expired, getting new signature...")
                    if not self.pia.get_signature():
                        logger.error("Failed to get new signature from PIA")
                        time.sleep(60)  # Wait before retrying
                        continue
                    
                    # New port from signature, update qBittorrent
                    pia_port = self.pia.current_port
                    if pia_port:
                        current_port = self.qbt.get_current_port()
                        if current_port != pia_port:
                            logger.info(f"New port from signature: {pia_port}, updating qBittorrent")
                            if self.qbt.set_listening_port(pia_port):
                                logger.info(f"Port update completed successfully")
                            else:
                                logger.error(f"Port update failed")
                
                # Check if we need to refresh port binding (every 5 minutes)
                elif self.pia.needs_refresh():
                    logger.info("Refreshing port binding...")
                    pia_port = self.pia.get_port_forward()
                    
                    if pia_port:
                        logger.info(f"PIA port binding refreshed: {pia_port}")
                        # Check current qBittorrent port
                        current_port = self.qbt.get_current_port()
                        
                        logger.debug(f"Comparing ports - PIA: {pia_port} (type: {type(pia_port)}), qBittorrent: {current_port} (type: {type(current_port)})")
                        
                        if current_port != pia_port:
                            logger.info(f"Port mismatch detected! Updating port: {current_port} -> {pia_port}")
                            if self.qbt.set_listening_port(pia_port):
                                logger.info(f"Port update completed successfully")
                            else:
                                logger.error(f"Port update failed")
                        else:
                            logger.info(f"Port {pia_port} already set, no update needed")
                    else:
                        logger.error("Failed to refresh port binding")
                else:
                    logger.debug(f"Port {self.pia.current_port} still valid")
                
                # Sleep until next check
                for _ in range(CHECK_INTERVAL):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(60)  # Wait before retrying
        
        logger.info("PIA Port Updater Service stopped")
        return 0


def main():
    """Entry point for the service."""
    service = PIAUpdaterService()
    return service.run()


if __name__ == '__main__':
    sys.exit(main())
