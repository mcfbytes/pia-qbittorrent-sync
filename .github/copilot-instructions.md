# PIA qBittorrent Sync - AI Coding Instructions

## Project Overview
A Linux service that automatically syncs Private Internet Access (PIA) VPN port forwarding with qBittorrent's listening port. Single-file Python daemon (`pia_qbittorrent_sync.py`) with dual init system support (systemd/OpenRC).

## Architecture

### Three-Class Design
1. **PIAPortForwarder** - Handles PIA API authentication and port lifecycle
   - Token management: `/var/run/pia_token` file caching with fallback to PIA API auth
   - Two-step port activation: `getSignature` (initial) → `bindPort` (refresh every 5 min)
   - SSL hostname patching: Uses `urllib3.util.connection` monkey-patching to redirect hostname→IP for custom cert verification
2. **QBittorrentClient** - Manages qBittorrent Web API v2 interactions
   - Session-based auth with automatic 403 retry logic
   - Port verification after updates (1-second delay before check)
3. **PIAUpdaterService** - Main orchestrator with signal handlers (SIGTERM/SIGINT)

### Critical Data Flows
- **Port expiry logic**: Refresh at 5-min intervals OR 15 min before expiry (whichever comes first)
- **Signature reuse**: Payload/signature obtained once via `getSignature`, reused for all `bindPort` calls until port expires
- **State management**: Port stored in `PIAPortForwarder.current_port`, expiry in `port_expiry` (ISO 8601 datetime)

## Configuration & Deployment

### Environment Variables (All Services)
Required: `PIA_USERNAME`, `PIA_PASSWORD` (or `PIA_TOKEN_FILE` with existing token), `PIA_GATEWAY` (default: `10.0.0.1`)
Optional: `PIA_HOSTNAME` + `PIA_CA_CERT` for custom SSL verification, `QBITTORRENT_HOST/USERNAME/PASSWORD`, `CHECK_INTERVAL` (default: 300s)

### Init Systems
- **systemd**: Config in `/etc/systemd/system/pia-qbittorrent-sync.service` (inline env vars)
- **OpenRC**: Config in `/etc/conf.d/pia-qbittorrent-sync` (exported vars), script in `/etc/init.d/pia-qbittorrent-sync`
- **Deployment**: `install.sh` auto-detects init system, creates venv at `/opt/pia-qbittorrent-sync/venv`, handles line ending conversion

## Development Patterns

### Error Handling
- All HTTP failures log status + response text at ERROR level
- 403 responses trigger automatic re-authentication (one retry)
- Main loop catches all exceptions, logs with `exc_info=True`, waits 60s before retry

### Logging Strategy
- Single handler (file or stdout) configured at module level to avoid duplicates
- DEBUG level includes: payload decoding, port comparisons with types, URL construction
- INFO level for: lifecycle events (auth, port changes, refresh), state transitions

### Testing Approach
When modifying code:
1. Verify logging consistency (use `logger.debug/info/error/exception`)
2. Ensure datetime operations use `timezone.utc` (required for expiry calculations)
3. Test both token file path and API auth workflows
4. Validate qBittorrent API changes with actual API docs (v2 endpoints)

## Key Files
- `pia_qbittorrent_sync.py` - All service logic (615 lines, classes in order: PIAPortForwarder → QBittorrentClient → PIAUpdaterService)
- `requirements.txt` - Single dependency: `requests>=2.31.0`
- `pia-qbittorrent-sync.conf` - OpenRC env var template (properties format with export statements)
- `pia-qbittorrent-sync.service` - systemd unit with security hardening (NoNewPrivileges, PrivateTmp, ProtectSystem)

## Common Tasks
- **Add new PIA API feature**: Extend `PIAPortForwarder`, follow session creation pattern with `_create_session_with_host_override()`
- **Change port refresh logic**: Modify `needs_refresh()` and `is_expired()` methods
- **Support new torrent client**: Create new client class mirroring `QBittorrentClient` structure (login → get_port → set_port)
- **Testing locally**: Run directly with env vars: `PIA_USERNAME=x PIA_PASSWORD=y python3 pia_qbittorrent_sync.py` (no root required for dev)
