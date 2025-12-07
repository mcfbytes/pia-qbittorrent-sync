# PIA qBittorrent Sync

Automatically retrieves port forwarding information from Private Internet Access (PIA) and updates qBittorrent's listening port.

Shamelessly vibe coded with GitHub Copilot using various models.

## Features

- Retrieves forwarded port from PIA via WireGuard gateway
- Automatically refreshes port before expiry
- Updates qBittorrent 5.0 listening port via API
- Runs as a systemd service on Linux
- Configurable via environment variables
- Comprehensive logging

## Requirements

- Active PIA WireGuard connection
- Python 3.7+
- qBittorrent 5.0+ with Web UI enabled

## Installation

### Quick Install

Use the provided installation script:

```bash
sudo ./install.sh
```

This will:
- Auto-detect your init system (OpenRC/systemd)
- Create a Python virtual environment at `/opt/pia-qbittorrent-sync/venv`
- Install all dependencies in the virtual environment
- Set up the appropriate service file
- Create necessary directories

### Manual Installation

### 1. Install Python and create virtual environment

```bash
# Install Python 3 (if not already installed)
# Alpine Linux:
apk add python3 py3-pip py3-virtualenv

# Debian/Ubuntu:
apt-get install python3 python3-pip python3-venv

# Create installation directory
sudo mkdir -p /opt/pia-qbittorrent-sync

# Create virtual environment
python3 -m venv /opt/pia-qbittorrent-sync/venv

# Install dependencies
/opt/pia-qbittorrent-sync/venv/bin/pip install --upgrade pip
/opt/pia-qbittorrent-sync/venv/bin/pip install -r requirements.txt
```

### 2. Copy files to system locations

```bash
# Copy Python script
sudo cp pia_qbittorrent_sync.py /opt/pia-qbittorrent-sync/
sudo chmod +x /opt/pia-qbittorrent-sync/pia_qbittorrent_sync.py

# For systemd (most Linux distros):
sudo cp pia-qbittorrent-sync.service /etc/systemd/system/
sudo systemctl daemon-reload

# For OpenRC (Alpine Linux):
sudo cp pia-qbittorrent-sync.openrc /etc/init.d/pia-qbittorrent-sync
sudo chmod +x /etc/init.d/pia-qbittorrent-sync
sudo cp pia-qbittorrent-sync.conf /etc/conf.d/pia-qbittorrent-sync

# Create log directory
sudo mkdir -p /var/log
sudo touch /var/log/pia_qbittorrent_sync.log

# Create token directory
sudo mkdir -p /run/pia
```

### 3. Configure the service

**For systemd:**
Edit `/etc/systemd/system/pia-qbittorrent-sync.service` and update the environment variables.

**For OpenRC (Alpine Linux):**
Edit `/etc/conf.d/pia-qbittorrent-sync` and update the configuration variables:

- **PIA_GATEWAY**: Your WireGuard gateway IP (usually `10.0.0.1`)
- **QBITTORRENT_HOST**: qBittorrent Web UI URL (default: `http://localhost:8080`)
- **QBITTORRENT_USERNAME**: qBittorrent Web UI username
- **QBITTORRENT_PASSWORD**: qBittorrent Web UI password
- **CHECK_INTERVAL**: How often to check in seconds (default: 300 = 5 minutes)
- **LOG_LEVEL**: Logging level (DEBUG, INFO, WARNING, ERROR)

### 4. Enable and start the service

**For systemd:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable pia-qbittorrent-sync.service

# Start the service
sudo systemctl start pia-qbittorrent-sync.service

# Check status
sudo systemctl status pia-qbittorrent-sync.service
```

**For OpenRC (Alpine Linux):**

```bash
# Enable service to start on boot
sudo rc-update add pia-qbittorrent-sync default

# Start the service
sudo rc-service pia-qbittorrent-sync start

# Check status
sudo rc-service pia-qbittorrent-sync status
```

## Usage

### Check service status

```bash
sudo systemctl status pia-qbittorrent-sync.service
```

### View logs

```bash
# Real-time logs
sudo journalctl -u pia-qbittorrent-sync.service -f

# All logs
sudo journalctl -u pia-qbittorrent-sync.service

# Log file
sudo tail -f /var/log/pia_qbittorrent_sync.log
```

### Restart service

```bash
sudo systemctl restart pia-qbittorrent-sync.service
```

### Stop service

```bash
sudo systemctl stop pia-qbittorrent-sync.service
```

## Configuration

All configuration is done via environment variables in the systemd service file:

| Variable | Default | Description |
|----------|---------|-------------|
| `PIA_GATEWAY` | `10.0.0.1` | PIA WireGuard gateway IP |
| `PIA_TOKEN_FILE` | `/var/run/pia_token` | Location to store PIA token |
| `QBITTORRENT_HOST` | `http://localhost:8080` | qBittorrent Web UI URL |
| `QBITTORRENT_USERNAME` | `admin` | qBittorrent username |
| `QBITTORRENT_PASSWORD` | `adminadmin` | qBittorrent password |
| `CHECK_INTERVAL` | `300` | Check interval in seconds |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FILE` | `/var/log/pia_qbittorrent_sync.log` | Log file location |

## How It Works

1. **Token Retrieval**: Gets authentication token from PIA gateway
2. **Port Request**: Requests port forwarding signature and binds port
3. **Port Update**: Updates qBittorrent listening port via Web API
4. **Monitoring**: Continuously monitors and refreshes port before expiry
5. **Auto-refresh**: Refreshes port 15 minutes before expiration

## Troubleshooting

### Alpine Linux: "cannot execute: required file not found"

This error usually means Windows line endings (CRLF) in the script file. Fix it:

```bash
# Install dos2unix if not available
apk add dos2unix

# Convert line endings
dos2unix /etc/init.d/pia-qbittorrent-sync

# Or use sed if dos2unix is not available
sed -i 's/\r$//' /etc/init.d/pia-qbittorrent-sync

# Ensure it's executable
chmod +x /etc/init.d/pia-qbittorrent-sync

# Verify the shebang interpreter exists
ls -l /sbin/openrc-run
```

### Alpine Linux: rc-service command not found

Ensure OpenRC is properly installed:

```bash
apk add openrc
rc-update -u
```

### Service won't start

Check logs:
```bash
sudo journalctl -u pia-qbittorrent-sync.service -n 50
```

Verify WireGuard is connected:
```bash
sudo wg show
```

### Can't connect to PIA gateway

Ensure your WireGuard connection is active and the gateway IP is correct:
```bash
ip route | grep default
```

### Can't connect to qBittorrent

Verify qBittorrent Web UI is enabled and accessible:
```bash
curl http://localhost:8080/api/v2/app/version
```

### Permission issues

Ensure the service has write permissions to log directories:
```bash
sudo chown root:root /var/log/pia_qbittorrent_sync.log
sudo chmod 644 /var/log/pia_qbittorrent_sync.log
```

## Security Notes

- Store qBittorrent credentials securely
- Consider using a dedicated qBittorrent user with limited permissions
- The service runs as root by default to access network interfaces
- Systemd security hardening is enabled in the service file

## License

This project is provided as-is for personal use.
