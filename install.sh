#!/bin/bash
# Installation script for PIA qBittorrent Sync Service

set -e

echo "Installing PIA qBittorrent Sync Service..."

# Detect init system
if command -v systemctl &> /dev/null && [ -d "/etc/systemd/system" ]; then
    INIT_SYSTEM="systemd"
    echo "Detected systemd"
elif command -v rc-update &> /dev/null && [ -f "/sbin/openrc-run" ]; then
    INIT_SYSTEM="openrc"
    echo "Detected OpenRC (Alpine Linux)"
else
    echo "Could not detect init system (tried systemd and OpenRC)"
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
if command -v apk &> /dev/null; then
    # Alpine Linux
    apk add --no-cache python3 py3-pip py3-virtualenv
    # Install netcat for qBittorrent readiness checks (used in OpenRC service)
    if ! command -v nc &> /dev/null; then
        echo "Installing netcat for service health checks..."
        if ! apk add --no-cache netcat-openbsd 2>/dev/null && ! apk add --no-cache busybox-extras 2>/dev/null; then
            echo "Warning: Could not install netcat. Service health checks may not work optimally."
            echo "You can install it manually later with: apk add netcat-openbsd"
        fi
    fi
else
    apt-get update && apt-get install -y python3 python3-pip python3-venv || \
    yum install -y python3 python3-pip || \
    true
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p /opt/pia-qbittorrent-sync

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv /opt/pia-qbittorrent-sync/venv

# Install dependencies in venv
echo "Installing Python packages..."
/opt/pia-qbittorrent-sync/venv/bin/pip install --upgrade pip
/opt/pia-qbittorrent-sync/venv/bin/pip install -r requirements.txt

# Copy Python script
echo "Copying service files..."
cp pia_qbittorrent_sync.py /opt/pia-qbittorrent-sync/
chmod +x /opt/pia-qbittorrent-sync/pia_qbittorrent_sync.py

# Install appropriate service file
if [ "$INIT_SYSTEM" = "openrc" ]; then
    echo "Installing OpenRC service..."
    
    # Convert line endings if dos2unix is available, otherwise use sed
    if command -v dos2unix &> /dev/null; then
        dos2unix pia-qbittorrent-sync.openrc 2>/dev/null || true
    else
        sed -i 's/\r$//' pia-qbittorrent-sync.openrc 2>/dev/null || true
    fi
    
    # Copy and set permissions
    cp pia-qbittorrent-sync.openrc /etc/init.d/pia-qbittorrent-sync
    chmod +x /etc/init.d/pia-qbittorrent-sync
    
    # Verify the shebang interpreter exists
    if [ ! -f /sbin/openrc-run ]; then
        echo "Warning: /sbin/openrc-run not found. OpenRC may not be properly installed."
    fi
    
    # Copy configuration file
    if [ ! -f /etc/conf.d/pia-qbittorrent-sync ]; then
        # Convert line endings for config file too
        if command -v dos2unix &> /dev/null; then
            dos2unix pia-qbittorrent-sync.conf 2>/dev/null || true
        else
            sed -i 's/\r$//' pia-qbittorrent-sync.conf 2>/dev/null || true
        fi
        cp pia-qbittorrent-sync.conf /etc/conf.d/pia-qbittorrent-sync
        echo "Configuration file created at /etc/conf.d/pia-qbittorrent-sync"
    else
        echo "Configuration file already exists at /etc/conf.d/pia-qbittorrent-sync (not overwriting)"
    fi
else
    echo "Installing systemd service..."
    cp pia-qbittorrent-sync.service /etc/systemd/system/
    systemctl daemon-reload
fi

# Create log directory and file
echo "Setting up logging..."
mkdir -p /var/log
touch /var/log/pia_qbittorrent_sync.log
chmod 644 /var/log/pia_qbittorrent_sync.log

# Create token directory
mkdir -p /run/pia
chmod 755 /run/pia

echo ""
echo "Installation complete!"
echo ""

if [ "$INIT_SYSTEM" = "openrc" ]; then
    echo "Next steps:"
    echo "1. Edit /etc/conf.d/pia-qbittorrent-sync to configure your settings"
    echo "2. Enable the service: rc-update add pia-qbittorrent-sync default"
    echo "3. Start the service: rc-service pia-qbittorrent-sync start"
    echo "4. Check status: rc-service pia-qbittorrent-sync status"
    echo "5. View logs: tail -f /var/log/pia_qbittorrent_sync.log"
else
    echo "Next steps:"
    echo "1. Edit /etc/systemd/system/pia-qbittorrent-sync.service to configure your settings"
    echo "2. Enable the service: sudo systemctl enable pia-qbittorrent-sync.service"
    echo "3. Start the service: sudo systemctl start pia-qbittorrent-sync.service"
    echo "4. Check status: sudo systemctl status pia-qbittorrent-sync.service"
    echo "5. View logs: sudo journalctl -u pia-qbittorrent-sync.service -f"
fi
echo ""
