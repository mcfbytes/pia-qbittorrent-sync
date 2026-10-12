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
        if ! (apk add --no-cache netcat-openbsd 2>/dev/null || apk add --no-cache busybox-extras 2>/dev/null); then
            echo "Warning: Could not install netcat. Service health checks may not work optimally."
            echo "You can install it manually later with: apk add netcat-openbsd"
        fi
    fi
else
    apt-get update && apt-get install -y python3 python3-pip python3-venv || \
    yum install -y python3 python3-pip || \
    true
fi

# Create dedicated service user
echo "Creating dedicated service user 'pia-sync'..."
if command -v apk &> /dev/null; then
    # Alpine Linux: use busybox adduser/addgroup
    if ! getent group pia-sync >/dev/null 2>&1; then
        addgroup -S pia-sync
    else
        echo "Group 'pia-sync' already exists"
    fi
    if ! id -u pia-sync &>/dev/null 2>&1; then
        adduser -S -D -H -G pia-sync -s /sbin/nologin pia-sync
    else
        echo "User 'pia-sync' already exists"
    fi
else
    # systemd-based distros: ensure group and user exist
    if ! getent group pia-sync >/dev/null 2>&1; then
        if command -v groupadd &>/dev/null; then
            groupadd --system pia-sync 2>/dev/null || groupadd pia-sync
        fi
    else
        echo "Group 'pia-sync' already exists"
    fi
    if ! id -u pia-sync &>/dev/null 2>&1; then
        NOLOGIN=$(command -v nologin 2>/dev/null || echo /bin/false)
        useradd --system --no-create-home --shell "$NOLOGIN" \
            --gid pia-sync \
            --comment "PIA qBittorrent Sync Service" pia-sync
    else
        echo "User 'pia-sync' already exists"
    fi
fi

# Failover restarts WireGuard through a privilege helper: doas if present, else sudo
if command -v doas &> /dev/null; then
    PRIV=doas
else
    PRIV=sudo
    if ! command -v sudo &> /dev/null; then
        if command -v apk &> /dev/null; then apk add --no-cache sudo; else apt-get install -y sudo || yum install -y sudo; fi
    fi
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
        chmod 660 /etc/conf.d/pia-qbittorrent-sync
        echo "Configuration file created at /etc/conf.d/pia-qbittorrent-sync"
    else
        echo "Configuration file already exists at /etc/conf.d/pia-qbittorrent-sync (not overwriting)"
        echo "Add PIA_CONFIG_FILE, PIA_WG_CONFIG, FAILOVER_TIMEOUT, RETRY_INTERVAL from pia-qbittorrent-sync.conf to enable failover"
    fi
else
    echo "Installing systemd service..."
    cp pia-qbittorrent-sync.service /etc/systemd/system/
    systemctl daemon-reload

    # PIA_GATEWAY/PIA_HOSTNAME are kept here so the service can rewrite them on failover
    mkdir -p /etc/pia-qbittorrent-sync
    if [ ! -f /etc/pia-qbittorrent-sync/server.env ]; then
        printf 'PIA_GATEWAY="10.0.0.1"\nPIA_HOSTNAME="your_server_hostname"\n' > /etc/pia-qbittorrent-sync/server.env
        echo "Created /etc/pia-qbittorrent-sync/server.env - set PIA_GATEWAY and PIA_HOSTNAME in it"
    fi
    chown root:pia-sync /etc/pia-qbittorrent-sync /etc/pia-qbittorrent-sync/server.env
    chmod 770 /etc/pia-qbittorrent-sync
    chmod 660 /etc/pia-qbittorrent-sync/server.env
fi

# Permissions for server failover: the service rewrites these files in place and
# restarts WireGuard. Group access is limited to the pia-sync user.
echo "Granting pia-sync access for server failover..."
chgrp pia-sync /etc/hosts && chmod 664 /etc/hosts
if [ -d /etc/wireguard ]; then
    chgrp pia-sync /etc/wireguard && chmod 750 /etc/wireguard
    for f in /etc/wireguard/*.conf; do
        [ -e "$f" ] && chgrp pia-sync "$f" && chmod 660 "$f"
    done
fi
if [ "$INIT_SYSTEM" = "openrc" ] && [ -f /etc/conf.d/pia-qbittorrent-sync ]; then
    chgrp pia-sync /etc/conf.d/pia-qbittorrent-sync
    chmod 660 /etc/conf.d/pia-qbittorrent-sync
fi
WG_BIN=$(command -v wg-quick || echo /usr/bin/wg-quick)
if [ "$PRIV" = "doas" ]; then
    for action in down up; do
        rule="permit nopass pia-sync as root cmd $WG_BIN args $action wg0"
        grep -qxF "$rule" /etc/doas.conf 2>/dev/null || echo "$rule" >> /etc/doas.conf
    done
    if [ "$INIT_SYSTEM" = "openrc" ] && [ -f /etc/conf.d/pia-qbittorrent-sync ]; then
        # doas matches the command as typed against the rule, so use the full path
        for pair in "PIA_WG_DOWN_CMD=doas -n $WG_BIN down wg0" "PIA_WG_UP_CMD=doas -n $WG_BIN up wg0"; do
            key=${pair%%=*}
            grep -q "^$key=" /etc/conf.d/pia-qbittorrent-sync || \
                printf '%s="%s"\nexport %s\n' "$key" "${pair#*=}" "$key" >> /etc/conf.d/pia-qbittorrent-sync
        done
    fi
else
    mkdir -p /etc/sudoers.d
    echo "pia-sync ALL=(root) NOPASSWD: $WG_BIN down wg0, $WG_BIN up wg0" > /etc/sudoers.d/pia-qbittorrent-sync
    chmod 440 /etc/sudoers.d/pia-qbittorrent-sync
fi

# Create log directory and token directory for OpenRC (systemd handles these via LogsDirectory= and RuntimeDirectory=)
if [ "$INIT_SYSTEM" = "openrc" ]; then
    echo "Setting up logging and token directory for OpenRC..."
    mkdir -p /var/log
    touch /var/log/pia_qbittorrent_sync.log
    chown pia-sync:pia-sync /var/log/pia_qbittorrent_sync.log
    chmod 600 /var/log/pia_qbittorrent_sync.log

    mkdir -p /run/pia
    chown pia-sync:pia-sync /run/pia
    chmod 700 /run/pia
fi

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
    echo "1. Edit /etc/systemd/system/pia-qbittorrent-sync.service and /etc/pia-qbittorrent-sync/server.env to configure your settings"
    echo "2. Enable the service: sudo systemctl enable pia-qbittorrent-sync.service"
    echo "3. Start the service: sudo systemctl start pia-qbittorrent-sync.service"
    echo "4. Check status: sudo systemctl status pia-qbittorrent-sync.service"
    echo "5. View logs: sudo journalctl -u pia-qbittorrent-sync.service -f"
fi
echo ""
