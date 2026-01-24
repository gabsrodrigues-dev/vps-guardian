#!/bin/bash
# VPS Guardian - Automated Security Setup
# Usage: git clone ... && cd vps-guardian && sudo ./setup.sh
# Idempotent: safe to run multiple times

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/vps-guardian"
SERVICE_NAME="guardian"

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo ./setup.sh)"

# CRITICAL: Check for SSH keys BEFORE making any changes
# This prevents lockout if password auth is disabled
log "[PRE-FLIGHT] Checking SSH key access..."
SSH_KEYS_FOUND=false

# Check root user's authorized_keys
if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    SSH_KEYS_FOUND=true
fi

# Check for any user with sudo access that has SSH keys
for user_home in /home/*; do
    if [[ -f "$user_home/.ssh/authorized_keys" ]] && [[ -s "$user_home/.ssh/authorized_keys" ]]; then
        SSH_KEYS_FOUND=true
        break
    fi
done

if [[ "$SSH_KEYS_FOUND" == "false" ]]; then
    echo ""
    warn "============================================"
    warn "  WARNING: NO SSH KEYS DETECTED!"
    warn "============================================"
    warn ""
    warn "This script will disable password authentication."
    warn "Without SSH keys, you will be LOCKED OUT of your server!"
    warn ""
    warn "To add SSH keys, run from your LOCAL machine:"
    warn "  ssh-copy-id user@your-server"
    warn ""
    read -p "Continue anyway? (type 'yes' to confirm): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        error "Aborted. Add SSH keys first, then run this script again."
    fi
    warn "Proceeding without SSH keys (at your own risk)..."
fi

# Detect distro
if [[ -f /etc/debian_version ]]; then
    DISTRO="debian"
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="rhel"
else
    error "Unsupported distribution. Only Debian/Ubuntu and RHEL/CentOS are supported."
fi

log "VPS Guardian Setup - Starting installation..."
log "Detected distribution: $DISTRO"

# Step 1: Install dependencies
log "[1/8] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive

if [[ "$DISTRO" == "debian" ]]; then
    apt-get update -qq
    apt-get install -y -qq \
        python3 \
        python3-psutil \
        python3-yaml \
        python3-requests \
        fail2ban \
        ipset \
        iptables-persistent \
        curl \
        chkrootkit \
        rkhunter \
        auditd \
        audispd-plugins
else
    yum install -y -q \
        python3 \
        python3-psutil \
        python3-pyyaml \
        python3-requests \
        fail2ban \
        ipset \
        iptables-services \
        curl \
        chkrootkit \
        rkhunter \
        audit \
        audit-libs
fi

# Step 2: Create installation directory
log "[2/8] Setting up installation directory..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/setup.sh"
chmod +x "$INSTALL_DIR/firewall/rules.sh"
chmod +x "$INSTALL_DIR/firewall/blocklists/update-blocklist.sh"
chmod +x "$INSTALL_DIR/audit/audit.sh" 2>/dev/null || true

# Create config.yaml from example if it doesn't exist
if [ ! -f "$INSTALL_DIR/guardian/config.yaml" ]; then
    if [ -f "$INSTALL_DIR/config.yaml.example" ]; then
        cp "$INSTALL_DIR/config.yaml.example" "$INSTALL_DIR/guardian/config.yaml"
        log "Created config.yaml from example"
    fi
else
    log "Existing config.yaml preserved (not overwritten)"
fi

# Step 3: Create required directories
log "[3/8] Creating runtime directories..."
mkdir -p /var/quarantine
mkdir -p /var/lib/guardian
mkdir -p /var/lib/guardian/forensics
mkdir -p /var/log
chmod 700 /var/quarantine
chmod 700 /var/lib/guardian/forensics

# Step 4: Configure SSH hardening
log "[4/8] Configuring SSH hardening..."
mkdir -p /etc/ssh/sshd_config.d
cp "$INSTALL_DIR/config/sshd_hardened.conf" /etc/ssh/sshd_config.d/90-guardian.conf
# Test sshd config before applying
if sshd -t 2>/dev/null; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    log "SSH hardening applied"
else
    warn "SSH config test failed, skipping (check your keys!)"
    rm -f /etc/ssh/sshd_config.d/90-guardian.conf
fi

# Step 5: Configure Fail2ban
log "[5/8] Configuring Fail2ban..."
mkdir -p /etc/fail2ban/jail.d
cp "$INSTALL_DIR/config/fail2ban.local" /etc/fail2ban/jail.d/guardian.local
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true

# Step 6: Setup firewall blocklists
log "[6/8] Setting up firewall blocklists..."
cd "$INSTALL_DIR/firewall/blocklists"
./update-blocklist.sh || warn "Blocklist update failed (might be offline)"
cd "$INSTALL_DIR"

# Apply firewall rules
"$INSTALL_DIR/firewall/rules.sh" install || warn "Firewall rules failed (might need reboot)"

# Step 7: Initialize integrity database and auditd rules
log "[7/8] Initializing integrity checker and auditd rules..."
cd "$INSTALL_DIR/guardian"
python3 -c "
import sys
sys.path.insert(0, '.')
from modules.integrity import IntegrityChecker
import yaml

with open('config.yaml') as f:
    config = yaml.safe_load(f)

checker = IntegrityChecker(config)
checker.initialize()
print('Integrity database initialized')
" || warn "Integrity init failed"

# Configure auditd rules for Guardian
if command -v auditctl &> /dev/null; then
    log "Installing Guardian audit rules..."
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/guardian.rules << 'EOF'
# VPS Guardian - Monitor executions in temp directories
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k guardian_tmp
-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k guardian_shm
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k guardian_vartmp
EOF

    # Reload audit rules if auditd is running
    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditctl -R /etc/audit/rules.d/guardian.rules 2>/dev/null || warn "Failed to load audit rules"
        log "Audit rules installed and loaded"
    else
        log "Audit rules installed (will be loaded when auditd starts)"
    fi
else
    warn "auditctl not found - skipping audit rules installation"
fi

# Step 8: Install and start Guardian service
log "[8/8] Installing Guardian service..."
cp "$INSTALL_DIR/guardian/guardian.service" /etc/systemd/system/guardian.service
systemctl daemon-reload
systemctl enable guardian
systemctl restart guardian

# Setup cron jobs
log "Setting up scheduled tasks..."

# Daily blocklist update (3 AM)
CRON_BLOCKLIST="0 3 * * * $INSTALL_DIR/firewall/blocklists/update-blocklist.sh >> /var/log/guardian-blocklist.log 2>&1"
(crontab -l 2>/dev/null | grep -v "update-blocklist.sh"; echo "$CRON_BLOCKLIST") | crontab -

# Weekly audit (Sunday 2 AM)
if [[ -f "$INSTALL_DIR/audit/audit.sh" ]]; then
    CRON_AUDIT="0 2 * * 0 $INSTALL_DIR/audit/audit.sh >> /var/log/guardian-audit.log 2>&1"
    (crontab -l 2>/dev/null | grep -v "audit.sh"; echo "$CRON_AUDIT") | crontab -
fi

# Final status
echo ""
log "============================================"
log "VPS Guardian installed successfully!"
log "============================================"
echo ""
echo "Service status:"
systemctl status guardian --no-pager -l | head -15

echo ""
log "Quick commands:"
echo "  - Check status:  systemctl status guardian"
echo "  - View logs:     journalctl -fu guardian"
echo "  - Stop:          systemctl stop guardian"
echo "  - Config:        nano $INSTALL_DIR/guardian/config.yaml"
echo ""

# Warnings
if [[ ! -f ~/.ssh/authorized_keys ]] || [[ ! -s ~/.ssh/authorized_keys ]]; then
    warn "WARNING: No SSH keys found! Make sure you have SSH key access before logging out."
    warn "         Password authentication has been disabled."
fi

log "Setup complete! Your VPS is now protected."
