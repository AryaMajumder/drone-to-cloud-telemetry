#!/usr/bin/env bash
set -eu

echo "=========================================="
echo "Applying SSH + Logging Fixes (No Mosquitto Config Changes)"
echo "=========================================="
echo ""

# ============================================================================
# STEP 1: Mosquitto Logging ONLY
# ============================================================================

echo "Step 1: Configuring Mosquitto logging..."

MOS_CONF="/usr/local/etc/mosquitto/mosquitto.conf"

# Create log directory
sudo mkdir -p /var/log/mosquitto
sudo chown mosquitto:mosquitto /var/log/mosquitto 2>/dev/null || true
sudo chmod 0750 /var/log/mosquitto

# Add logging to config if not present (without changing anything else)
if ! grep -q "log_dest file" "$MOS_CONF"; then
    sudo tee -a "$MOS_CONF" > /dev/null << 'EOF'

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_dest syslog
log_type error
log_type warning
log_type notice
log_type information
log_timestamp true
EOF
    echo "✓ Logging configuration added"
else
    echo "✓ Logging already configured"
fi

# Create logrotate config
sudo tee /etc/logrotate.d/mosquitto > /dev/null << 'EOF'
/var/log/mosquitto/mosquitto.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 0640 mosquitto mosquitto
    sharedscripts
    postrotate
        systemctl reload mosquitto >/dev/null 2>&1 || true
    endscript
}
EOF

echo "✓ Log rotation configured"
echo ""

# ============================================================================
# STEP 2: SSH Configuration
# ============================================================================

echo "Step 2: Configuring SSH..."

SSHD_CONF="/etc/ssh/sshd_config"

# Backup
sudo cp "$SSHD_CONF" "${SSHD_CONF}.backup.$(date +%s)"

# Add Port 443 if not present
if ! grep -Eq '^[[:space:]]*Port[[:space:]]+443' "$SSHD_CONF"; then
    echo "Port 443" | sudo tee -a "$SSHD_CONF" > /dev/null
    echo "✓ Added Port 443"
fi

# Ensure Port 22 exists
if ! grep -Eq '^[[:space:]]*Port[[:space:]]+22' "$SSHD_CONF"; then
    echo "Port 22" | sudo tee -a "$SSHD_CONF" > /dev/null
    echo "✓ Added Port 22"
fi

# Enable TCP forwarding
if grep -Eiq '^[[:space:]]*AllowTcpForwarding' "$SSHD_CONF"; then
    sudo sed -i -E 's/^[[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/I' "$SSHD_CONF"
else
    echo "AllowTcpForwarding yes" | sudo tee -a "$SSHD_CONF" > /dev/null
fi
echo "✓ TCP forwarding enabled"

# Restart SSH
echo "Restarting SSH..."
sudo systemctl restart sshd
echo "✓ SSH restarted"
echo ""

# ============================================================================
# STEP 3: Restart Mosquitto (to pick up logging changes only)
# ============================================================================

echo "Step 3: Restarting Mosquitto..."
sudo systemctl restart mosquitto
sleep 2

echo "✓ Mosquitto restarted"
echo ""

# ============================================================================
# VERIFICATION
# ============================================================================

echo "=========================================="
echo "Verification"
echo "=========================================="
echo ""

echo "Mosquitto status:"
sudo systemctl status mosquitto --no-pager -l | head -15
echo ""

echo "Mosquitto listening on:"
sudo ss -tlnp | grep :1883 || echo "  ⚠ Not listening on 1883"
echo ""

echo "SSH listening on:"
sudo ss -tlnp | grep sshd | grep -E ':(22|443)' || echo "  ⚠ SSH not on 22/443"
echo ""

echo "=========================================="
echo "Fixes Applied Successfully"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Verify authentication works:"
echo "     PASS=\$(sudo cat /root/mosquitto_drone_credentials.txt | awk -F: '/^drone:/{print \$2}')"
echo "     mosquitto_sub -h 127.0.0.1 -p 1883 -u drone -P \"\$PASS\" -t test -v"
echo ""
echo "  2. Ensure EC2 Security Group allows:"
echo "     - TCP 443 (SSH)"
echo "     - TCP 22 (SSH)"
echo ""