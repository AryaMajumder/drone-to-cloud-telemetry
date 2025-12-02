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
# STEP 3: Add SSH Public Key
# ============================================================================

echo "Step 3: Adding SSH public key..."

# Define the public key
PUBLIC_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2evMuoB+VKvlD3fm8zaOMQSyBZl8cppCZvgBBp0R3+ companion@DESKTOP-5AL6U1P"

# Determine which user to add key for (ec2-user or ssm-user)
if id ec2-user &>/dev/null; then
    SSH_USER="ec2-user"
elif id ssm-user &>/dev/null; then
    SSH_USER="ssm-user"
else
    echo "⚠ Neither ec2-user nor ssm-user found, skipping SSH key"
    SSH_USER=""
fi

if [ -n "$SSH_USER" ]; then
    SSH_HOME=$(eval echo ~$SSH_USER)
    SSH_DIR="$SSH_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    
    # Create .ssh directory if it doesn't exist
    sudo mkdir -p "$SSH_DIR"
    sudo chmod 700 "$SSH_DIR"
    
    # Add key if not already present
    if [ -f "$AUTH_KEYS" ]; then
        if grep -Fq "$PUBLIC_SSH_KEY" "$AUTH_KEYS"; then
            echo "✓ SSH key already present for $SSH_USER"
        else
            echo "$PUBLIC_SSH_KEY" | sudo tee -a "$AUTH_KEYS" > /dev/null
            echo "✓ SSH key added for $SSH_USER"
        fi
    else
        echo "$PUBLIC_SSH_KEY" | sudo tee "$AUTH_KEYS" > /dev/null
        echo "✓ SSH key added for $SSH_USER"
    fi
    
    # Set correct permissions and ownership
    sudo chmod 600 "$AUTH_KEYS"
    sudo chown -R $SSH_USER:$SSH_USER "$SSH_DIR"
    echo "✓ Permissions set"
fi
echo ""

# ============================================================================
# STEP 4: Restart Mosquitto (to pick up logging changes only)
# ============================================================================

echo "Step 4: Restarting Mosquitto..."
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