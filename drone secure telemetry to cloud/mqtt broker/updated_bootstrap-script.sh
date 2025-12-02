#!/bin/bash
set -e

################################################################################
# Unified MQTT Broker Installation Script
# 
# Runs scripts in sequence:
# 1. mosquitto-script.sh (build and install Mosquitto)
# 2. mosquitto_passwd.sh (create passwords with PBKDF2-SHA512)
# 3. fixes.sh (SSH configuration and logging)
# 4. IoT forwarder setup
################################################################################

echo "=========================================="
echo "Unified MQTT Broker Installation"
echo "=========================================="
echo ""

# ============================================================================
# CONFIGURATION - EDIT AWS CREDENTIALS HERE
# ============================================================================

AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-YOUR_AWS_ACCESS_KEY_ID}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-YOUR_AWS_SECRET_ACCESS_KEY}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_IOT_ENDPOINT="${AWS_IOT_ENDPOINT:-your-iot-endpoint.iot.us-east-1.amazonaws.com}"

INSTALL_DIR="/opt/iot-forwarder"

# ============================================================================
# PHASE 1: Clone Repository
# ============================================================================

echo "Phase 1: Installing git and cloning repository..."
sudo dnf install -y git || sudo yum install -y git

cd ~
rm -rf drone-to-cloud-telemetry 2>/dev/null || true
git clone https://github.com/AryaMajumder/drone-to-cloud-telemetry.git

cd "drone-to-cloud-telemetry/drone secure telemetry to cloud/mqtt broker"
echo "✓ Repository cloned"
echo ""

# ============================================================================
# PHASE 2: Fix Scripts (Remove pipefail, fix line endings)
# ============================================================================

echo "Phase 2: Fixing scripts..."
for script in mosquitto-script.sh mosquitto_passwd.sh fixes.sh; do
    if [ -f "$script" ]; then
        echo "  Fixing $script..."
        tr -d '\r' < "$script" > "${script}.fixed"
        sed -i 's/set -euxo pipefail/set -eux/g' "${script}.fixed"
        sed -i 's/set -euo pipefail/set -eu/g' "${script}.fixed"
        sed -i 's/set -eo pipefail/set -e/g' "${script}.fixed"
        chmod +x "${script}.fixed"
    fi
done
echo "✓ Scripts fixed"
echo ""

# ============================================================================
# PHASE 3: Replace mosquitto_passwd.sh with PBKDF2 version
# ============================================================================

echo "Phase 3: Creating PBKDF2-SHA512 password script..."

cat > mosquitto_passwd_pbkdf2.sh << 'EOFPASSWD'
#!/bin/bash
set -eux

echo "Creating Mosquitto passwords with PBKDF2-SHA512..."

PW_DIR="/usr/local/etc/mosquitto"
PASSFILE="${PW_DIR}/passwords"
ROOTCREDS="/root/mosquitto_drone_credentials.txt"
mkdir -p "$PW_DIR"

# Generate random passwords
DRONE_PW=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)
CONSUMER_PW=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)

# Export for Python script
export DRONE_PW
export CONSUMER_PW
export PASSFILE

# Create PBKDF2-SHA512 hashes (Mosquitto 2.0+ format: $7$)
python3 << 'EOPYTHON'
import hashlib, secrets, base64, sys, os

def mosquitto_hash(password):
    salt = secrets.token_bytes(12)
    iterations = 101
    dk = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode()
    hash_b64 = base64.b64encode(dk).decode()
    return f"$7${iterations}${salt_b64}${hash_b64}"

drone_pw = os.environ.get('DRONE_PW')
consumer_pw = os.environ.get('CONSUMER_PW')
passfile = os.environ.get('PASSFILE')

with open(passfile, 'w') as f:
    f.write(f"drone:{mosquitto_hash(drone_pw)}\n")
    f.write(f"consumer:{mosquitto_hash(consumer_pw)}\n")
EOPYTHON

# Set permissions
if id -u mosquitto >/dev/null 2>&1; then
  chown mosquitto:mosquitto "$PASSFILE" || true
fi
chmod 600 "$PASSFILE"

# Save credentials
printf "drone:%s\nconsumer:%s\n" "$DRONE_PW" "$CONSUMER_PW" > "$ROOTCREDS"
chmod 600 "$ROOTCREDS"

echo "✓ Password file created: $PASSFILE (PBKDF2-SHA512 format)"
echo "✓ Credentials saved: $ROOTCREDS"

# Fix library paths
echo "Fixing library paths..."
LIB_DIR=$(find /usr/local -name "libmosquitto.so*" -type f 2>/dev/null | head -1 | xargs dirname)
if [ -n "$LIB_DIR" ]; then
    cd "$LIB_DIR"
    LATEST=$(ls -1 libmosquitto.so.* 2>/dev/null | sort -V | tail -n1)
    [ -n "$LATEST" ] && ln -sf "$LATEST" libmosquitto.so.1
    [ -n "$LATEST" ] && ln -sf "$LATEST" libmosquitto.so
    echo "$LIB_DIR" > /etc/ld.so.conf.d/mosquitto.conf
    ldconfig
    echo "✓ Library paths fixed"
fi
EOFPASSWD

chmod +x mosquitto_passwd_pbkdf2.sh
echo "✓ PBKDF2 password script created"
echo ""

# ============================================================================
# PHASE 4: Create minimal fixes.sh (no mosquitto config changes)
# ============================================================================

echo "Phase 4: Creating minimal fixes script..."

cat > fixes_minimal.sh << 'EOFFIXES'
#!/usr/bin/env bash
set -eu

echo "Applying SSH + Logging Fixes..."

MOS_CONF="/usr/local/etc/mosquitto/mosquitto.conf"

# Create log directory
sudo mkdir -p /var/log/mosquitto
sudo chown mosquitto:mosquitto /var/log/mosquitto 2>/dev/null || true
sudo chmod 0750 /var/log/mosquitto

# Add logging to config if not present
if ! grep -q "log_dest file" "$MOS_CONF"; then
    sudo tee -a "$MOS_CONF" > /dev/null << 'EOF'

# Logging
log_dest file /var/log/mosquitto/mosquitto.log
log_type all
log_timestamp true
EOF
fi

# SSH Configuration
SSHD_CONF="/etc/ssh/sshd_config"
sudo cp "$SSHD_CONF" "${SSHD_CONF}.backup.$(date +%s)" 2>/dev/null || true

if ! grep -Eq '^[[:space:]]*Port[[:space:]]+443' "$SSHD_CONF"; then
    echo "Port 443" | sudo tee -a "$SSHD_CONF" > /dev/null
fi

if ! grep -Eq '^[[:space:]]*Port[[:space:]]+22' "$SSHD_CONF"; then
    echo "Port 22" | sudo tee -a "$SSHD_CONF" > /dev/null
fi

if grep -Eiq '^[[:space:]]*AllowTcpForwarding' "$SSHD_CONF"; then
    sudo sed -i -E 's/^[[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/I' "$SSHD_CONF"
else
    echo "AllowTcpForwarding yes" | sudo tee -a "$SSHD_CONF" > /dev/null
fi

sudo systemctl restart sshd
sudo systemctl restart mosquitto

echo "✓ Fixes applied"
EOFFIXES

chmod +x fixes_minimal.sh
echo "✓ Minimal fixes script created"
echo ""

# ============================================================================
# PHASE 5: Run Scripts in Sequence
# ============================================================================

echo "Phase 5: Running installation scripts..."
echo ""

echo "Step 1: Building Mosquitto (mosquitto-script.sh)..."
sudo bash mosquitto-script.sh.fixed
echo "✓ Mosquitto built and installed"
echo ""

echo "Step 2: Creating passwords (PBKDF2-SHA512)..."
sudo bash mosquitto_passwd_pbkdf2.sh
echo "✓ Passwords created"
echo ""

echo "Step 3: Applying fixes (SSH + Logging)..."
sudo bash fixes_minimal.sh
echo "✓ Fixes applied"
echo ""

# ============================================================================
# PHASE 6: Setup IoT Forwarder
# ============================================================================

if [ "$AWS_ACCESS_KEY_ID" != "YOUR_AWS_ACCESS_KEY_ID" ]; then
    echo "Phase 6: Setting up IoT forwarder..."
    
    # Install Python dependencies
    sudo pip3 install --break-system-packages boto3 paho-mqtt 2>/dev/null || \
        sudo pip3 install boto3 paho-mqtt
    
    # Create install directory
    sudo mkdir -p "$INSTALL_DIR"
    
    # Copy forwarder script if exists
    if [ -f "forwarder_to_iot.py" ]; then
        sudo cp forwarder_to_iot.py "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/forwarder_to_iot.py"
    fi
    
    # Create AWS credentials file
    sudo tee "$INSTALL_DIR/aws_credentials.env" > /dev/null << EOF
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
AWS_REGION=$AWS_REGION
AWS_IOT_ENDPOINT=$AWS_IOT_ENDPOINT
EOF
    
    sudo chmod 600 "$INSTALL_DIR/aws_credentials.env"
    
    # Create systemd service
    sudo tee /etc/systemd/system/iot-forwarder.service > /dev/null << 'EOFSERVICE'
[Unit]
Description=Drone MQTT to AWS IoT forwarder
After=network.target mosquitto.service
Wants=mosquitto.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/iot-forwarder
EnvironmentFile=/opt/iot-forwarder/aws_credentials.env
ExecStart=/usr/bin/python3 /opt/iot-forwarder/forwarder_to_iot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSERVICE
    
    sudo systemctl daemon-reload
    sudo systemctl enable iot-forwarder
    sudo systemctl start iot-forwarder
    
    echo "✓ IoT forwarder installed"
else
    echo "Phase 6: Skipping IoT forwarder (AWS credentials not configured)"
fi
echo ""

# ============================================================================
# PHASE 7: Verification
# ============================================================================

echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""

echo "Services Status:"
sudo systemctl is-active mosquitto &>/dev/null && echo "  ✓ Mosquitto: running" || echo "  ✗ Mosquitto: not running"
if [ "$AWS_ACCESS_KEY_ID" != "YOUR_AWS_ACCESS_KEY_ID" ]; then
    sudo systemctl is-active iot-forwarder &>/dev/null && echo "  ✓ IoT Forwarder: running" || echo "  ✗ IoT Forwarder: not running"
fi
echo ""

echo "Installed Utilities:"
for util in mosquitto mosquitto_pub mosquitto_sub; do
    if command -v $util &>/dev/null; then
        echo "  ✓ $util: $(which $util)"
    else
        echo "  ✗ $util: NOT FOUND"
    fi
done
echo ""

echo "Configuration Files:"
echo "  Credentials: /root/mosquitto_drone_credentials.txt"
echo "  Mosquitto config: /usr/local/etc/mosquitto/mosquitto.conf"
echo "  Password file: /usr/local/etc/mosquitto/passwords"
if [ "$AWS_ACCESS_KEY_ID" != "YOUR_AWS_ACCESS_KEY_ID" ]; then
    echo "  IoT forwarder: $INSTALL_DIR/forwarder_to_iot.py"
    echo "  AWS credentials: $INSTALL_DIR/aws_credentials.env"
fi
echo ""

echo "Test MQTT Authentication:"
PASS=$(sudo cat /root/mosquitto_drone_credentials.txt | awk -F: '/^drone:/{print $2}')
echo "  Password: $PASS"
echo ""
echo "  Subscribe: mosquitto_sub -h 127.0.0.1 -p 1883 -u drone -P '$PASS' -t test -v"
echo "  Publish:   mosquitto_pub -h 127.0.0.1 -p 1883 -u drone -P '$PASS' -t test -m hello"
echo ""

echo "View Logs:"
echo "  sudo journalctl -u mosquitto -f"
if [ "$AWS_ACCESS_KEY_ID" != "YOUR_AWS_ACCESS_KEY_ID" ]; then
    echo "  sudo journalctl -u iot-forwarder -f"
fi
echo ""