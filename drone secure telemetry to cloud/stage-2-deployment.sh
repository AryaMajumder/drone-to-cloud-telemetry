#!/bin/bash
################################################################################
# C2 Setup Script — Cloud → Drone Command Pipeline
# Runs on: LOCAL COMPANION MACHINE (unless noted)
# Usage: sudo bash c2-setup.sh
################################################################################

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()     { echo -e "${RED}[ERROR]${NC}   $*" >&2; exit 1; }
header()  { echo -e "\n${BLUE}══════════════════════════════════════════════════${NC}"; \
            echo -e "${BLUE}  $*${NC}"; \
            echo -e "${BLUE}══════════════════════════════════════════════════${NC}\n"; }

# Helper: send a base64-encoded script via SSM and wait for completion
run_ssm() {
    local DESC="$1"
    local WAIT_MAX="$2"
    local ENCODED="$3"

    local CMD_ID
    CMD_ID=$(aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "{\"commands\":[\"echo ${ENCODED} | base64 -d | bash\"]}" \
        --timeout-seconds "$WAIT_MAX" \
        --query "Command.CommandId" \
        --output text) || die "SSM send-command failed for: $DESC"

    info "SSM CommandId ($DESC): $CMD_ID — waiting up to ${WAIT_MAX}s …"
    local WAIT=0
    while [[ $WAIT -lt $WAIT_MAX ]]; do
        local STATUS
        STATUS=$(aws ssm get-command-invocation \
            --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
            --query "Status" --output text 2>/dev/null || echo "Pending")
        case "$STATUS" in
            Success)
                success "$DESC completed"
                aws ssm get-command-invocation \
                    --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" \
                    --query "StandardOutputContent" --output text 2>/dev/null | sed 's/^/  /'
                return 0 ;;
            Failed|Cancelled|TimedOut)
                local SERR SOUT
                SERR=$(aws ssm get-command-invocation --command-id "$CMD_ID" \
                    --instance-id "$INSTANCE_ID" --query "StandardErrorContent" \
                    --output text 2>/dev/null || true)
                SOUT=$(aws ssm get-command-invocation --command-id "$CMD_ID" \
                    --instance-id "$INSTANCE_ID" --query "StandardOutputContent" \
                    --output text 2>/dev/null || true)
                die "$DESC failed (status=$STATUS)\n── STDERR ──\n$SERR\n── STDOUT ──\n$SOUT" ;;
            *) echo -n "."; sleep 5; WAIT=$((WAIT+5)) ;;
        esac
    done
    echo ""
    warn "$DESC SSM timed out after ${WAIT_MAX}s"
}

################################################################################
# 1. KILL EXISTING PROCESSES
################################################################################
header "Step 1 — Kill existing processes"

pkill -9 -f "mav_encrypt_publish.py" && success "Killed mav_encrypt_publish.py" \
    || warn "mav_encrypt_publish.py was not running"

pkill -9 -f "mav_to_mqtt.py" && success "Killed mav_to_mqtt.py" \
    || warn "mav_to_mqtt.py was not running"

################################################################################
# 2. FETCH EC2 IP & UPDATE SSH TUNNEL SERVICE
################################################################################
header "Step 2 — Fetch mqtt-broker IP and update tunnel service"

EC2_IP=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=mqtt-broker" \
              "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].PublicIpAddress" \
    --output text 2>/dev/null) || die "aws ec2 describe-instances failed"

[[ "$EC2_IP" == "None" || -z "$EC2_IP" ]] && die "Could not find a running EC2 instance named 'mqtt-broker'"
success "mqtt-broker IP: $EC2_IP"

TUNNEL_SERVICE="/etc/systemd/system/mqtt-ssh-tunnel.service"
[[ -f "$TUNNEL_SERVICE" ]] || die "$TUNNEL_SERVICE not found"

sed -i "s|ec2-user@[^ ]*|ec2-user@${EC2_IP}|g" "$TUNNEL_SERVICE"
success "Updated $TUNNEL_SERVICE with IP $EC2_IP"

################################################################################
# 3. FETCH MOSQUITTO PASSWORD VIA SSM
################################################################################
header "Step 3 — Fetch drone MQTT password from broker via SSM"

INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=mqtt-broker" \
              "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text 2>/dev/null) || die "Could not fetch instance ID"

[[ "$INSTANCE_ID" == "None" || -z "$INSTANCE_ID" ]] && die "No running instance named 'mqtt-broker' found"
success "Instance ID: $INSTANCE_ID"

PW_CMD_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters '{"commands":["cat /root/mosquitto_drone_credentials.txt"]}' \
    --query "Command.CommandId" \
    --output text) || die "SSM send-command failed"

info "Fetching drone password (SSM: $PW_CMD_ID) …"
sleep 8

SSM_OUTPUT=$(aws ssm get-command-invocation \
    --command-id "$PW_CMD_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "StandardOutputContent" \
    --output text 2>/dev/null) || die "Could not retrieve SSM output"

DRONE_PASSWORD=$(echo "$SSM_OUTPUT" | grep "^drone:" | head -1 | cut -d':' -f2 | tr -d '[:space:]')
[[ -z "$DRONE_PASSWORD" ]] && die "Could not parse drone password. Raw output:\n$SSM_OUTPUT"
success "Drone password retrieved (${#DRONE_PASSWORD} chars)"

mkdir -p /etc/drone-pub
echo "$DRONE_PASSWORD" > /etc/drone-pub/mqtt_pass.txt
chmod 600 /etc/drone-pub/mqtt_pass.txt
success "Password written to /etc/drone-pub/mqtt_pass.txt"

################################################################################
# 3b. ATTACH IoT PERMISSIONS TO EC2 INSTANCE ROLE
#
# Root cause: IAM credentials used by command_forwarder lacked iot:Receive.
# IoT Core silently accepts SUBSCRIBE but drops message delivery without it.
# Both iot:Subscribe AND iot:Receive are required — they are separate permissions.
#
# This step:
#   1. Reads the instance profile attached to mqtt-broker
#   2. Resolves the IAM role from that profile
#   3. Puts an inline policy granting the four required IoT actions
################################################################################
header "Step 3b — Attach IoT permissions to EC2 instance role"

ROLE_NAME="(no instance profile)"

PROFILE_NAME=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].IamInstanceProfile.Arn" \
    --output text 2>/dev/null || true)

if [[ -z "$PROFILE_NAME" || "$PROFILE_NAME" == "None" ]]; then
    warn "No instance profile attached to $INSTANCE_ID — skipping IoT role policy"
else
    PROFILE_SHORT="${PROFILE_NAME##*/}"
    info "Instance profile: $PROFILE_SHORT"

    ROLE_NAME=$(aws iam get-instance-profile \
        --instance-profile-name "$PROFILE_SHORT" \
        --query "InstanceProfile.Roles[0].RoleName" \
        --output text 2>/dev/null) || die "Could not resolve role from instance profile $PROFILE_SHORT"

    [[ -z "$ROLE_NAME" || "$ROLE_NAME" == "None" ]] && die "No role found in instance profile $PROFILE_SHORT"
    info "IAM role: $ROLE_NAME"

    IOT_POLICY_DOC='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IoTCommandForwarder",
      "Effect": "Allow",
      "Action": [
        "iot:Connect",
        "iot:Subscribe",
        "iot:Receive",
        "iot:Publish"
      ],
      "Resource": "*"
    }
  ]
}'

    aws iam put-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-name "IoTCommandForwarder" \
        --policy-document "$IOT_POLICY_DOC" \
    && success "Inline policy IoTCommandForwarder attached to role $ROLE_NAME" \
    || die "Failed to attach IoT policy to role $ROLE_NAME"

    info "Verifying policy was written …"
    aws iam get-role-policy \
        --role-name "$ROLE_NAME" \
        --policy-name "IoTCommandForwarder" \
        --query "PolicyDocument.Statement[0].Action" \
        --output table 2>/dev/null | sed 's/^/  /' || true
fi

################################################################################
# 4a. REPAIR iot-forwarder.service IF CORRUPTED + WRITE CREDENTIALS
################################################################################
header "Step 4a — Repair service file + write AWS credentials on broker"

STEP4A=$(mktemp /tmp/step4a_XXXXXX.sh)
cat > "$STEP4A" << 'LOCALEOF'
#!/bin/bash
set -e

echo ">>> Restoring /etc/systemd/system/iot-forwarder.service"
sudo rm -f /etc/systemd/system/iot-forwarder.service

printf '%s\n' '[Unit]'                                                              | sudo tee    /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'Description=Drone MQTT → AWS IoT forwarder'                         | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'After=network-online.target'                                         | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'Wants=network-online.target'                                         | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' ''                                                                     | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' '[Service]'                                                            | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'Type=simple'                                                          | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'EnvironmentFile=-/opt/iot-forwarder/aws_credentials.env'             | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'ExecStart=/usr/bin/python3 /opt/iot-forwarder/forwarder_to_iot.py'  | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'Restart=always'                                                       | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'RestartSec=10'                                                        | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'StandardOutput=journal'                                               | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'StandardError=journal'                                                | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' ''                                                                     | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' '[Install]'                                                            | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null
printf '%s\n' 'WantedBy=multi-user.target'                                          | sudo tee -a /etc/systemd/system/iot-forwarder.service > /dev/null

echo ">>> iot-forwarder.service restored:"
cat /etc/systemd/system/iot-forwarder.service

echo ">>> Writing /opt/iot-forwarder/aws_credentials.env"
sudo mkdir -p /opt/iot-forwarder

printf '%s\n' 'AWS_ACCESS_KEY_ID=AKIAWGJxxxxx'                                    | sudo tee    /opt/iot-forwarder/aws_credentials.env > /dev/null
printf '%s\n' 'AWS_SECRET_ACCESS_KEY=MEWlcNp3liZSE6UZQHUxxxxxxxxxxx'            | sudo tee -a /opt/iot-forwarder/aws_credentials.env > /dev/null
printf '%s\n' 'AWS_REGION=us-east-1'                                                        | sudo tee -a /opt/iot-forwarder/aws_credentials.env > /dev/null
printf '%s\n' 'AWS_IOT_ENDPOINT=a1asql9cssattj-ats.iot.us-east-1.amazonaws.com'            | sudo tee -a /opt/iot-forwarder/aws_credentials.env > /dev/null

sudo chmod 600 /opt/iot-forwarder/aws_credentials.env
echo ">>> aws_credentials.env written:"
cat /opt/iot-forwarder/aws_credentials.env

echo ">>> Installing Python deps"
sudo pip3 install --quiet boto3 paho-mqtt

echo ">>> daemon-reload + restart iot-forwarder"
sudo systemctl daemon-reload
sudo systemctl restart iot-forwarder || true
sleep 3
sudo systemctl is-active iot-forwarder \
    && echo ">>> iot-forwarder is running OK" \
    || echo ">>> WARNING: iot-forwarder not active — check journalctl -u iot-forwarder"

echo ">>> STEP4A_DONE"
LOCALEOF

run_ssm "4a-repair-and-credentials" 90 "$(base64 -w 0 < "$STEP4A")"
rm -f "$STEP4A"

################################################################################
# 4b. DOWNLOAD AND RUN deploy-forwarders.sh ON BROKER — FOR EACH DRONE
################################################################################
header "Step 4b — Run deploy-forwarders.sh on broker for each drone"

STEP4B=$(mktemp /tmp/step4b_XXXXXX.sh)
cat > "$STEP4B" << 'LOCALEOF'
#!/bin/bash
set -e
GITHUB_URL="https://raw.githubusercontent.com/AryaMajumder/cloud-to-drone-command-pipeline/main/drone%20command%20link/broker-command%26ack-forwarder/deploy-forwarders.sh"

echo ">>> Downloading deploy-forwarders.sh"
curl -fsSL --retry 3 --retry-delay 2 "$GITHUB_URL" -o /tmp/deploy-raw.sh

FIRST=$(head -1 /tmp/deploy-raw.sh)
if [[ "$FIRST" != "#!"* ]]; then
    echo "ERROR: Not a shell script — got: $FIRST"
    head -5 /tmp/deploy-raw.sh
    exit 1
fi

# Strip CRLF and patch out interactive prompts
tr -d '\r' < /tmp/deploy-raw.sh \
    | sed "s/read -p 'Continue.*' -n 1 -r/REPLY=y/" \
    > /tmp/deploy-forwarders.sh
rm -f /tmp/deploy-raw.sh
chmod +x /tmp/deploy-forwarders.sh
echo ">>> Ready — $(wc -l < /tmp/deploy-forwarders.sh) lines (CRLF stripped, prompt patched)"

if grep -q "read -p" /tmp/deploy-forwarders.sh; then
    echo "WARNING: 'read -p' still found after patch:"
    grep -n "read -p" /tmp/deploy-forwarders.sh
fi

DRONE_PASS=$(grep "^drone:" /root/mosquitto_drone_credentials.txt | head -1 | cut -d':' -f2 | tr -d '[:space:]')
echo ">>> Drone MQTT password: ${#DRONE_PASS} chars"

sudo mkdir -p /opt/forwarders/drone-01
sudo mkdir -p /opt/forwarders/drone-02
echo ">>> /opt/forwarders/drone-01 and drone-02 pre-created"

# ── Deploy forwarders for each drone independently ───────────────────────────
for DRONE_ID in drone-01 drone-02; do
    LOG="/tmp/deploy-forwarders-${DRONE_ID}.log"
    echo ">>> Launching deploy-forwarders.sh for ${DRONE_ID} — log: $LOG"

    nohup bash -c "yes y | bash -x /tmp/deploy-forwarders.sh \
        --aws-access-key  'AKIAWGJ4MNG2PPvvvvvvv' \
        --aws-secret-key  'MEWlcNp3liZSE6UZQHU6RuoQCvvvvvvvvvv' \
        --iot-endpoint    'a1asql9cssattj-ats.iot.us-east-1.amazonaws.com' \
        --drone-id        '${DRONE_ID}' \
        --install-dir     '/opt/forwarders/${DRONE_ID}' \
        --mqtt-user       'drone' \
        --mqtt-pass       '${DRONE_PASS}'" \
        > "$LOG" 2>&1 &

    DEPLOY_PID=$!
    echo ">>> ${DRONE_ID} PID: $DEPLOY_PID"

    WAITED=0
    while kill -0 "$DEPLOY_PID" 2>/dev/null; do
        sleep 5; WAITED=$((WAITED+5))
        echo "  … ${DRONE_ID} ${WAITED}s"
        [[ $WAITED -ge 150 ]] && { echo ">>> Timeout — check $LOG"; break; }
    done

    echo ">>> Log tail for ${DRONE_ID} (last 50 lines):"
    tail -50 "$LOG" 2>/dev/null || echo "(empty log)"
    echo ">>> ${DRONE_ID} deploy done"
done

echo ">>> STEP4B_DONE"
LOCALEOF

run_ssm "4b-deploy-forwarders" 420 "$(base64 -w 0 < "$STEP4B")"
rm -f "$STEP4B"

################################################################################
# 4c. ENSURE EC2 SECURITY GROUP ALLOWS ALL INBOUND CONNECTIONS
################################################################################
header "Step 4c — Open EC2 security group to allow all inbound traffic"

SG_IDS=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].SecurityGroups[*].GroupId" \
    --output text 2>/dev/null) || die "Could not fetch security group IDs"

[[ -z "$SG_IDS" ]] && die "No security groups found on instance $INSTANCE_ID"
info "Security groups on mqtt-broker: $SG_IDS"

for SG_ID in $SG_IDS; do
    info "Processing SG: $SG_ID"

    EXISTING=$(aws ec2 describe-security-groups \
        --group-ids "$SG_ID" \
        --query "SecurityGroups[0].IpPermissions[?IpProtocol=='-1'] | [?IpRanges[?CidrIp=='0.0.0.0/0']]" \
        --output text 2>/dev/null || true)

    if [[ -n "$EXISTING" ]]; then
        success "SG $SG_ID already has allow-all inbound rule — skipping"
        continue
    fi

    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol "-1" \
        --port "-1" \
        --cidr "0.0.0.0/0" 2>/dev/null \
    && success "SG $SG_ID — allow-all IPv4 inbound added" \
    || warn "SG $SG_ID — IPv4 rule may already exist"

    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --ip-permissions '[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]' 2>/dev/null \
    && success "SG $SG_ID — allow-all IPv6 inbound added" \
    || warn "SG $SG_ID — IPv6 rule may already exist"
done

for SG_ID in $SG_IDS; do
    info "Current inbound rules for $SG_ID:"
    aws ec2 describe-security-groups \
        --group-ids "$SG_ID" \
        --query "SecurityGroups[0].IpPermissions" \
        --output table 2>/dev/null | sed 's/^/  /' || true
done

################################################################################
# 5. RESTART LOCAL SERVICES
################################################################################
header "Step 5 — Reload systemd and restart local services"

systemctl daemon-reload
success "systemd daemon reloaded"

systemctl restart mqtt-ssh-tunnel.service
success "mqtt-ssh-tunnel.service restarted"

systemctl restart drone-pipeline.service
success "drone-pipeline.service restarted"

systemctl restart drone-pipeline-02.service
success "drone-pipeline-02.service restarted"

################################################################################
# 6. CREATE COMMAND PROCESSOR
################################################################################
header "Step 6 — Create command processor (Lambda + ACK storage)"

CREATE_LAMBDA_SCRIPT="/opt/drone-command/create-lambda-fixed.sh"
RUN_ALL_SCRIPT="/root/ack-storage/run-all.sh"

if [[ -x "$CREATE_LAMBDA_SCRIPT" ]]; then
    info "Running $CREATE_LAMBDA_SCRIPT …"
    bash "$CREATE_LAMBDA_SCRIPT"
    success "create-lambda-fixed.sh completed"
else
    die "$CREATE_LAMBDA_SCRIPT not found or not executable"
fi

if [[ -x "$RUN_ALL_SCRIPT" ]]; then
    info "Running $RUN_ALL_SCRIPT …"
    bash "$RUN_ALL_SCRIPT"
    success "run-all.sh completed"
else
    die "$RUN_ALL_SCRIPT not found or not executable"
fi

################################################################################
# DONE
################################################################################
header "✅  C2 Setup Complete"

cat << SUMMARY
  EC2 (mqtt-broker) IP  : $EC2_IP
  Instance ID           : $INSTANCE_ID
  IAM role              : $ROLE_NAME — IoTCommandForwarder policy applied
  Security groups       : $SG_IDS — allow-all inbound ensured
  Drone MQTT password   : written to /etc/drone-pub/mqtt_pass.txt
  SSH tunnel service    : restarted
  drone-pipeline        : restarted
  drone-pipeline-02     : restarted
  Lambda + ACK storage  : provisioned

Post-run checks on broker (SSM in):
  systemctl status iot-forwarder
  systemctl status ack_forwarder
  systemctl status command_forwarder
  cat /tmp/deploy-forwarders-drone-01.log      <- drone-01 bash -x trace
  cat /tmp/deploy-forwarders-drone-02.log      <- drone-02 bash -x trace

Local checks:
  systemctl status mqtt-ssh-tunnel.service
  systemctl status drone-pipeline.service
  systemctl status drone-pipeline-02.service
SUMMARY
