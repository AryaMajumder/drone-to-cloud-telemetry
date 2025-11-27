#!/usr/bin/env bash
# mosquitto_ec2_setup.sh
# Idempotent script to:
#  - update mosquitto config listener/auth/logging
#  - enable SSH on ports 22 and 443 and allow TCP forwarding (for ssh tunnel)
#  - add an SSH public key to ec2-user authorized_keys
#  - create /var/log/mosquitto and set perms
#  - install logrotate config for mosquitto logs
#  - backup any files modified
#
# Usage:
#   sudo ./mosquitto_ec2_setup.sh
#   sudo PUBLIC_MOSQUITTO=1 ./mosquitto_ec2_setup.sh   # if you want mosquitto to listen on 0.0.0.0
#
set -euo pipefail
IFS=$'\n\t'

# ---------- Configurable variables ----------
# Set PUBLIC_MOSQUITTO=1 in environment to change listener to 0.0.0.0 (explicit opt-in).
PUBLIC_MOSQUITTO=${PUBLIC_MOSQUITTO:-0}

# The mosquitto config path we will edit
MOS_CONF=${MOS_CONF:-/usr/local/etc/mosquitto/mosquitto.conf}

# Where mosquitto password file should live (script ensures it's referenced)
PASSFILE=${PASSFILE:-/usr/local/etc/mosquitto/passwords}

# SSH pubkey to add to ec2-user authorized_keys. Edit this value or export PUBLIC_SSH_KEY in env before running.
# (Default is the example key you pasted; replace it if you want a different key.)
PUBLIC_SSH_KEY=${PUBLIC_SSH_KEY:-"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2evMuoB+VKvlD3fm8zaOMQSyBZl8cppCZvgBBp0R3+ companion@DESKTOP-5AL6U1P"}

# sshd config path
SSHD_CONF=/etc/ssh/sshd_config

# mosquitto logfile path and logrotate config path
MOS_LOG_DIR=/var/log/mosquitto
MOS_LOG_FILE=${MOS_LOG_DIR}/mosquitto.log
LOGROTATE_CONF=/etc/logrotate.d/mosquitto

# timestamp for backups
STAMP=$(date +%s)

# ---------- helper functions ----------
bak() {
  # create a backup of a file if it exists (filename.bak.TIMESTAMP)
  local f="$1"
  if [ -f "$f" ]; then
    cp -a "$f" "${f}.bak.${STAMP}"
    echo "Backed up $f -> ${f}.bak.${STAMP}"
  fi
}

safe_sed_replace_listener() {
  # Replace or append mosquitto listener + auth block.
  # Accepts two args: $1 = listener_host (e.g., "127.0.0.1" or "0.0.0.0")
  local host="$1"
  local tmp="${MOS_CONF}.tmp.${STAMP}"

  # Ensure directory exists
  mkdir -p "$(dirname "$MOS_CONF")"

  # If MOS_CONF doesn't exist create an empty file so awk can operate
  if [ ! -f "$MOS_CONF" ]; then
    touch "$MOS_CONF"
    chown mosquitto:mosquitto "$MOS_CONF" 2>/dev/null || true
  fi

  # Use awk to replace an existing 'listener 1883 ...' stanza (and any following allow_anonymous/password_file lines)
  # or append the canonical block if not found.
  awk -v host="$host" '
  BEGIN { replaced=0; skipping=0 }
  {
    # if we find listener 1883, print our replacement block and enter skipping mode
    if ($1=="listener" && $2=="1883") {
      print "listener 1883 " host
      print "allow_anonymous false"
      print "password_file '"${PASSFILE}"'"
      replaced=1
      skipping=1
      next
    }
    # while skipping, skip any allow_anonymous/password_file lines
    if (skipping==1) {
      if ($1=="allow_anonymous" || $1=="password_file") {
        next
      } else {
        skipping=0
      }
    }
    print $0
  }
  END {
    if (!replaced) {
      print ""
      print "# Added by mosquitto_ec2_setup.sh"
      print "listener 1883 " host
      print "allow_anonymous false"
      print "password_file '"${PASSFILE}"'"
    }
  }' "$MOS_CONF" > "$tmp" && mv "$tmp" "$MOS_CONF"
}

ensure_logging_in_mosconf() {
  # Ensure the specified logging lines exist (append if missing).
  # We'll add log_dest file, log_dest syslog, a set of log_type lines, and log_timestamp true.
  local tmp="${MOS_CONF}.tmp.log.${STAMP}"

  # Build the logging block we want to ensure present
  read -r -d '' LOGBLOCK <<'EOF' || true
# logging (added by mosquitto_ec2_setup.sh)
log_dest file /var/log/mosquitto/mosquitto.log
log_dest syslog
log_type error
log_type warning
log_type notice
log_type information
log_timestamp true
EOF

  # If these lines already appear, do not duplicate — we'll insert the block if none of the key lines exist.
  if grep -qE '^[[:space:]]*log_dest file[[:space:]]+/var/log/mosquitto/mosquitto.log' "$MOS_CONF" 2>/dev/null || \
     grep -qE '^[[:space:]]*log_dest syslog' "$MOS_CONF" 2>/dev/null; then
    echo "Mosquitto logging entries already exist in $MOS_CONF; skipping log block append."
    return
  fi

  # Append the block to the end (idempotent due to prior grep)
  printf "\n%s\n" "$LOGBLOCK" >> "$MOS_CONF"
}

add_ssh_port_and_forwarding() {
  # Backup sshd_config and ensure Port 22 and Port 443 exist and AllowTcpForwarding yes and LogLevel VERBOSE.
  bak "$SSHD_CONF"

  # Add Port 22 if missing
  if ! grep -E '^[[:space:]]*Port[[:space:]]+22' "$SSHD_CONF" >/dev/null 2>&1; then
    echo "Port 22" >> "$SSHD_CONF"
    echo "Added 'Port 22' to $SSHD_CONF"
  else
    # make sure it's not commented out — if commented, add an explicit Port 22 line to be safe
    if grep -E '^[[:space:]]*#.*Port[[:space:]]+22' "$SSHD_CONF" >/dev/null 2>&1; then
      echo "Port 22" >> "$SSHD_CONF"
      echo "Added explicit 'Port 22' because only commented Port 22 found"
    fi
  fi

  # Add Port 443 if missing
  if ! grep -E '^[[:space:]]*Port[[:space:]]+443' "$SSHD_CONF" >/dev/null 2>&1; then
    echo "Port 443" >> "$SSHD_CONF"
    echo "Added 'Port 443' to $SSHD_CONF"
  else
    # handle commented case similarly
    if grep -E '^[[:space:]]*#.*Port[[:space:]]+443' "$SSHD_CONF" >/dev/null 2>&1; then
      echo "Port 443" >> "$SSHD_CONF"
      echo "Added explicit 'Port 443' because only commented Port 443 found"
    fi
  fi

  # Ensure AllowTcpForwarding yes (replace any existing AllowTcpForwarding line)
  if grep -Ei '^[[:space:]]*AllowTcpForwarding' "$SSHD_CONF" >/dev/null 2>&1; then
    sed -i -E 's/^[[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/I' "$SSHD_CONF"
    echo "Set 'AllowTcpForwarding yes' in $SSHD_CONF"
  else
    echo "AllowTcpForwarding yes" >> "$SSHD_CONF"
    echo "Appended 'AllowTcpForwarding yes' to $SSHD_CONF"
  fi

  # Set LogLevel VERBOSE for debugging (only if not present or to replace existing)
  if grep -Ei '^[[:space:]]*LogLevel' "$SSHD_CONF" >/dev/null 2>&1; then
    sed -i -E 's/^[[:space:]]*LogLevel.*/LogLevel VERBOSE/I' "$SSHD_CONF"
    echo "Set 'LogLevel VERBOSE' in $SSHD_CONF"
  else
    echo "LogLevel VERBOSE" >> "$SSHD_CONF"
    echo "Appended 'LogLevel VERBOSE' to $SSHD_CONF"
  fi
}

restart_and_show_sshd() {
  # Restart sshd carefully and show status; print warnings about lockout risk.
  echo
  echo ">> About to restart sshd. IMPORTANT: ensure your EC2 Security Group allows inbound TCP 443 (and 22) before proceeding."
  echo "If you rely solely on SSH, ensure you have an alternative recovery method (SSM/console) in case of lockout."
  sleep 2
  systemctl restart sshd
  systemctl status sshd --no-pager || true
}

add_public_key_to_ec2_user() {
  # Ensure ec2-user .ssh exists and append key to authorized_keys if not present.
  local user_home
  # Try typical home for ec2-user; fallback to /home/ec2-user
  user_home=$(getent passwd ec2-user | cut -d: -f6 || echo "/home/ec2-user")

  mkdir -p "${user_home}/.ssh"
  chmod 700 "${user_home}/.ssh"
  touch "${user_home}/.ssh/authorized_keys"
  chmod 600 "${user_home}/.ssh/authorized_keys"

  # Add key only if not already present
  if ! grep -Fqx "${PUBLIC_SSH_KEY}" "${user_home}/.ssh/authorized_keys" 2>/dev/null; then
    echo "${PUBLIC_SSH_KEY}" >> "${user_home}/.ssh/authorized_keys"
    echo "Appended SSH public key to ${user_home}/.ssh/authorized_keys"
  else
    echo "SSH public key already present in ${user_home}/.ssh/authorized_keys; not adding duplicate"
  fi

  # Ensure ownership is correct if the user exists
  if id -u ec2-user >/dev/null 2>&1; then
    chown -R ec2-user:ec2-user "${user_home}/.ssh" || true
  fi
}

ensure_mos_log_dir_and_perms() {
  # Create /var/log/mosquitto and set ownership/perms
  mkdir -p "${MOS_LOG_DIR}"
  chown mosquitto:mosquitto "${MOS_LOG_DIR}" 2>/dev/null || true
  chmod 0750 "${MOS_LOG_DIR}" || true
  echo "Ensured ${MOS_LOG_DIR} exists with correct perms"
}

install_logrotate_config() {
  # Install a logrotate config for mosquitto if not already present
  if [ -f "${LOGROTATE_CONF}" ]; then
    echo "Logrotate config ${LOGROTATE_CONF} already exists; skipping creation."
    return
  fi

  cat > "${LOGROTATE_CONF}" <<'LR'
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
LR

  echo "Installed logrotate config at ${LOGROTATE_CONF}"
}

restart_and_show_mosquitto() {
  # Restart mosquitto to pick up config changes; tolerant to failures
  systemctl daemon-reload || true
  systemctl restart mosquitto || true
  systemctl enable --now mosquitto || true

  echo
  echo "=== mosquitto status ==="
  systemctl status mosquitto --no-pager || true

  echo
  echo "=== listening sockets (1883) ==="
  ss -lntp | grep 1883 || true

  echo
  echo "=== recent mosquitto logs ==="
  journalctl -u mosquitto -n 80 --no-pager || true

  # show the mosquitto log file head if present
  if [ -f "${MOS_LOG_FILE}" ]; then
    echo
    echo "=== tail of ${MOS_LOG_FILE} ==="
    tail -n 80 "${MOS_LOG_FILE}" || true
  fi
}

# ---------- MAIN flow ----------
echo "Starting mosquitto + sshd configuration script"
echo "Backup timestamp: ${STAMP}"

# 1) Backup mosquitto.conf and modify listener + password_file block
bak "$MOS_CONF"

if [ "${PUBLIC_MOSQUITTO}" -eq 1 ]; then
  echo "Configuring Mosquitto to listen on 0.0.0.0 (PUBLIC_MOSQUITTO=1)"
  safe_sed_replace_listener "0.0.0.0"
else
  echo "Keeping Mosquitto bound to loopback 127.0.0.1 (recommended for SSH tunneling)"
  safe_sed_replace_listener "127.0.0.1"
fi

# 2) Ensure logging directives exist in mosquitto.conf
ensure_logging_in_mosconf

# 3) Ensure mosquitto password file reference exists (PASSFILE). If password file doesn't exist, we create an empty file and lock perms.
if [ ! -f "${PASSFILE}" ]; then
  mkdir -p "$(dirname "${PASSFILE}")"
  touch "${PASSFILE}"
  # keep secure perms
  chown mosquitto:mosquitto "${PASSFILE}" 2>/dev/null || true
  chmod 0600 "${PASSFILE}" || true
  echo "Created placeholder password file at ${PASSFILE} (fill with mosquitto_passwd or bcrypt hashes before enabling remote clients)"
else
  echo "Password file ${PASSFILE} already exists; left unchanged"
fi

# 4) Create /var/log/mosquitto and set perms
ensure_mos_log_dir_and_perms

# 5) Install logrotate config for mosquitto
install_logrotate_config

# 6) SSH config edits to listen on ports 22 & 443 and allow TCP forwarding (for tunnel forwarding)
bak "$SSHD_CONF"
add_ssh_port_and_forwarding

# 7) Add the provided SSH public key to ec2-user authorized_keys
add_public_key_to_ec2_user

# 8) Restart sshd and show status (BE SURE your SG/firewall allows port 443!)
restart_and_show_sshd

# 9) Restart mosquitto to pick up config changes (and print status/logs)
restart_and_show_mosquitto

echo
echo "DONE. Important reminders:"
echo " - If you want clients to reach the EC2 machine's SSH on port 443, ensure your EC2 Security Group allows inbound TCP 443 from client IPs."
echo " - If you set PUBLIC_MOSQUITTO=1, the broker will be reachable on 0.0.0.0:1883 — ensure you want that and secure with TLS/auth."
echo " - If you lose SSH access, use EC2 Serial Console, Session Manager (SSM), or provider console to recover."
echo
echo "If you want the script to also generate mosquitto password file entries (using mosquitto_passwd or bcrypt fallback), tell me and I will add that to the script."
