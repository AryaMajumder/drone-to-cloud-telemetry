#!/usr/bin/env bash
# mosquitto_ec2_setup.sh
# Idempotent script to:
#  - update mosquitto config listener/auth/logging
#  - enable SSH on ports 22 and 443 and allow TCP forwarding (for ssh tunnel)
#  - add an SSH public key to ec2-user authorized_keys (explicitly uses /home/ec2-user)
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
PUBLIC_MOSQUITTO=${PUBLIC_MOSQUITTO:-0}  # set to 1 to make mosquitto listen on 0.0.0.0

MOS_CONF=${MOS_CONF:-/usr/local/etc/mosquitto/mosquitto.conf}
PASSFILE=${PASSFILE:-/usr/local/etc/mosquitto/passwords}
SSHD_CONF=/etc/ssh/sshd_config
MOS_LOG_DIR=/var/log/mosquitto
MOS_LOG_FILE=${MOS_LOG_DIR}/mosquitto.log
LOGROTATE_CONF=/etc/logrotate.d/mosquitto

# === IMPORTANT: set this to the public key you want appended to ec2-user's authorized_keys ===
# Replace with your own key if needed or export PUBLIC_SSH_KEY before running
PUBLIC_SSH_KEY=${PUBLIC_SSH_KEY:-"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2evMuoB+VKvlD3fm8zaOMQSyBZl8cppCZvgBBp0R3+ companion@DESKTOP-5AL6U1P"}

EC2_USER=ec2-user                      # account to place the key into
EC2_HOME="/home/${EC2_USER}"           # explicit ec2-user home path
STAMP=$(date +%s)

# ---------- helper functions ----------
bak() {
  local f="$1"
  if [ -f "$f" ]; then
    cp -a "$f" "${f}.bak.${STAMP}"
    echo "Backed up $f -> ${f}.bak.${STAMP}"
  fi
}

safe_sed_replace_listener() {
  local host="$1"
  local tmp="${MOS_CONF}.tmp.${STAMP}"
  mkdir -p "$(dirname "$MOS_CONF")"
  [ -f "$MOS_CONF" ] || touch "$MOS_CONF"
  awk -v host="$host" '
  BEGIN { replaced=0; skipping=0 }
  {
    if ($1=="listener" && $2=="1883") {
      print "listener 1883 " host
      print "allow_anonymous false"
      print "password_file '"${PASSFILE}"'"
      replaced=1
      skipping=1
      next
    }
    if (skipping==1) {
      if ($1=="allow_anonymous" || $1=="password_file") { next } else { skipping=0 }
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

  if grep -qE '^[[:space:]]*log_dest file[[:space:]]+/var/log/mosquitto/mosquitto.log' "$MOS_CONF" 2>/dev/null || \
     grep -qE '^[[:space:]]*log_dest syslog' "$MOS_CONF" 2>/dev/null; then
    echo "Mosquitto logging already configured; skipping."
    return
  fi
  printf "\n%s\n" "$LOGBLOCK" >> "$MOS_CONF"
}

add_ssh_port_and_forwarding() {
  bak "$SSHD_CONF"

  # Ensure Port 22 exists (append if missing or commented)
  if ! grep -E '^[[:space:]]*Port[[:space:]]+22' "$SSHD_CONF" >/dev/null 2>&1; then
    echo "Port 22" >> "$SSHD_CONF"
    echo "Added 'Port 22' to $SSHD_CONF"
  else
    if grep -E '^[[:space:]]*#.*Port[[:space:]]+22' "$SSHD_CONF" >/dev/null 2>&1; then
      echo "Port 22" >> "$SSHD_CONF"
      echo "Added explicit 'Port 22' because only commented Port 22 found"
    fi
  fi

  # Ensure Port 443 exists (append if missing or commented)
  if ! grep -E '^[[:space:]]*Port[[:space:]]+443' "$SSHD_CONF" >/dev/null 2>&1; then
    echo "Port 443" >> "$SSHD_CONF"
    echo "Added 'Port 443' to $SSHD_CONF"
  else
    if grep -E '^[[:space:]]*#.*Port[[:space:]]+443' "$SSHD_CONF" >/dev/null 2>&1; then
      echo "Port 443" >> "$SSHD_CONF"
      echo "Added explicit 'Port 443' because only commented Port 443 found"
    fi
  fi

  # Ensure AllowTcpForwarding yes
  if grep -Ei '^[[:space:]]*AllowTcpForwarding' "$SSHD_CONF" >/dev/null 2>&1; then
    sed -i -E 's/^[[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/I' "$SSHD_CONF"
  else
    echo "AllowTcpForwarding yes" >> "$SSHD_CONF"
  fi
  echo "Set AllowTcpForwarding yes"

  # Ensure LogLevel VERBOSE (helpful for debugging)
  if grep -Ei '^[[:space:]]*LogLevel' "$SSHD_CONF" >/dev/null 2>&1; then
    sed -i -E 's/^[[:space:]]*LogLevel.*/LogLevel VERBOSE/I' "$SSHD_CONF"
  else
    echo "LogLevel VERBOSE" >> "$SSHD_CONF"
  fi
  echo "Set LogLevel VERBOSE"
}

restart_and_show_sshd() {
  echo
  echo ">> Restarting sshd. Confirm EC2 Security Group allows inbound TCP 443 and 22."
  sleep 2
  systemctl restart sshd
  systemctl status sshd --no-pager || true
}

# === The modified function: explicitly target ec2-user home/authorized_keys ===
add_public_key_to_ec2_user() {
  # This function ensures /home/ec2-user/.ssh exists, appends the provided PUBLIC_SSH_KEY
  # only if it's not already present, and sets permissions/ownership to ec2-user:ec2-user.
  local key="$PUBLIC_SSH_KEY"
  local home="$EC2_HOME"
  local sshdir="${home}/.ssh"
  local authfile="${sshdir}/authorized_keys"

  echo "Adding SSH public key to ${authfile} (if not present)"

  # Create home directory if it doesn't exist; this is idempotent
  if [ ! -d "${home}" ]; then
    mkdir -p "${home}"
    echo "Created missing home directory ${home}"
    # If user exists, set owner
    if id -u "${EC2_USER}" >/dev/null 2>&1; then
      chown "${EC2_USER}:${EC2_USER}" "${home}" || true
    fi
  fi

  # Create .ssh dir and authorized_keys with correct perms
  mkdir -p "${sshdir}"
  chmod 700 "${sshdir}" || true

  # Ensure the authorized_keys file exists
  touch "${authfile}"
  chmod 600 "${authfile}" || true

  # Check if key already present (exact line match). If not, append.
  if grep -Fqx "${key}" "${authfile}" 2>/dev/null; then
    echo "SSH public key already present in ${authfile}; no changes made."
  else
    echo "${key}" >> "${authfile}"
    echo "Appended SSH public key to ${authfile}"
  fi

  # Set ownership to ec2-user if that user exists on system
  if id -u "${EC2_USER}" >/dev/null 2>&1; then
    chown -R "${EC2_USER}:${EC2_USER}" "${sshdir}" || true
    echo "Set ownership of ${sshdir} to ${EC2_USER}:${EC2_USER}"
  else
    echo "Warning: user ${EC2_USER} not found; left ${sshdir} owned by current user"
  fi
}

ensure_mos_log_dir_and_perms() {
  mkdir -p "${MOS_LOG_DIR}"
  chown mosquitto:mosquitto "${MOS_LOG_DIR}" 2>/dev/null || true
  chmod 0750 "${MOS_LOG_DIR}" || true
  echo "Ensured ${MOS_LOG_DIR} exists with correct perms"
}

install_logrotate_config() {
  if [ -f "${LOGROTATE_CONF}" ]; then
    echo "Logrotate config already present at ${LOGROTATE_CONF}; skipping"
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
  if [ -f "${MOS_LOG_FILE}" ]; then
    echo
    echo "=== tail of ${MOS_LOG_FILE} ==="
    tail -n 80 "${MOS_LOG_FILE}" || true
  fi
}

# ---------- MAIN flow ----------
echo "Starting mosquitto + sshd configuration script"
echo "Backup timestamp: ${STAMP}"

# 1) Backup and modify mosquitto.conf listener block
bak "$MOS_CONF"
if [ "${PUBLIC_MOSQUITTO}" -eq 1 ]; then
  echo "Configuring Mosquitto to listen on 0.0.0.0 (PUBLIC_MOSQUITTO=1)"
  safe_sed_replace_listener "0.0.0.0"
else
  echo "Keeping Mosquitto bound to loopback 127.0.0.1 (recommended for SSH tunneling)"
  safe_sed_replace_listener "127.0.0.1"
fi

# 2) Ensure logging config present in mosquitto.conf
ensure_logging_in_mosconf

# 3) Ensure password file placeholder exists (locked down); don't overwrite an existing password file
if [ ! -f "${PASSFILE}" ]; then
  mkdir -p "$(dirname "${PASSFILE}")"
  touch "${PASSFILE}"
  chown mosquitto:mosquitto "${PASSFILE}" 2>/dev/null || true
  chmod 0600 "${PASSFILE}" || true
  echo "Created placeholder password file at ${PASSFILE}"
else
  echo "Password file ${PASSFILE} already exists; not modifying"
fi

# 4) Ensure mosquitto log dir and perms
ensure_mos_log_dir_and_perms

# 5) Install logrotate config
install_logrotate_config

# 6) Edit SSH config to add ports and allow forwarding, then restart sshd
bak "$SSHD_CONF"
add_ssh_port_and_forwarding
add_public_key_to_ec2_user
restart_and_show_sshd

# 7) Restart mosquitto and show status/logs
restart_and_show_mosquitto

echo
echo "DONE. Reminders:"
echo " - Ensure EC2 Security Group allows inbound TCP 443 (and 22) from client IPs."
echo " - PUBLIC_MOSQUITTO=1 will expose Mosquitto on 0.0.0.0:1883; secure accordingly."
echo " - If you are locked out of SSH, recover via EC2 Serial Console, EC2 Session Manager (SSM), or cloud provider console."
