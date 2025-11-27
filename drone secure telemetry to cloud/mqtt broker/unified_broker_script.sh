#!/usr/bin/env bash
#
# setup_mosquitto_complete.sh
#
# All-in-one idempotent Mosquitto build/install + auth + systemd + "fixes" for SSH tunneling on EC2.
# - Default: Mosquitto listens on 127.0.0.1 (safer), SSH listens on 22 & 443 to support SSH local forwarding:
#     client: ssh -L 1883:127.0.0.1:1883 -p 443 ec2-user@<ec2-host>
# - Set PUBLIC_MOSQUITTO=1 to make mosquitto listen on 0.0.0.0 instead (explicit opt-in).
#
# Usage:
#   sudo ./setup_mosquitto_complete.sh         # full flow (build, install, auth, systemd, fixes, status)
#   sudo PUBLIC_MOSQUITTO=1 ./setup_mosquitto_complete.sh  # same but set listener 0.0.0.0
#
set -euxo pipefail

# ---------- config ----------
MOSQ_VERSION=${MOSQ_VERSION:-"2.0.17"}
TMPDIR=${TMPDIR:-/tmp}
SRC_TAR="${TMPDIR}/mosquitto-${MOSQ_VERSION}.tar.gz"
SRC_DIR="${TMPDIR}/mosquitto-${MOSQ_VERSION}"
BUILD_DIR="${SRC_DIR}/build"
INSTALL_PREFIX=${INSTALL_PREFIX:-/usr/local}
BIN_DIR="${INSTALL_PREFIX}/bin"
LIB_DIR="${INSTALL_PREFIX}/lib64"
CONF_DIR="${INSTALL_PREFIX}/etc/mosquitto"
PASSFILE="${CONF_DIR}/passwords"
LOGDIR="${TMPDIR}"
BUILDLOG="${LOGDIR}/mosquitto-build.log"
INSTALLLOG="${LOGDIR}/mosquitto-install.log"
BOOTLOG="${LOGDIR}/mosquitto-bootstrap.log"
PATH="${BIN_DIR}:${PATH}"
export PATH

# Set this to 1 to make mosquitto listen publicly (0.0.0.0).
# Default is 0 (listen only on 127.0.0.1).
PUBLIC_MOSQUITTO=${PUBLIC_MOSQUITTO:-0}

# ---------- logging ----------
exec > >(tee -a "${BOOTLOG}") 2>&1
echo "=== mosquitto complete bootstrap start: $(date) ==="

# ---------- helpers ----------
dnf_makecache() { dnf makecache --refresh -y || true; }

ensure_ssm_agent() {
  systemctl enable amazon-ssm-agent || true
  systemctl restart amazon-ssm-agent || true
}

ensure_dev_pkgs_for_build() {
  dnf_makecache
  dnf -y groupinstall "Development Tools" || true
  dnf -y install wget curl tar openssl-devel c-ares-devel libuuid-devel pkgconfig \
                 libxslt libxml2 libxml2-devel openssh-clients shadow-utils \
                 gcc make autoconf automake perl perl-ExtUtils-Embed || true
}

ensure_cmake() {
  if ! command -v cmake >/dev/null 2>&1; then
    if ! dnf -y install cmake; then
      echo "dnf cmake failed; installing Kitware binary"
      CMAKE_VER="3.27.8"
      cd "${TMPDIR}"
      curl -fsSL -o "cmake-${CMAKE_VER}-linux-x86_64.tar.gz" \
        "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}-linux-x86_64.tar.gz"
      tar --strip-components=1 -C /usr/local -xzf "cmake-${CMAKE_VER}-linux-x86_64.tar.gz"
      rm -f "cmake-${CMAKE_VER}-linux-x86_64.tar.gz"
    fi
  fi
  cmake --version || true
}

# ---------- build ----------
build_mosquitto() {
  echo "==> build_mosquitto: cleaning previous sources/build"
  systemctl stop mosquitto || true
  rm -rf "${SRC_DIR}" "${BUILD_DIR}" "${SRC_TAR}" "${BUILDLOG}"* "${INSTALLLOG}"* || true

  echo "==> build_mosquitto: download mosquitto ${MOSQ_VERSION}"
  cd "${TMPDIR}"
  wget -q -O "${SRC_TAR}" "https://github.com/eclipse/mosquitto/archive/refs/tags/v${MOSQ_VERSION}.tar.gz"
  tar -xzf "${SRC_TAR}" -C "${TMPDIR}"
  cd "${SRC_DIR}"

  do_build_no_man() {
    rm -rf "${BUILD_DIR}" CMakeCache.txt CMakeFiles || true
    unset CMAKE_PREFIX_PATH || true

    cmake -B "${BUILD_DIR}" \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_TLS=OFF \
      -DWITH_WEBSOCKETS=OFF \
      -DWITH_MAN=OFF \
      -DWITH_MANPAGES=OFF \
      -DWITH_CPP=OFF \
      2>&1 | tee "${BUILDLOG}.cmake"

    cmake --build "${BUILD_DIR}" -j"$(nproc)" 2>&1 | tee "${BUILDLOG}.build"
  }

  ensure_dev_pkgs_for_build
  ensure_cmake

  do_build_no_man || true

  if grep -qi "xsltproc not found" "${BUILDLOG}.cmake" 2>/dev/null || grep -qi "xsltproc not found" "${BUILDLOG}.build" 2>/dev/null; then
    echo "xsltproc required — installing docbook/xsltproc and retrying"
    dnf_makecache
    dnf -y install libxslt libxslt-devel libxml2 docbook-style-xsl docbook-dtds xsltproc || true
    do_build_no_man || true
  fi
}

# ---------- install ----------
install_mosquitto() {
  echo "==> install_mosquitto: attempting cmake --install"
  mkdir -p "${BIN_DIR}" "${LIB_DIR}" "${CONF_DIR}" || true

  if cmake --install "${BUILD_DIR}" >"${INSTALLLOG}" 2>&1; then
    echo "cmake --install done"
  fi

  if [ ! -x "${BIN_DIR}/mosquitto" ]; then
    echo "copying built artifacts (manual fallback)"
    [ -f "${BUILD_DIR}/src/mosquitto" ] && cp -f "${BUILD_DIR}/src/mosquitto" "${BIN_DIR}/mosquitto" && chmod 755 "${BIN_DIR}/mosquitto"
    for f in mosquitto_pub mosquitto_sub mosquitto_rr; do
      [ -f "${BUILD_DIR}/client/${f}" ] && cp -f "${BUILD_DIR}/client/${f}" "${BIN_DIR}/${f}" && chmod 755 "${BIN_DIR}/${f}"
    done
    if [ -f "${BUILD_DIR}/apps/mosquitto_passwd/mosquitto_passwd" ]; then
      cp -f "${BUILD_DIR}/apps/mosquitto_passwd/mosquitto_passwd" "${BIN_DIR}/mosquitto_passwd"
      chmod 755 "${BIN_DIR}/mosquitto_passwd"
    fi
    if compgen -G "${BUILD_DIR}/lib/libmosquitto.so*" >/dev/null 2>&1; then
      cp -f "${BUILD_DIR}/lib/"libmosquitto.so* "${LIB_DIR}/" || true
    fi
    if compgen -G "${BUILD_DIR}/lib/cpp/libmosquittopp.so*" >/dev/null 2>&1; then
      cp -f "${BUILD_DIR}/lib/cpp/"libmosquittopp.so* "${LIB_DIR}/" || true
    fi

    pushd "${LIB_DIR}" >/dev/null 2>&1 || true
    if ls libmosquitto.so.* >/dev/null 2>&1; then
      latest=$(ls -1 libmosquitto.so.* | sort -V | tail -n1)
      ln -sf "${latest}" libmosquitto.so.2 || true
      ln -sf "${latest}" libmosquitto.so || true
    fi
    if ls libmosquittopp.so.* >/dev/null 2>&1; then
      latestcpp=$(ls -1 libmosquittopp.so.* | sort -V | tail -n1)
      ln -sf "${latestcpp}" libmosquittopp.so.1 || true
      ln -sf "${latestcpp}" libmosquittopp.so || true
    fi
    popd >/dev/null 2>&1 || true
    ldconfig || true
  fi

  if [ ! -x "${BIN_DIR}/mosquitto" ]; then
    echo "FATAL: mosquitto binary missing after build/copy. TAIL logs below for debugging."
    tail -n 200 "${BUILDLOG}.build" || true
    tail -n 200 "${INSTALLLOG}" || true
    exit 1
  fi
}

# ---------- user & perms ----------
ensure_user_and_permissions() {
  if ! id -u mosquitto >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /sbin/nologin mosquitto || true
  fi

  mkdir -p "${CONF_DIR}" /var/lib/mosquitto /var/log/mosquitto
  chown -R mosquitto:mosquitto "${CONF_DIR}" /var/lib/mosquitto /var/log/mosquitto || true
  chmod 750 "${CONF_DIR}" || true
  chmod 700 /var/lib/mosquitto || true
  chmod 750 /var/log/mosquitto || true
}

# ---------- auth ----------
write_passwords_with_mosquitto_passwd() {
  local BIN_PASSWD="${BIN_DIR}/mosquitto_passwd"
  if ! [ -x "${BIN_PASSWD}" ]; then
    BIN_PASSWD="$(command -v mosquitto_passwd || true)"
  fi
  if [ -n "${BIN_PASSWD}" ] && [ -x "${BIN_PASSWD}" ]; then
    echo "Using mosquitto_passwd at ${BIN_PASSWD} to create password file"
    mkdir -p "${CONF_DIR}"
    if [ ! -f "${PASSFILE}" ]; then
      DRONE_PW="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
      CONSUMER_PW="consumerpass"
      "${BIN_PASSWD}" -c -b "${PASSFILE}" drone "${DRONE_PW}"
      "${BIN_PASSWD}" -b "${PASSFILE}" consumer "${CONSUMER_PW}"
      chown mosquitto:mosquitto "${PASSFILE}" || true
      chmod 600 "${PASSFILE}" || true
      printf "drone:%s\nconsumer:%s\n" "${DRONE_PW}" "${CONSUMER_PW}" > /root/mosquitto_drone_credentials.txt
      chmod 600 /root/mosquitto_drone_credentials.txt || true
      echo "Saved creds to /root/mosquitto_drone_credentials.txt"
    else
      chown mosquitto:mosquitto "${PASSFILE}" || true
      chmod 600 "${PASSFILE}" || true
      echo "Password file already exists; left unchanged."
    fi
    return 0
  fi
  return 1
}

write_passwords_with_python_bcrypt() {
  echo "mosquitto_passwd not available — using python3 + bcrypt to write password file."

  if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 required for bcrypt fallback but not found" >&2
    return 1
  fi

  if ! python3 -m pip --version >/dev/null 2>&1; then
    python3 -m ensurepip --upgrade || true
    python3 -m pip install --upgrade pip || true
  fi

  if ! python3 -c "import bcrypt" >/dev/null 2>&1; then
    echo "bcrypt python package missing; installing build deps and bcrypt"
    dnf -y install gcc python3-devel openssl-devel libffi-devel || true
    python3 -m pip install --upgrade pip
    python3 -m pip install --upgrade bcrypt
  fi

  mkdir -p "${CONF_DIR}"

  DRONE_PW="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
  CONSUMER_PW="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"

  DRONE_HASH=$(python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" "$DRONE_PW")
  CONSUMER_HASH=$(python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" "$CONSUMER_PW")

  if [ -z "${DRONE_HASH}" ] || [ -z "${CONSUMER_HASH}" ]; then
    echo "ERROR: empty bcrypt hash produced; aborting" >&2
    python3 -V
    python3 -m pip show bcrypt || true
    return 1
  fi

  printf "%s:%s\n" "drone" "${DRONE_HASH}" > "${PASSFILE}"
  printf "%s:%s\n" "consumer" "${CONSUMER_HASH}" >> "${PASSFILE}"

  if id -u mosquitto >/dev/null 2>&1; then
    chown mosquitto:mosquitto "${PASSFILE}" || true
  fi
  chmod 600 "${PASSFILE}" || true

  printf "drone:%s\nconsumer:%s\n" "${DRONE_PW}" "${CONSUMER_PW}" > /root/mosquitto_drone_credentials.txt
  chmod 600 /root/mosquitto_drone_credentials.txt || true
}

ensure_auth() {
  if write_passwords_with_mosquitto_passwd; then
    echo "Created password file with mosquitto_passwd."
  else
    write_passwords_with_python_bcrypt || {
      echo "Both mosquitto_passwd and python bcrypt methods failed; writing anonymous localhost config as fallback (demo mode)."
      cat > "${CONF_DIR}/mosquitto.conf" <<'EOF'
# Localhost-only demo broker (anonymous allowed)
listener 1883 127.0.0.1
allow_anonymous true
# password_file /usr/local/etc/mosquitto/passwords
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
EOF
      chown -R mosquitto:mosquitto "${CONF_DIR}" || true
      chmod 750 "${CONF_DIR}" || true
    }
  fi
}

# ---------- systemd ----------
install_systemd_unit() {
  cat > /etc/systemd/system/mosquitto.service <<'EOF'
[Unit]
Description=Eclipse Mosquitto MQTT Broker (custom build)
After=network.target

[Service]
ExecStart=/usr/local/bin/mosquitto -c /usr/local/etc/mosquitto/mosquitto.conf
Restart=on-failure
RestartSec=3
User=mosquitto
Group=mosquitto
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now mosquitto || true
}

# ---------- apply fixes: mosquitto.conf and sshd_config ----------
apply_fixes() {
  echo "=== apply_fixes: backup and modify mosquitto.conf and /etc/ssh/sshd_config ==="

  # MOSQUITTO CONF
  MOS_CONF="${CONF_DIR}/mosquitto.conf"
  stamp=$(date +%s)
  if [ -f "${MOS_CONF}" ]; then
    cp -a "${MOS_CONF}" "${MOS_CONF}.bak.${stamp}" || true
    echo "Backed up ${MOS_CONF} -> ${MOS_CONF}.bak.${stamp}"
  else
    mkdir -p "$(dirname "${MOS_CONF}")"
    touch "${MOS_CONF}"
    chown mosquitto:mosquitto "${MOS_CONF}" || true
  fi

  # Build replacement block based on PUBLIC_MOSQUITTO
  if [ "${PUBLIC_MOSQUITTO}" -eq 1 ]; then
    read -r -d '' NEW_BLOCK <<'EOF' || true
listener 1883 0.0.0.0
allow_anonymous false
password_file /usr/local/etc/mosquitto/passwords
EOF
  else
    read -r -d '' NEW_BLOCK <<'EOF' || true
listener 1883 127.0.0.1
allow_anonymous false
password_file /usr/local/etc/mosquitto/passwords
EOF
  fi

  # Replace any existing "listener 1883" stanza and adjacent auth lines; append if not present.
  awk -v newblock="$NEW_BLOCK" '
  BEGIN { replaced=0; skip=0 }
  {
    if ($1=="listener" && $2=="1883") {
      # when we encounter listener 1883, print newblock and set skip until we see a line that is not auth-related
      print newblock
      replaced=1
      skip=1
      next
    }
    if (skip==1) {
      # skip allow_anonymous / password_file lines that belonged to old block
      if ($1=="allow_anonymous" || $1=="password_file") {
        next
      } else {
        skip=0
      }
    }
    print $0
  }
  END {
    if (!replaced) {
      print "" 
      print "# Added by setup_mosquitto_complete.sh"
      print newblock
    }
  }' "${MOS_CONF}" > "${MOS_CONF}.tmp" && mv "${MOS_CONF}.tmp" "${MOS_CONF}"

  chown mosquitto:mosquitto "${MOS_CONF}" || true
  chmod 640 "${MOS_CONF}" || true
  echo "Updated ${MOS_CONF}:"
  sed -n '1,200p' "${MOS_CONF}" || true

  # SSHD_CONFIG
  SSHD_CONF="/etc/ssh/sshd_config"
  if [ -f "${SSHD_CONF}" ]; then
    cp -a "${SSHD_CONF}" "${SSHD_CONF}.bak.${stamp}" || true
    echo "Backed up ${SSHD_CONF} -> ${SSHD_CONF}.bak.${stamp}"
  else
    echo "ERROR: ${SSHD_CONF} not present; aborting sshd config edits" >&2
  fi

  # Ensure Port 22 and 443 entries exist (append if missing)
  grep -Ei '^[[:space:]]*Port[[:space:]]+22' "${SSHD_CONF}" >/dev/null 2>&1 || echo "Port 22" >> "${SSHD_CONF}"
  grep -Ei '^[[:space:]]*Port[[:space:]]+443' "${SSHD_CONF}" >/dev/null 2>&1 || echo "Port 443" >> "${SSHD_CONF}"

  # Ensure AllowTcpForwarding yes
  if grep -Ei '^[[:space:]]*AllowTcpForwarding' "${SSHD_CONF}" >/dev/null 2>&1; then
    sed -i -r 's/^[[:space:]]*AllowTcpForwarding.*/AllowTcpForwarding yes/I' "${SSHD_CONF}"
  else
    echo "AllowTcpForwarding yes" >> "${SSHD_CONF}"
  fi

  # Set LogLevel VERBOSE for debugging (you can remove after confirming)
  if grep -Ei '^[[:space:]]*LogLevel' "${SSHD_CONF}" >/dev/null 2>&1; then
    sed -i -r 's/^[[:space:]]*LogLevel.*/LogLevel VERBOSE/I' "${SSHD_CONF}"
  else
    echo "LogLevel VERBOSE" >> "${SSHD_CONF}"
  fi

  echo "Edited ${SSHD_CONF}; showing the last 60 lines:"
  tail -n 60 "${SSHD_CONF}" || true

  # Restart sshd
  echo "Restarting sshd (may lock you out if firewall/Security Group not opened for 443) ..."
  systemctl restart sshd
  systemctl status sshd --no-pager || true

  echo
  echo "IMPORTANT SAFETY NOTES:"
  echo " - Ensure your EC2 security group allows inbound TCP 443 (and 22) from the client(s)."
  echo " - If you lose SSH access, recover via EC2 Serial Console, EC2 Session Manager (SSM), or provider console."
  echo
  echo "To create the client tunnel:"
  echo "  ssh -L 1883:127.0.0.1:1883 -p 443 ec2-user@<ec2-host-or-ip>"
}

# ---------- status ----------
show_status() {
  echo "=== mosquitto status ==="
  systemctl status mosquitto --no-pager || true

  echo "=== listening sockets (1883) ==="
  ss -lntp | grep 1883 || true

  echo "=== tail logs ==="
  journalctl -u mosquitto -n 120 --no-pager || true
  tail -n 80 "${BUILDLOG}.build" || true
  tail -n 80 "${INSTALLLOG}" || true

  echo "=== creds (root-only) ==="
  if [ -f /root/mosquitto_drone_credentials.txt ]; then
    cat /root/mosquitto_drone_credentials.txt
  else
    echo "No credentials written (mosquitto_passwd probably missing or bcrypt fallback not used)."
  fi
}

# ---------- top-level flow ----------
main_all() {
  ensure_ssm_agent
  ensure_dev_pkgs_for_build
  ensure_cmake
  build_mosquitto
  install_mosquitto
  ensure_user_and_permissions
  ensure_auth
  install_systemd_unit
  apply_fixes
  # Restart mosquitto to pick up config if running
  systemctl restart mosquitto || true
  systemctl enable --now mosquitto || true
  show_status
  echo "Bootstrap finished: $(date)"
}

# Run full flow
main_all

# End
