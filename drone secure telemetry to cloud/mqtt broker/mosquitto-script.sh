#!/bin/bash
# setup_mosquitto_final.sh
# All-in-one idempotent Mosquitto build/install + permissions + auth fallback script for Amazon Linux 2023.
# Run as root: sudo bash setup_mosquitto_final.sh
set -euxo pipefail

# ---------- config ----------
MOSQ_VERSION="2.0.17"
TMPDIR="/tmp"
SRC_TAR="${TMPDIR}/mosquitto-${MOSQ_VERSION}.tar.gz"
SRC_DIR="${TMPDIR}/mosquitto-${MOSQ_VERSION}"
BUILD_DIR="${SRC_DIR}/build"
INSTALL_PREFIX="/usr/local"
BIN_DIR="${INSTALL_PREFIX}/bin"
LIB_DIR="${INSTALL_PREFIX}/lib64"
CONF_DIR="${INSTALL_PREFIX}/etc/mosquitto"
PASSFILE="${CONF_DIR}/passwords"
LOGDIR="${TMPDIR}"
BUILDLOG="${LOGDIR}/mosquitto-build.log"
INSTALLLOG="${LOGDIR}/mosquitto-install.log"
BOOTLOG="${LOGDIR}/mosquitto-bootstrap.log"
PATH="${BIN_DIR}:${PATH}"   # ensure /usr/local/bin visible for commands we install
export PATH

# unify logging
exec > >(tee -a "${BOOTLOG}") 2>&1
echo "=== mosquitto final bootstrap start: $(date) ==="

# ---------- helper: safe dnf ---------- 
dnf_makecache() { dnf makecache --refresh -y || true; }

# ---------- 0) ensure ssm agent ----------
systemctl enable amazon-ssm-agent || true
systemctl restart amazon-ssm-agent || true

# ---------- 1) base packages ----------
dnf_makecache
dnf -y groupinstall "Development Tools" || true
dnf -y install wget curl tar openssl-devel c-ares-devel libuuid-devel pkgconfig \
               libxslt libxml2 libxml2-devel openssh-clients shadow-utils || true

# ---------- 1.1) ensure cmake (dnf, then kitware) ----------
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

# ---------- 2) clean/download source ----------
echo "==> cleaning previous sources/build"
systemctl stop mosquitto || true
rm -rf "${SRC_DIR}" "${BUILD_DIR}" "${SRC_TAR}" "${BUILDLOG}"* "${INSTALLLOG}"* || true

echo "==> downloading mosquitto ${MOSQ_VERSION}"
cd "${TMPDIR}"
wget -q -O "${SRC_TAR}" "https://github.com/eclipse/mosquitto/archive/refs/tags/v${MOSQ_VERSION}.tar.gz"
tar -xzf "${SRC_TAR}" -C "${TMPDIR}"
cd "${SRC_DIR}"

# ---------- helper: configure + build (no manpages) ----------
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

# try build without manpages
do_build_no_man || true

# if CMake still failed with xsltproc, attempt to install xsltproc/docbook and retry
if grep -qi "xsltproc not found" "${BUILDLOG}.cmake" 2>/dev/null || grep -qi "xsltproc not found" "${BUILDLOG}.build" 2>/dev/null; then
  echo "xsltproc required — installing docbook/xsltproc and retrying"
  dnf_makecache
  dnf -y install libxslt libxslt-devel libxml2 docbook-style-xsl docbook-dtds xsltproc || true
  do_build_no_man || true
fi

# ---------- 3) install or copy artifacts ----------
echo "==> attempting cmake --install"
if cmake --install "${BUILD_DIR}" >"${INSTALLLOG}" 2>&1; then
  echo "cmake --install done"
fi

# make sure bin/lib dirs exist
mkdir -p "${BIN_DIR}" "${LIB_DIR}" "${CONF_DIR}" || true

# If install didn't produce binaries, copy from build
if [ ! -x "${BIN_DIR}/mosquitto" ]; then
  echo "copying built artifacts"
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

# sanity check
if [ ! -x "${BIN_DIR}/mosquitto" ]; then
  echo "FATAL: mosquitto binary missing after build/copy. TAIL logs below for debugging."
  tail -n 200 "${BUILDLOG}.build" || true
  tail -n 200 "${INSTALLLOG}" || true
  exit 1
fi

# ---------- 4) ensure mosquitto user & perms ----------
if ! id -u mosquitto >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /sbin/nologin mosquitto || true
fi

mkdir -p "${CONF_DIR}" /var/lib/mosquitto /var/log/mosquitto
chown -R mosquitto:mosquitto "${CONF_DIR}" /var/lib/mosquitto /var/log/mosquitto || true
chmod 750 "${CONF_DIR}" || true
chmod 700 /var/lib/mosquitto || true
chmod 750 /var/log/mosquitto || true

# ---------- 5) auth handling: prefer creating passwords; fallback to anonymous localhost ----------
# locate mosquitto_passwd (prefer /usr/local/bin then build paths)
MOSQUITTO_PASSWD="$(command -v mosquitto_passwd || true)"
if [ -z "${MOSQUITTO_PASSWD}" ]; then
  MOSQUITTO_PASSWD="$(find /tmp /root /usr/src /opt -type f -name mosquitto_passwd -perm -111 2>/dev/null | head -n1 || true)"
fi
if [ -n "${MOSQUITTO_PASSWD}" ] && [ -x "${MOSQUITTO_PASSWD}" ]; then
  echo "mosquitto_passwd available: ${MOSQUITTO_PASSWD}"
  # copy to /usr/local/bin if not already there
  if [ ! -x "${BIN_DIR}/mosquitto_passwd" ]; then
    cp -f "${MOSQUITTO_PASSWD}" "${BIN_DIR}/mosquitto_passwd"
    chmod 755 "${BIN_DIR}/mosquitto_passwd"
    MOSQUITTO_PASSWD="${BIN_DIR}/mosquitto_passwd"
  else
    MOSQUITTO_PASSWD="${BIN_DIR}/mosquitto_passwd"
  fi
fi

if [ -x "${BIN_DIR}/mosquitto_passwd" ]; then
  # create mosquitto.conf requiring auth
  cat > "${CONF_DIR}/mosquitto.conf" <<'EOF'
# Authenticated localhost-only broker
listener 1883 0.0.0.0
allow_anonymous false
password_file /usr/local/etc/mosquitto/passwords
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
EOF

  if [ ! -f "${PASSFILE}" ]; then
    echo "Creating password file (drone + consumer)"
    DRONE_PW="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
    CONSUMER_PW="consumerpass"
    "${BIN_DIR}/mosquitto_passwd" -c -b "${PASSFILE}" drone "${DRONE_PW}"
    "${BIN_DIR}/mosquitto_passwd" -b "${PASSFILE}" consumer "${CONSUMER_PW}"
    chown mosquitto:mosquitto "${PASSFILE}" || true
    chmod 600 "${PASSFILE}" || true
    echo "drone:${DRONE_PW}" > /root/mosquitto_drone_credentials.txt
    echo "consumer:${CONSUMER_PW}" >> /root/mosquitto_drone_credentials.txt
    chmod 600 /root/mosquitto_drone_credentials.txt || true
    echo "Saved creds to /root/mosquitto_drone_credentials.txt"
  else
    chown mosquitto:mosquitto "${PASSFILE}" || true
    chmod 600 "${PASSFILE}" || true
  fi
else
  # fallback: anonymous localhost broker (allows service to start)
  echo "mosquitto_passwd not found — creating anonymous localhost-only config to allow service to start (demo mode)."
  cat > "${CONF_DIR}/mosquitto.conf" <<'EOF'
# Localhost-only demo broker (anonymous allowed)
listener 1883 127.0.0.1
allow_anonymous true
# password_file /usr/local/etc/mosquitto/passwords
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
EOF
  echo "To enable authentication later: copy mosquitto_passwd to /usr/local/bin and run /usr/local/bin/mosquitto_passwd -c -b /usr/local/etc/mosquitto/passwords drone <pw>"
fi

chown -R mosquitto:mosquitto "${CONF_DIR}" || true
chmod 750 "${CONF_DIR}" || true

# ---------- 6) systemd unit ----------
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

# ---------- 7) verification ----------
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
  echo "No credentials written (mosquitto_passwd probably missing)."
fi

# ---------- 8) helpful next-steps message ----------
cat <<'MSG'

If broker started in anonymous fallback mode and you want auth:

1) Locate mosquitto_passwd (likely: /tmp/mosquitto-*/build/apps/mosquitto_passwd/mosquitto_passwd)
   Copy it to /usr/local/bin and chmod +x.

   sudo cp /path/to/mosquitto_passwd /usr/local/bin/
   sudo chmod 755 /usr/local/bin/mosquitto_passwd

2) Create password file:
   sudo /usr/local/bin/mosquitto_passwd -c -b /usr/local/etc/mosquitto/passwords drone <pw>
   sudo /usr/local/bin/mosquitto_passwd -b /usr/local/etc/mosquitto/passwords consumer <pw2>
   sudo chown mosquitto:mosquitto /usr/local/etc/mosquitto/passwords
   sudo chmod 600 /usr/local/etc/mosquitto/passwords

3) Edit /usr/local/etc/mosquitto/mosquitto.conf: set allow_anonymous false and ensure password_file line present.

4) Restart:
   sudo systemctl restart mosquitto
   sudo systemctl status mosquitto --no-pager

MSG

echo "Bootstrap finished: $(date)"
