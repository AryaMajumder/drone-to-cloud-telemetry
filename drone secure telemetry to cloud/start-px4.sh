#!/usr/bin/env bash
# start-px4.sh — starts PX4 SITL. Default: run PX4 binary in FOREGROUND (pxh>).
# Usage:
#   ./start-px4.sh               # runs PX4 in foreground (default)
#   BACKGROUND=1 ./start-px4.sh  # run build+px4 in background (old behavior)
# Optional env:
#   CLOUD_IP and CLOUD_PORT to forward telemetry (UDP).
#   DISABLE_ARMING_CHECKS=1 (note: script only prints a hint; update params interactively via pxh>).
set -euo pipefail

# -------------------
# Configurable bits
PX4_ROOT="${HOME}/src/PX4-Autopilot"
PX4_BUILD_LOG="${HOME}/px4_build_output.txt"
PX4_BIN="${PX4_ROOT}/build/px4_sitl_default/bin/px4"
SIM_PORT=14560    # PX4 <-> simulator UDP port
GCS_PORT=14550    # PX4 telemetry port (for GCS forwarding)
WAIT_TIMEOUT=120  # seconds to wait for PX4 / port binds
# -------------------

echo ">>> START SCRIPT: $(date)"
echo "PX4 root: ${PX4_ROOT}"

# 1) Optional: detect & export DISPLAY (harmless if jmavsim not used)
NS=$(grep -m1 nameserver /etc/resolv.conf | awk '{print $2}' || true)
if [ -n "$NS" ]; then
  export DISPLAY="${NS}:0.0"
  echo "DISPLAY set to ${DISPLAY} (no-op for PX4-only run)"
else
  echo "DISPLAY not auto-detected. This is fine for PX4-only runs."
fi

# 2) Kill previous PX4 processes (safe)
echo "Stopping previous PX4 processes (if any)..."
pkill -f "${PX4_BIN}" 2>/dev/null || true
sleep 1

# 3) Build PX4 (only build here; running handled below)
cd "$PX4_ROOT" || { echo "PX4 root not found at $PX4_ROOT"; exit 1; }

echo "Starting build: make px4_sitl_default none (logs -> ${PX4_BUILD_LOG})"
# run build and tee logs so you can inspect if something fails
# do NOT set -e on the build pipeline failure so we can print helpful message
if ! make px4_sitl_default none 2>&1 | tee "${PX4_BUILD_LOG}"; then
  echo "ERROR: build failed. Inspect ${PX4_BUILD_LOG}."
  exit 1
fi

# 4) Decide foreground or background run
# Default behaviour: run PX4 binary in foreground (gives pxh>)
if [ "${BACKGROUND:-0}" = "1" ]; then
  echo "Starting PX4 in BACKGROUND (log -> ${PX4_BUILD_LOG})."
  nohup make px4_sitl_default none > "${PX4_BUILD_LOG}" 2>&1 &
  echo "PX4 background start attempted."
  # Wait for the px4 binary/process to show up briefly
  count=0
  while [ $count -lt $WAIT_TIMEOUT ]; do
    if pgrep -f "${PX4_BIN}" >/dev/null 2>&1; then
      echo "PX4 started (background)."
      break
    fi
    sleep 1
    ((count++))
  done
  if [ $count -ge $WAIT_TIMEOUT ]; then
    echo "WARNING: PX4 background did not start within ${WAIT_TIMEOUT}s. Check ${PX4_BUILD_LOG}."
  fi
  echo "---- STATUS ----"
  ps aux | grep -E 'px4' | grep -v grep || true
  exit 0
fi

# 5) Foreground run: ensure binary exists, then exec it so we get pxh>
if [ ! -x "${PX4_BIN}" ]; then
  echo "ERROR: px4 binary not found at ${PX4_BIN} or not executable."
  echo "Check ${PX4_BUILD_LOG} for build result."
  exit 1
fi

echo "Launching PX4 binary in FOREGROUND. You will get pxh> prompt in this terminal."
echo "If you need to background it later, use Ctrl+Z/bg or run in another terminal."
# Exec so px4 replaces the shell process (cleaner; Ctrl-C will stop PX4)
exec "${PX4_BIN}"
