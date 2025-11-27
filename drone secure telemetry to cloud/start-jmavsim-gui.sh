#!/usr/bin/env bash
# start-jmavsim-fixed.sh
# Minimal robust jMAVSim launcher:
#  - auto-detects DISPLAY for WSL (uses /etc/resolv.conf nameserver)
#  - prefers launching via classpath (me.drton.jmavsim.Simulator)
#  - falls back to jmavsim_run.jar or jmavsim.jar with -jar
#  - uses Java 17 module flags (keeps compatibility)
#  - logs to ~/jmavsim_run.txt and prints tail on success/failure
set -euo pipefail

# Config (override with env vars if needed)
PX4_ROOT="${PX4_ROOT:-${HOME}/src/PX4-Autopilot}"
JMAVSIM_SUBPATH="Tools/simulation/jmavsim/jMAVSim"
JMAVSIM_DIR="${PX4_ROOT}/${JMAVSIM_SUBPATH}"
LOG="${JMAVSIM_LOG:-${HOME}/jmavsim_run.txt}"
SIM_PORT="${SIM_PORT:-14560}"
RATE="${RATE:-100}"
JAVA="${JAVA:-java}"

# tiny helper
die(){ echo "ERROR: $*" >&2; exit 1; }

echo "=== jMAVSim launcher (fixed) ==="
echo "PX4_ROOT = ${PX4_ROOT}"
echo "jmavsim dir = ${JMAVSIM_DIR}"
echo "log = ${LOG}"
echo

# 1) DISPLAY detection (WSL->Windows)
NS=$(grep -m1 nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)
if [ -z "$NS" ]; then
  echo "WARN: Could not auto-detect Windows host IP from /etc/resolv.conf."
  echo "If GUI doesn't appear, set DISPLAY manually: export DISPLAY=<win_ip>:0.0"
else
  export DISPLAY="${NS}:0.0"
  echo "DISPLAY set to ${DISPLAY}"
fi

# 2) cd to jmavsim dir
if [ ! -d "${JMAVSIM_DIR}" ]; then
  die "jMAVSim directory not found at ${JMAVSIM_DIR}. Clone PX4 repo or set PX4_ROOT."
fi
cd "${JMAVSIM_DIR}"

# 3) clear old log
: > "${LOG}"

# 4) Try to find compiled classes (Simulator.class) and construct classpath
CP=""
# Common locations (case sensitive)
CLASS_ROOT=$(find . -type f -path './out/production/*/me/drton/jmavsim/Simulator.class' -printf '%h\n' 2>/dev/null | head -n1 || true)

if [ -n "${CLASS_ROOT}" ]; then
  # class root is like ./out/production/jMAVSim/me/drton/jmavsim -> we want cp = ./out/production/jMAVSim
  # strip trailing /me/drton/jmavsim
  CP_ROOT="${CLASS_ROOT%/me/drton/jmavsim}"
  CP="${CP_ROOT}"
  # include libs
  if [ -d "lib" ]; then
    CP="${CP}:lib/*"
  fi
  if [ -d "jMAVlib/lib" ]; then
    CP="${CP}:jMAVlib/lib/*"
  fi
  echo "Found compiled classes at: ${CP_ROOT}"
  echo "Constructed classpath: ${CP}"
fi

# 5) Try to locate runnable jars as fallback
JAR_RUN=$(find . -maxdepth 4 -type f \( -iname 'jmavsim_run.jar' -o -iname '*run*.jar' -o -iname 'jmavsim.jar' \) -print -quit || true)
if [ -n "${JAR_RUN}" ]; then
  echo "Found candidate jar: ${JAR_RUN}"
fi

# 6) prepare java flags (Java >=9 module exports needed for j3d/jogl with Java 17)
JAVA_FLAGS=(--add-exports=java.desktop/sun.awt=ALL-UNNAMED --add-opens=java.desktop/sun.awt=ALL-UNNAMED)

launch_cmd=""
# 7) Prefer classpath launch if we found classes
if [ -n "${CP}" ]; then
  echo "Attempting classpath launch (preferred)..."
  launch_cmd=( "${JAVA}" "${JAVA_FLAGS[@]}" -cp "${CP}" me.drton.jmavsim.Simulator -udp "${SIM_PORT}" -r "${RATE}" -gui -automag )
else
  # if no classes found but there's a run jar, use -jar
  if [ -n "${JAR_RUN}" ]; then
    echo "No compiled classes found; will try running jar: ${JAR_RUN}"
    launch_cmd=( "${JAVA}" "${JAVA_FLAGS[@]}" -jar "${JAR_RUN}" -udp "${SIM_PORT}" -r "${RATE}" -gui -automag )
  else
    die "No classes or runnable jar found. Build jMAVSim (ant/gradle) first."
  fi
fi

# 8) Kill previous jmavsim java processes (safe)
pkill -f 'me.drton.jmavsim.Simulator' 2>/dev/null || true
pkill -f 'jmavsim_run.jar' 2>/dev/null || true
sleep 0.5

# 9) Launch (background) and capture PID
echo "Running: ${launch_cmd[*]}"
env DISPLAY="${DISPLAY:-}" "${launch_cmd[@]}" > "${LOG}" 2>&1 &
JMAV_PID=$!
sleep 1

# 10) Check process & show tail
if ps -p "${JMAV_PID}" > /dev/null 2>&1; then
  echo "jMAVSim launched (pid ${JMAV_PID}). Log -> ${LOG}"
  echo "Tail of log (last 120 lines):"
  sleep 0.3
  tail -n 120 "${LOG}" || true
  echo
  echo "If you don't see a GUI: check VcXsrv is running on Windows, DISPLAY value, and firewall."
else
  echo "Launch failed (process not alive). Showing log (${LOG}):"
  tail -n 200 "${LOG}" || true
  # also try jar fallback if we attempted classpath
  if [ -n "${CP}" ] && [ -n "${JAR_RUN}" ]; then
    echo
    echo "Attempting fallback: run jar ${JAR_RUN} with java -jar ..."
    env DISPLAY="${DISPLAY:-}" "${JAVA}" "${JAVA_FLAGS[@]}" -jar "${JAR_RUN}" -udp "${SIM_PORT}" -r "${RATE}" -gui -automag > "${LOG}" 2>&1 &
    PID2=$!
    sleep 1
    if ps -p "${PID2}" > /dev/null 2>&1; then
      echo "Fallback jar started (pid ${PID2}). Tail of log:"
      tail -n 120 "${LOG}" || true
      exit 0
    else
      echo "Fallback also failed. Tail of log:"
      tail -n 200 "${LOG}" || true
      die "Both classpath and jar launch failed. See log for details."
    fi
  else
    die "Launcher failed and no fallback jar available. See ${LOG}."
  fi
fi

echo "Done."
