#!/usr/bin/env python3
"""
run_pipeline.py

Supervisor wrapper that runs conversion -> encryption as a streaming pipeline:
convert(stdout) | encrypt(stdin)

Expects environment variables (can be set in /etc/drone-pub/env.conf or systemd
EnvironmentFile):
 - PYTHON_BIN (path to python, e.g. /opt/drone-pub/venv/bin/python)
 - CONVERT_SCRIPT (full path)
 - ENCRYPT_SCRIPT (full path)

Important: children are launched with -u (unbuffered) to avoid stdio buffering.
"""
from __future__ import annotations
import os
import shlex
import signal
import subprocess
import sys
import time

# load from env, with defaults
PYTHON_BIN = os.environ.get("PYTHON_BIN", sys.executable)
CONVERT_SCRIPT = os.environ.get("CONVERT_SCRIPT", "/opt/drone-pub/mav_to_mqtt.py")
ENCRYPT_SCRIPT = os.environ.get("ENCRYPT_SCRIPT", "/opt/drone-pub/mav_encrypt_publish.py")

# restart/backoff
BASE_DELAY = 1.0
MAX_DELAY = 30.0

# global state
terminate = False
proc_convert = None
proc_encrypt = None

def log(msg, *args):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"{ts} [pipeline] {msg % args}", flush=True)

def start_pipeline():
    """
    Start convert -> encrypt pipeline:
    p1 = python -u CONVERT_SCRIPT --stdout (stdout=PIPE)
    p2 = python -u ENCRYPT_SCRIPT --stdin  (stdin=p1.stdout)
    After starting p2, parent closes p1.stdout so EOF propagates to p2 when p1 exits.
    """
    global proc_convert, proc_encrypt
    if not os.path.isfile(CONVERT_SCRIPT):
        log("ERROR: convert script not found: %s", CONVERT_SCRIPT)
        return None, None
    if not os.path.isfile(ENCRYPT_SCRIPT):
        log("ERROR: encrypt script not found: %s", ENCRYPT_SCRIPT)
        return None, None

    # Start converter (unbuffered) with --stdout to emit base64-packed MAVLink lines
    cmd1 = [PYTHON_BIN, "-u", CONVERT_SCRIPT, "--stdout"]
    log("Starting convert: %s", " ".join(shlex.quote(x) for x in cmd1))
    proc_convert = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

    # Start encryptor reading from convert's stdout (--stdin)
    cmd2 = [PYTHON_BIN, "-u", ENCRYPT_SCRIPT, "--stdin"]
    log("Starting encrypt: %s", " ".join(shlex.quote(x) for x in cmd2))
    # IMPORTANT: pass proc_convert.stdout as stdin for the encryptor
    # Keep encryptor stdout/stderr as PIPE so supervisor can observe logs; adjust if journal deadlocks occur.
    proc_encrypt = subprocess.Popen(cmd2, stdin=proc_convert.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

    # Parent must close its reference to proc_convert.stdout so that EOF propagates to encrypt when convert exits.
    try:
        proc_convert.stdout.close()
    except Exception:
        pass

    return proc_convert, proc_encrypt

def stop_process(p, name, timeout=5.0):
    if p is None:
        return
    if p.poll() is not None:
        return
    try:
        log("Terminating %s (pid=%s)", name, p.pid)
        p.terminate()
    except Exception as e:
        log("Error terminating %s: %s", name, e)

    deadline = time.time() + timeout
    while time.time() < deadline:
        if p.poll() is not None:
            return
        time.sleep(0.1)

    # still alive -> kill
    try:
        log("Killing %s (pid=%s)", name, p.pid)
        p.kill()
    except Exception as e:
        log("Error killing %s: %s", name, e)

def terminate_all():
    global proc_convert, proc_encrypt
    log("terminate_all: stopping children")
    stop_process(proc_encrypt, "encrypt")
    stop_process(proc_convert, "convert")

def sigterm_handler(signum, frame):
    global terminate
    log("Received signal %s", signum)
    terminate = True
    terminate_all()

def supervise():
    global proc_convert, proc_encrypt, terminate
    delay = BASE_DELAY

    while not terminate:
        proc_convert, proc_encrypt = start_pipeline()

        # if start failed, backoff and retry
        if proc_convert is None or proc_encrypt is None:
            log("Pipeline start failed; retrying in %.1fs", delay)
            time.sleep(delay)
            delay = min(delay * 2, MAX_DELAY)
            continue

        log("Pipeline started: convert(pid=%s) -> encrypt(pid=%s)", proc_convert.pid, proc_encrypt.pid)
        # reset backoff on success
        delay = BASE_DELAY

        # Wait for either child to exit (monitor both)
        try:
            while not terminate:
                rc1 = proc_convert.poll()
                rc2 = proc_encrypt.poll()
                if rc1 is not None:
                    log("convert exited with rc=%s", rc1)
                    break
                if rc2 is not None:
                    log("encrypt exited with rc=%s", rc2)
                    break
                time.sleep(0.2)
        except KeyboardInterrupt:
            log("KeyboardInterrupt received")
            terminate = True

        # If terminating, break and cleanup
        if terminate:
            break

        # Child exited unexpectedly; terminate remaining and restart after backoff
        log("Pipeline broken; stopping remaining children and restarting in %.1fs", delay)
        terminate_all()
        time.sleep(delay)
        delay = min(delay * 2, MAX_DELAY)

    # cleanup before exit
    terminate_all()
    log("Supervisor exiting")

def main():
    # trap signals
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)
    log("Pipeline supervisor starting. PYTHON_BIN=%s CONVERT_SCRIPT=%s ENCRYPT_SCRIPT=%s", PYTHON_BIN, CONVERT_SCRIPT, ENCRYPT_SCRIPT)
    supervise()

if __name__ == "__main__":
    main()
