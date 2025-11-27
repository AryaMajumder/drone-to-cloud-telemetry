#!/usr/bin/env python3
"""
mav_to_mqtt.py

MAVLink -> (optionally MQTT) bridge.

Modes:
 - Default: publish JSON telemetry to MQTT (existing behavior).
 - Pipe mode: `--stdout` writes base64(packed_mavlink) one line per message to stdout (unbuffered).
   This is intended to feed into the encryptor as: converter.stdout | encryptor.stdin

Requirements:
    pip install paho-mqtt pymavlink
"""
from __future__ import annotations
import argparse
import base64
import json
import time
import sys
import threading
from queue import Queue, Empty

import paho.mqtt.client as mqtt
from pymavlink import mavutil

DEFAULT_MAV_URI = "udp:127.0.0.1:14550"
DEFAULT_MQTT_HOST = "localhost"
DEFAULT_MQTT_PORT = 1883
DEFAULT_TOPIC = "drone/telemetry"
DEFAULT_RATE = 5.0  # Hz

# ---------------- helpers ----------------
def build_telemetry_from_msg(msg, seq):
    t = {"seq": seq, "timestamp": time.time()}
    mt = msg.get_type()
    if mt == "GLOBAL_POSITION_INT":
        try:
            t.update({
                "lat": msg.lat / 1e7,
                "lon": msg.lon / 1e7,
                "alt": msg.alt / 1000.0,
                "relative_alt": getattr(msg, "relative_alt", None) / 1000.0 if getattr(msg, "relative_alt", None) is not None else None,
                "vx": getattr(msg, "vx", None),
                "vy": getattr(msg, "vy", None),
                "vz": getattr(msg, "vz", None),
                "hdg": getattr(msg, "hdg", None) / 100.0 if getattr(msg, "hdg", None) is not None else None
            })
        except Exception:
            return None
    elif mt == "VFR_HUD":
        try:
            t.update({
                "velocity": getattr(msg, "vel", None),
                "alt": getattr(msg, "alt", None),
                "airspeed": getattr(msg, "airspeed", None),
                "groundspeed": getattr(msg, "groundspeed", None),
                "throttle": getattr(msg, "throttle", None)
            })
        except Exception:
            return None
    elif mt == "GPS_RAW_INT":
        try:
            t.update({
                "lat": msg.lat / 1e7,
                "lon": msg.lon / 1e7,
                "alt": msg.alt / 1000.0,
                "eph": getattr(msg, "eph", None),
                "epv": getattr(msg, "epv", None),
            })
        except Exception:
            return None
    else:
        return None
    return {k: v for k, v in t.items() if v is not None}

# ---------------- MQTT helper ----------------
class MQTTClient:
    def __init__(self, host, port, username=None, password=None, client_id="mav_to_mqtt"):
        self.client = mqtt.Client(client_id=client_id)
        if username:
            self.client.username_pw_set(username, password)
        self._connected = threading.Event()
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.host = host
        self.port = port

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("[mqtt] connected", flush=True)
            self._connected.set()
        else:
            print(f"[mqtt] connect failed rc={rc}", flush=True)

    def _on_disconnect(self, client, userdata, rc):
        print("[mqtt] disconnected", flush=True)
        self._connected.clear()

    def start(self):
        try:
            self.client.connect(self.host, self.port, keepalive=60)
        except Exception as e:
            print(f"[mqtt] connect failed: {e}", file=sys.stderr, flush=True)
        self.client.loop_start()

    def stop(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

    def publish(self, topic, payload, qos=1):
        try:
            self.client.publish(topic, payload, qos=qos)
        except Exception as e:
            print(f"[mqtt] publish exception: {e}", file=sys.stderr, flush=True)

# ---------------- main bridge ----------------
def bridge_loop(mav_uri, mqtt_cfg, topic, rate_hz, stdout_mode=False, queue_size=200):
    print(f"[mav] connecting to {mav_uri} ...", flush=True)
    mav = mavutil.mavlink_connection(mav_uri, autoreconnect=True, source_system=255)
    try:
        hb = mav.wait_heartbeat(timeout=5)
        if hb:
            print("[mav] heartbeat received", flush=True)
        else:
            print("[mav] no heartbeat yet", flush=True)
    except Exception as e:
        print(f"[mav] heartbeat wait error: {e}", file=sys.stderr, flush=True)

    mqttc = None
    if not stdout_mode:
        mqttc = MQTTClient(**mqtt_cfg)
        mqttc.start()

    seq = 0
    last_pub = 0.0
    publish_interval = 1.0 / max(0.1, rate_hz)

    out_queue = Queue(maxsize=queue_size)

    def reader():
        nonlocal seq
        while True:
            try:
                msg = mav.recv_match(blocking=True, timeout=2)
                if msg is None:
                    continue
                seq += 1
                # Prefer raw packed MAVLink to preserve fidelity
                raw = None
                try:
                    raw = msg.pack(mav.mav)
                except Exception:
                    # fallback to JSON telemetry
                    telemetry = build_telemetry_from_msg(msg, seq)
                    if telemetry:
                        out_queue.put_nowait(("json", telemetry, msg.get_type(), seq))
                        continue

                if raw:
                    b64 = base64.b64encode(raw).decode("ascii")
                    out_queue.put_nowait(("raw_b64", b64, msg.get_type(), seq))
            except Exception as e:
                print(f"[mav reader] error: {e}", file=sys.stderr, flush=True)
                time.sleep(1)

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    print("[bridge] entering publish loop (stdout_mode=%s)" % stdout_mode, flush=True)
    try:
        while True:
            try:
                kind, data, msg_type, seqn = out_queue.get(timeout=1.0)
            except Empty:
                time.sleep(0.01)
                continue

            now = time.time()
            if now - last_pub < publish_interval:
                # skip to keep latency low
                continue

            if stdout_mode:
                # emit a compact line: prefix to indicate type
                if kind == "raw_b64":
                    line = f"RAW_B64|{seqn}|{msg_type}|{data}"
                else:
                    line = f"JSON|{seqn}|{msg_type}|{json.dumps(data, separators=(',', ':'))}"
                # write unbuffered
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            else:
                # publish to mqtt topic
                if kind == "raw_b64":
                    payload = json.dumps({"type": "raw_b64", "seq": seqn, "msg_type": msg_type, "data": data})
                else:
                    payload = json.dumps({"type": "json", "seq": seqn, "msg_type": msg_type, "data": data})
                mqttc.publish(topic, payload)
                print(f"[bridge] published seq={seqn} type={msg_type}", flush=True)
            last_pub = now

    except KeyboardInterrupt:
        print("[bridge] interrupted", flush=True)
    finally:
        if mqttc:
            mqttc.stop()
        print("[bridge] stopped", flush=True)

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(prog="mav_to_mqtt", description="MAVLink -> MQTT/pipe bridge")
    p.add_argument("--mav", default=DEFAULT_MAV_URI)
    p.add_argument("--mqtt-host", default=DEFAULT_MQTT_HOST)
    p.add_argument("--mqtt-port", default=DEFAULT_MQTT_PORT, type=int)
    p.add_argument("--topic", default=DEFAULT_TOPIC)
    p.add_argument("--rate", default=DEFAULT_RATE, type=float)
    p.add_argument("--stdout", action="store_true", help="Write base64-packed MAVLink lines to stdout instead of publishing to MQTT")
    p.add_argument("--queue-size", default=200, type=int)
    return p.parse_args()

def main():
    args = parse_args()
    mqtt_cfg = {"host": args.mqtt_host, "port": args.mqtt_port, "username": None, "password": None}
    bridge_loop(args.mav, mqtt_cfg, args.topic, args.rate, stdout_mode=args.stdout, queue_size=args.queue_size)

if __name__ == "__main__":
    main()
