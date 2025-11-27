#!/usr/bin/env python3
# mav_encrypt_publish.py
# Updated: keyfile resolution, bytes/str fixes, clearer MQTT handling

import argparse
import base64
import logging
import os
import sys
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import paho.mqtt.client as mqtt

LOG = logging.getLogger("mav_encrypt_publish")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --------- helpers ----------
def parse_args():
    p = argparse.ArgumentParser(prog="mav_encrypt_publish", description="MAVLink to MQTT encrypt/publish")
    p.add_argument("--transport", default=os.environ.get("TRANSPORT", "udp:127.0.0.1:14550"),
                   help="pymavlink transport")
    p.add_argument("--keyfile", help="Path to 32-byte AEAD key")
    p.add_argument("--drone-id", default=os.environ.get("DRONE_ID", "DRONE01"))
    p.add_argument("--mqtt-host", default=os.environ.get("MQTT_HOST", "localhost"))
    p.add_argument("--mqtt-port", default=int(os.environ.get("MQTT_PORT", 1883)), type=int)
    p.add_argument("--mqtt-user", default=os.environ.get("MQTT_USER"))
    p.add_argument("--mqtt-pass-file", default=os.environ.get("MQTT_PASS_FILE"))
    p.add_argument("--topic", default=os.environ.get("TOPIC", "drone/{drone_id}/telemetry_enc"))
    p.add_argument("--qos", default=int(os.environ.get("QOS", 1)), type=int)
    p.add_argument("--stdin", action="store_true", help="Read base64 frames from stdin (pipe mode)")
    p.add_argument("--stdout", action="store_true", help="Also write plaintext or debug to stdout")
    return p.parse_args()

def resolve_keyfile(cli_keyfile=None):
    # order: CLI -> ENV KEYFILE -> /etc/drone-pub/drone_key.bin
    if cli_keyfile:
        return cli_keyfile
    env_k = os.environ.get("KEYFILE") or os.environ.get("KEY_FILE") or os.environ.get("DRONE_KEYFILE")
    if env_k:
        return env_k
    default = "/etc/drone-pub/drone_key.bin"
    return default

def check_keyfile(path):
    if not path:
        LOG.error("No keyfile path supplied")
        return False
    try:
        st = os.stat(path)
        if not (st.st_mode & 0o400):  # readable by owner / group
            LOG.warning("Keyfile %s exists but may not be readable by current user", path)
        return True
    except FileNotFoundError:
        LOG.error("Keyfile %s not found", path)
        return False
    except Exception as e:
        LOG.exception("Error accessing keyfile %s: %s", path, e)
        return False

def load_key(path):
    with open(path, "rb") as f:
        key = f.read()
    if not isinstance(key, (bytes, bytearray)):
        LOG.error("Key read from %s is not bytes", path)
        raise TypeError("Key not bytes")
    if len(key) != 32:
        LOG.error("Key length is %d bytes (expected 32)", len(key))
        raise ValueError("AEAD key must be 32 bytes")
    return bytes(key)

def read_passfile(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        LOG.warning("Unable to read mqtt pass file %s: %s", path, e)
        return None

# --------- MQTT wrapper ----------
class MQTTPublisher:
    def __init__(self, host, port, user=None, passfile=None, client_id=None, keepalive=60):
        self.host = host
        self.port = port
        self.user = user
        self.passfile = passfile
        self.client_id = client_id
        self.keepalive = keepalive
        self.client = mqtt.Client(client_id=self.client_id) if self.client_id else mqtt.Client()
        if self.user:
            pw = read_passfile(self.passfile)
            if pw is None:
                LOG.warning("mqtt user provided but password file empty or unreadable")
            self.client.username_pw_set(self.user, pw)
        # attach simple callbacks for logging
        self.client.on_connect = lambda cl, userdata, flags, rc: LOG.info("MQTT connected to %s:%d (rc=%s)", self.host, self.port, rc)
        self.client.on_disconnect = lambda cl, userdata, rc: LOG.info("MQTT disconnected (rc=%s)", rc)

    def connect(self, retries=3, retry_delay=2):
        for attempt in range(1, retries + 1):
            try:
                self.client.connect(self.host, self.port, keepalive=self.keepalive)
                # start loop in background thread to service network events (non-blocking)
                self.client.loop_start()
                return True
            except Exception as e:
                LOG.error("MQTT connect exception (attempt %d/%d): %s", attempt, retries, e)
                if attempt < retries:
                    time.sleep(retry_delay)
        return False

    def publish(self, topic, payload_str, qos=1):
        # payload_str must be a str (we encode it to bytes when calling paho)
        if not isinstance(payload_str, str):
            payload_str = str(payload_str)
        # Paho accepts bytes or str for payload; we'll pass str
        res = self.client.publish(topic, payload_str, qos=qos)
        return res

    def stop(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass

# --------- encryption ----------
def encrypt_frame(aead_key, plaintext_bytes):
    aead = ChaCha20Poly1305(aead_key)
    nonce = os.urandom(12)  # 12 bytes recommended for ChaCha20-Poly1305
    ct = aead.encrypt(nonce, plaintext_bytes, associated_data=None)  # returns bytes (ciphertext + tag)
    # final payload = nonce || ciphertext+tag
    return nonce + ct  # bytes

# --------- main ----------
def main():
    args = parse_args()

    # resolve & load key
    keyfile = resolve_keyfile(args.keyfile)
    LOG.info("Resolved keyfile: %s", keyfile)
    if not check_keyfile(keyfile):
        LOG.error("Keyfile check failed: %s", keyfile)
        sys.exit(2)
    try:
        aead_key = load_key(keyfile)
        LOG.info("Loaded %d-byte AEAD key from %s", len(aead_key), keyfile)
    except Exception as e:
        LOG.exception("Failed to load AEAD key: %s", e)
        sys.exit(3)

    # prepare mqtt
    topic = args.topic.format(drone_id=args.drone_id) if "{drone_id" in args.topic else args.topic
    publisher = MQTTPublisher(args.mqtt_host, args.mqtt_port, user=args.mqtt_user,
                             passfile=args.mqtt_pass_file, client_id=None)
    if not publisher.connect(retries=3, retry_delay=1):
        LOG.error("Unable to connect to MQTT broker %s:%d - ConnectionRefused or unreachable", args.mqtt_host, args.mqtt_port)
        # we continue so the daemon can try to publish later (or exit if desired)
        # choose to continue and attempt publishes (they will fail until connection resumes)
    LOG.info("Reading base64 frames from stdin and publishing encrypted payloads to %s (qos=%d)", topic, args.qos)

    seq = 0
    try:
        for raw in sys.stdin:
            seq += 1
            raw = raw.strip()
            if not raw:
                continue
            # if input already includes metadata (like "RAW_B64|..."), try to locate base64 chunk.
            # naive: take last pipe-separated field if there are pipes
            b64_part = raw.split("|")[-1].strip()
            try:
                frame = base64.b64decode(b64_part)
            except Exception as e:
                LOG.error("seq=%d: input not valid base64: %s", seq, e)
                continue

            try:
                encrypted = encrypt_frame(aead_key, frame)  # bytes
                encoded = base64.b64encode(encrypted).decode("ascii")  # str
                # publish - ensure topic is str
                res = publisher.publish(topic, encoded, qos=args.qos)
                LOG.info("Published seq=%d len=%d", seq, len(encoded))
                if args.stdout:
                    # print the encoded payload to stdout; keep it as str
                    print(encoded)
            except Exception as e:
                LOG.exception("Encrypt/publish error at seq=%d: %s", seq, e)
    except KeyboardInterrupt:
        LOG.info("Interrupted by user")
    finally:
        publisher.stop()

if __name__ == "__main__":
    main()

root@DESKTOP-5AL6U1P:/opt/drone-pub#



