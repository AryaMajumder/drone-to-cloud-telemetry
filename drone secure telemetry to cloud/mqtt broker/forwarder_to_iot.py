#!/usr/bin/env python3
"""
Forward messages from a local MQTT broker to AWS IoT Core (iot-data publish).
No X.509 certs needed — uses IAM credentials (instance profile or env creds).
"""

import argparse
import logging
import os
import sys
import time
import boto3
import botocore
import json
import threading
from paho.mqtt import client as mqtt

LOG = logging.getLogger("forwarder")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s [%(levelname)s] %(message)s")

def get_iot_data_client(region_name=None):
    """
    Create an iot-data client by first calling iot.describe_endpoint.
    This finds your correct IoT data endpoint (ATS) for publish calls.
    """
    sess = boto3.Session(region_name=region_name)
    iot = sess.client("iot")
    try:
        resp = iot.describe_endpoint(endpointType="iot:Data-ATS")
        endpoint = resp.get("endpointAddress")
        if not endpoint:
            raise RuntimeError("No iot data endpoint returned")
        endpoint_url = "https://" + endpoint
        LOG.info("Using IoT data endpoint: %s", endpoint)
        iot_data = sess.client("iot-data", endpoint_url=endpoint_url)
        return iot_data
    except botocore.exceptions.BotoCoreError as e:
        LOG.exception("Error creating iot-data client: %s", e)
        raise

class Forwarder:
    def __init__(self, mqtt_host, mqtt_port, aws_region, aws_topic_template, mqtt_user=None, mqtt_pass=None, qos=1):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.qos = qos
        self.aws_region = aws_region
        self.aws_topic_template = aws_topic_template
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass
        self._stop = threading.Event()
        self.iot_data = None
        self.mqtt_client = None

    def start(self):
        self.iot_data = get_iot_data_client(region_name=self.aws_region)
        self._start_mqtt()

    def _start_mqtt(self):
        self.mqtt_client = mqtt.Client()
        if self.mqtt_user:
            self.mqtt_client.username_pw_set(self.mqtt_user, password=self.mqtt_pass)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_disconnect = self.on_disconnect

        while not self._stop.is_set():
            try:
                LOG.info("Connecting to local broker %s:%s", self.mqtt_host, self.mqtt_port)
                self.mqtt_client.connect(self.mqtt_host, self.mqtt_port, keepalive=60)
                self.mqtt_client.loop_forever()
            except Exception as e:
                LOG.exception("MQTT connection error, retrying in 5s: %s", e)
                time.sleep(5)

    def on_connect(self, client, userdata, flags, rc):
        LOG.info("Connected to local broker (rc=%s). Subscribing to local topics.", rc)
        # subscribe wildcard to your drone topic(s) - adjust as required
        client.subscribe("drone/+/telemetry_enc", qos=1)

    def on_disconnect(self, client, userdata, rc):
        LOG.warning("Disconnected from local broker (rc=%s).", rc)

    def on_message(self, client, userdata, msg):
        try:
            # payload is bytes — forward as-is
            payload = msg.payload
            # Map local topic => IoT topic (or keep same)
            # Example: local 'drone/DRONE01/telemetry_enc' -> AWS 'drone/DRONE01/telemetry_enc'
            aws_topic = msg.topic  # or self.aws_topic_template.format(drone_id=...)
            LOG.debug("Forwarding message topic=%s len=%d", aws_topic, len(payload))

            # boto3 expects bytes for payload
            self.iot_data.publish(topic=aws_topic, qos=self.qos, payload=payload)
            LOG.info("Published to IoT: %s (len=%d)", aws_topic, len(payload))
        except Exception as e:
            LOG.exception("Error forwarding message: %s", e)

    def stop(self):
        self._stop.set()
        if self.mqtt_client:
            try:
                self.mqtt_client.disconnect()
            except Exception:
                pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mqtt-host", default=os.environ.get("BROKER_HOST", "localhost"))
    p.add_argument("--mqtt-port", type=int, default=int(os.environ.get("BROKER_PORT", 1883)))
    p.add_argument("--aws-region", default=os.environ.get("AWS_REGION", "us-east-1"))
    p.add_argument("--aws-topic-template", default=os.environ.get("AWS_TOPIC_TEMPLATE", "drone/{drone_id}/telemetry_enc"))
    p.add_argument("--mqtt-user", default=os.environ.get("MQTT_USER"))
    p.add_argument("--mqtt-pass", default=os.environ.get("MQTT_PASS"))
    p.add_argument("--qos", type=int, default=int(os.environ.get("QOS", 1)))
    args = p.parse_args()

    fwd = Forwarder(args.mqtt_host, args.mqtt_port, args.aws_region, args.aws_topic_template, mqtt_user=args.mqtt_user, mqtt_pass=args.mqtt_pass, qos=args.qos)
    try:
        fwd.start()
    except KeyboardInterrupt:
        LOG.info("Interrupted, stopping")
    finally:
        fwd.stop()

if __name__ == "__main__":
    main()
