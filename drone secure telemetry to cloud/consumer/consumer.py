#!/usr/bin/env python3
"""
consumer.py - Enhanced ECS/Lambda consumer for encrypted MAVLink telemetry

Receives encrypted messages from SQS (forwarded from IoT Core),
decrypts them, parses MAVLink data, and sends metrics to CloudWatch.
"""

import os
import sys
import time
import base64
import logging
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
LOG = logging.getLogger(__name__)

# Try to import pymavlink for proper parsing
try:
    from pymavlink import mavutil
    PYMAVLINK_AVAILABLE = True
    LOG.info("pymavlink is available - using full MAVLink parsing")
except ImportError:
    PYMAVLINK_AVAILABLE = False
    LOG.warning("pymavlink not available - will use basic parsing only")

# Environment configuration
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
POLL_WAIT = int(os.environ.get("SQS_WAIT", "10"))
VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY", "30"))
AEAD_KEY_B64 = os.environ.get("AEAD_KEY_B64")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "DronePipeline")
DRONE_ID = os.environ.get("DRONE_ID", "UNKNOWN")

# Validate required config
if not SQS_QUEUE_URL:
    LOG.error("SQS_QUEUE_URL env var is required")
    sys.exit(1)

# Initialize AWS clients
sqs = boto3.client("sqs", region_name=AWS_REGION)
cloudwatch = boto3.client("cloudwatch", region_name=AWS_REGION)


def get_encryption_key():
    """
    Retrieve the AEAD encryption key from environment or AWS Secrets Manager.
    """
    if AEAD_KEY_B64:
        try:
            key = base64.b64decode(AEAD_KEY_B64)
            if len(key) != 32:
                raise ValueError("AEAD key must be 32 bytes")
            LOG.info("Loaded encryption key from AEAD_KEY_B64 environment variable")
            return key
        except Exception as e:
            LOG.error("Invalid AEAD_KEY_B64: %s", e)
            raise
    
    # Try to load from Secrets Manager
    secret_name = os.environ.get("AEAD_KEY_SECRET_NAME")
    if secret_name:
        try:
            secrets = boto3.client("secretsmanager", region_name=AWS_REGION)
            response = secrets.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response["SecretString"])
            key_b64 = secret_data.get("AEAD_KEY_B64")
            if key_b64:
                key = base64.b64decode(key_b64)
                if len(key) == 32:
                    LOG.info("Loaded encryption key from Secrets Manager: %s", secret_name)
                    return key
        except Exception as e:
            LOG.warning("Failed to load key from Secrets Manager: %s", e)
    
    LOG.error("No valid AEAD key provided (set AEAD_KEY_B64 or AEAD_KEY_SECRET_NAME)")
    sys.exit(1)


# Initialize encryption
KEY = get_encryption_key()
AEAD = ChaCha20Poly1305(KEY)


def decrypt_payload(b64_ciphertext):
    """
    Decrypt a base64-encoded encrypted payload.
    Expected format: base64(nonce[12 bytes] + ciphertext + tag)
    """
    try:
        raw = base64.b64decode(b64_ciphertext)
        nonce = raw[:12]  # ChaCha20-Poly1305 uses 96-bit nonce
        ct_and_tag = raw[12:]
        plaintext = AEAD.decrypt(nonce, ct_and_tag, associated_data=None)
        return plaintext
    except Exception as e:
        LOG.exception("Decryption failed: %s", e)
        raise


def parse_mavlink_with_pymavlink(payload_bytes):
    """
    Parse MAVLink message using pymavlink library.
    Returns dict with extracted telemetry data.
    """
    try:
        # Create a MAVLink parser
        mav = mavutil.mavlink_connection('', source_system=255, dialect='common')
        
        # Parse the message
        mav.mav.parse_buffer(payload_bytes)
        
        # Try to extract message from the buffer
        msg = mav.recv_match(blocking=False)
        
        if not msg:
            LOG.warning("No MAVLink message parsed from payload")
            return None
        
        telemetry = {
            "timestamp": datetime.utcnow().isoformat(),
            "msg_type": msg.get_type(),
            "seq": getattr(msg, "_seq", None),
        }
        
        msg_type = msg.get_type()
        
        # Extract data based on message type
        if msg_type == "GLOBAL_POSITION_INT":
            telemetry.update({
                "latitude": msg.lat / 1e7,
                "longitude": msg.lon / 1e7,
                "altitude_msl": msg.alt / 1000.0,  # mm to meters
                "altitude_relative": msg.relative_alt / 1000.0,
                "velocity_x": msg.vx / 100.0,  # cm/s to m/s
                "velocity_y": msg.vy / 100.0,
                "velocity_z": msg.vz / 100.0,
                "heading": msg.hdg / 100.0,  # centidegrees to degrees
            })
        
        elif msg_type == "ATTITUDE":
            telemetry.update({
                "roll": msg.roll,
                "pitch": msg.pitch,
                "yaw": msg.yaw,
                "rollspeed": msg.rollspeed,
                "pitchspeed": msg.pitchspeed,
                "yawspeed": msg.yawspeed,
            })
        
        elif msg_type == "VFR_HUD":
            telemetry.update({
                "airspeed": msg.airspeed,
                "groundspeed": msg.groundspeed,
                "heading": msg.heading,
                "throttle": msg.throttle,
                "altitude": msg.alt,
                "climb_rate": msg.climb,
            })
        
        elif msg_type == "SYS_STATUS":
            telemetry.update({
                "voltage_battery": msg.voltage_battery / 1000.0,  # mV to V
                "current_battery": msg.current_battery / 100.0,  # cA to A
                "battery_remaining": msg.battery_remaining,
                "drop_rate_comm": msg.drop_rate_comm,
                "errors_comm": msg.errors_comm,
            })
        
        elif msg_type == "GPS_RAW_INT":
            telemetry.update({
                "gps_fix_type": msg.fix_type,
                "latitude": msg.lat / 1e7,
                "longitude": msg.lon / 1e7,
                "altitude": msg.alt / 1000.0,
                "satellites_visible": msg.satellites_visible,
                "eph": msg.eph,
                "epv": msg.epv,
            })
        
        elif msg_type == "HEARTBEAT":
            telemetry.update({
                "type": msg.type,
                "autopilot": msg.autopilot,
                "base_mode": msg.base_mode,
                "custom_mode": msg.custom_mode,
                "system_status": msg.system_status,
                "mavlink_version": msg.mavlink_version,
            })
        
        return telemetry
        
    except Exception as e:
        LOG.exception("Failed to parse MAVLink with pymavlink: %s", e)
        return None


def parse_mavlink_basic(payload_bytes):
    """
    Basic MAVLink parsing without pymavlink.
    Only extracts header information.
    """
    try:
        if len(payload_bytes) < 8:
            LOG.warning("Payload too short for MAVLink: %d bytes", len(payload_bytes))
            return None
        
        # MAVLink v1 or v2 detection
        magic = payload_bytes[0]
        
        if magic == 0xFE:  # MAVLink v1
            payload_len = payload_bytes[1]
            seq = payload_bytes[2]
            sys_id = payload_bytes[3]
            comp_id = payload_bytes[4]
            msg_id = payload_bytes[5]
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 1,
                "payload_length": payload_len,
                "seq": seq,
                "system_id": sys_id,
                "component_id": comp_id,
                "message_id": msg_id,
                "parsing": "basic",
            }
        
        elif magic == 0xFD:  # MAVLink v2
            payload_len = payload_bytes[1]
            incompat_flags = payload_bytes[2]
            compat_flags = payload_bytes[3]
            seq = payload_bytes[4]
            sys_id = payload_bytes[5]
            comp_id = payload_bytes[6]
            msg_id = int.from_bytes(payload_bytes[7:10], byteorder='little')
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 2,
                "payload_length": payload_len,
                "incompat_flags": incompat_flags,
                "compat_flags": compat_flags,
                "seq": seq,
                "system_id": sys_id,
                "component_id": comp_id,
                "message_id": msg_id,
                "parsing": "basic",
            }
        
        else:
            LOG.warning("Unknown MAVLink magic byte: 0x%02X", magic)
            return None
            
    except Exception as e:
        LOG.exception("Failed to parse MAVLink (basic): %s", e)
        return None


def send_cloudwatch_metrics(telemetry, drone_id=DRONE_ID):
    """
    Send extracted telemetry as CloudWatch metrics.
    """
    try:
        metric_data = []
        timestamp = datetime.utcnow()
        
        dimensions = [
            {"Name": "DroneId", "Value": drone_id},
            {"Name": "MessageType", "Value": telemetry.get("msg_type", "UNKNOWN")},
        ]
        
        # Message count
        metric_data.append({
            "MetricName": "MessageCount",
            "Value": 1,
            "Unit": "Count",
            "Timestamp": timestamp,
            "Dimensions": dimensions,
        })
        
        # Battery metrics
        if "battery_remaining" in telemetry:
            metric_data.append({
                "MetricName": "BatteryPercent",
                "Value": telemetry["battery_remaining"],
                "Unit": "Percent",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        if "voltage_battery" in telemetry:
            metric_data.append({
                "MetricName": "BatteryVoltage",
                "Value": telemetry["voltage_battery"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        # Altitude metrics
        if "altitude_msl" in telemetry:
            metric_data.append({
                "MetricName": "AltitudeMSL",
                "Value": telemetry["altitude_msl"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        if "altitude_relative" in telemetry:
            metric_data.append({
                "MetricName": "AltitudeRelative",
                "Value": telemetry["altitude_relative"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        # Speed metrics
        if "groundspeed" in telemetry:
            metric_data.append({
                "MetricName": "GroundSpeed",
                "Value": telemetry["groundspeed"],
                "Unit": "None",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        # GPS metrics
        if "satellites_visible" in telemetry:
            metric_data.append({
                "MetricName": "GPSSatellites",
                "Value": telemetry["satellites_visible"],
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": dimensions,
            })
        
        # Send metrics in batches (CloudWatch limit: 20 per request)
        for i in range(0, len(metric_data), 20):
            batch = metric_data[i:i+20]
            cloudwatch.put_metric_data(
                Namespace=CLOUDWATCH_NAMESPACE,
                MetricData=batch
            )
        
        LOG.info("Sent %d metrics to CloudWatch", len(metric_data))
        
    except Exception as e:
        LOG.exception("Failed to send CloudWatch metrics: %s", e)


def process_message(msg):
    """
    Process a single SQS message: decrypt, parse, log, and send metrics.
    Returns True if successful, False otherwise.
    """
    body = msg.get("Body")
    receipt = msg.get("ReceiptHandle")
    
    if not body:
        LOG.warning("Received message with empty body")
        return False
    
    try:
        # Try to parse as JSON (IoT Core might wrap it)
        try:
            body_json = json.loads(body)
            # If body is JSON, extract the actual payload
            if isinstance(body_json, dict):
                body = body_json.get("data") or body_json.get("payload") or body
        except json.JSONDecodeError:
            pass  # Body is already the raw encrypted payload
        
        # Decrypt
        plaintext = decrypt_payload(body)
        LOG.info("Decrypted payload: %d bytes", len(plaintext))
        LOG.debug("Plaintext (hex, first 200 chars): %s", plaintext.hex()[:200])
        
        # Parse MAVLink
        if PYMAVLINK_AVAILABLE:
            telemetry = parse_mavlink_with_pymavlink(plaintext)
        else:
            telemetry = parse_mavlink_basic(plaintext)
        
        if telemetry:
            LOG.info("Parsed telemetry: %s", json.dumps(telemetry, indent=2))
            
            # Send to CloudWatch Metrics
            send_cloudwatch_metrics(telemetry)
            
            # TODO: Store in Timestream / OpenSearch / S3
            # store_in_timestream(telemetry)
            # store_in_s3(telemetry)
        else:
            LOG.warning("Failed to parse MAVLink message")
        
        return True
        
    except Exception as e:
        LOG.exception("Failed to process message: %s", e)
        
        # Send error metric
        try:
            cloudwatch.put_metric_data(
                Namespace=CLOUDWATCH_NAMESPACE,
                MetricData=[{
                    "MetricName": "DecryptErrors",
                    "Value": 1,
                    "Unit": "Count",
                    "Timestamp": datetime.utcnow(),
                    "Dimensions": [{"Name": "DroneId", "Value": DRONE_ID}],
                }]
            )
        except:
            pass
        
        return False


def main():
    """
    Main consumer loop: poll SQS, process messages, delete on success.
    """
    LOG.info("=" * 60)
    LOG.info("Starting Drone Telemetry Consumer")
    LOG.info("=" * 60)
    LOG.info("SQS Queue: %s", SQS_QUEUE_URL)
    LOG.info("AWS Region: %s", AWS_REGION)
    LOG.info("CloudWatch Namespace: %s", CLOUDWATCH_NAMESPACE)
    LOG.info("Drone ID: %s", DRONE_ID)
    LOG.info("PyMAVLink Available: %s", PYMAVLINK_AVAILABLE)
    LOG.info("=" * 60)
    
    message_count = 0
    
    while True:
        try:
            # Long-poll SQS
            response = sqs.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=POLL_WAIT,
                VisibilityTimeout=VISIBILITY_TIMEOUT,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
            
            messages = response.get("Messages", [])
            
            if not messages:
                continue
            
            for message in messages:
                message_count += 1
                LOG.info("Processing message #%d (MessageId: %s)", 
                        message_count, message.get("MessageId"))
                
                if process_message(message):
                    # Delete message on success
                    sqs.delete_message(
                        QueueUrl=SQS_QUEUE_URL,
                        ReceiptHandle=message["ReceiptHandle"]
                    )
                    LOG.info("Message processed and deleted successfully")
                else:
                    LOG.warning("Processing failed; message will remain in queue "
                              "(visibility timeout will expire)")
        
        except ClientError as e:
            LOG.exception("AWS client error: %s", e)
            time.sleep(5)
        
        except KeyboardInterrupt:
            LOG.info("Shutting down gracefully...")
            break
        
        except Exception as e:
            LOG.exception("Unexpected error: %s", e)
            time.sleep(2)
    
    LOG.info("Consumer stopped. Processed %d messages total.", message_count)


if __name__ == "__main__":
    main()