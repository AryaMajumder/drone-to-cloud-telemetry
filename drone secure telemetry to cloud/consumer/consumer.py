#!/usr/bin/env python3
"""
consumer.py - Auto-installs dependencies and parses MAVLink without serial issues

This version:
1. Auto-installs pymavlink and pyserial if missing
2. Uses direct dialect import (avoids serial connection dependency)
3. Full MAVLink parsing with all telemetry extraction
"""

import os
import sys
import time
import base64
import logging
import json
import subprocess
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

# ============================================================================
# AUTO-INSTALL PYMAVLINK AND PYSERIAL
# ============================================================================
PYMAVLINK_AVAILABLE = False

def install_dependencies():
    """Install pymavlink and pyserial if missing."""
    try:
        LOG.info("Checking for pymavlink...")
        import pymavlink
        LOG.info("✓ pymavlink already installed")
        return True
    except ImportError:
        LOG.warning("pymavlink not found - attempting auto-install...")
        
        try:
            # Install both pymavlink and pyserial
            LOG.info("Running: pip install pymavlink pyserial --break-system-packages")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "pymavlink", "pyserial", "--break-system-packages"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                LOG.info("✓ pymavlink and pyserial installed successfully")
                return True
            else:
                LOG.error("Failed to install: %s", result.stderr)
                return False
                
        except subprocess.TimeoutExpired:
            LOG.error("Installation timed out")
            return False
        except Exception as e:
            LOG.error("Error during auto-install: %s", e)
            return False

# Try to install dependencies first
if install_dependencies():
    try:
        # Import dialect directly to avoid serial dependency
        from pymavlink.dialects.v20 import common as mavlink2
        PYMAVLINK_AVAILABLE = True
        MAVLINK_DIALECT = mavlink2
        LOG.info("✓ Using MAVLink v2 dialect")
    except ImportError:
        try:
            from pymavlink.dialects.v10 import common as mavlink1
            PYMAVLINK_AVAILABLE = True
            MAVLINK_DIALECT = mavlink1
            LOG.info("✓ Using MAVLink v1 dialect")
        except ImportError:
            LOG.warning("Could not import MAVLink dialects")
            PYMAVLINK_AVAILABLE = False
else:
    LOG.warning("Will use basic parsing only (no pymavlink)")

# Environment configuration
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
POLL_WAIT = int(os.environ.get("SQS_WAIT", "10"))
VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY", "30"))
AEAD_KEY_B64 = os.environ.get("AEAD_KEY_B64")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "DronePipeline")
DRONE_ID = os.environ.get("DRONE_ID", "UNKNOWN")

if not SQS_QUEUE_URL:
    LOG.error("SQS_QUEUE_URL env var is required")
    sys.exit(1)

# Initialize AWS clients
sqs = boto3.client("sqs", region_name=AWS_REGION)
cloudwatch = boto3.client("cloudwatch", region_name=AWS_REGION)


def get_encryption_key():
    """Retrieve the AEAD encryption key."""
    if AEAD_KEY_B64:
        try:
            key = base64.b64decode(AEAD_KEY_B64)
            if len(key) != 32:
                raise ValueError("AEAD key must be 32 bytes")
            LOG.info("Loaded encryption key from AEAD_KEY_B64")
            return key
        except Exception as e:
            LOG.error("Invalid AEAD_KEY_B64: %s", e)
            raise
    
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
                    LOG.info("Loaded encryption key from Secrets Manager")
                    return key
        except Exception as e:
            LOG.warning("Failed to load key from Secrets Manager: %s", e)
    
    LOG.error("No valid AEAD key provided")
    sys.exit(1)


KEY = get_encryption_key()
AEAD = ChaCha20Poly1305(KEY)


def decrypt_payload(b64_ciphertext):
    """Decrypt a base64-encoded encrypted payload."""
    try:
        raw = base64.b64decode(b64_ciphertext)
        nonce = raw[:12]
        ct_and_tag = raw[12:]
        plaintext = AEAD.decrypt(nonce, ct_and_tag, associated_data=None)
        return plaintext
    except Exception as e:
        LOG.exception("Decryption failed: %s", e)
        raise


def parse_mavlink_direct(payload_bytes):
    """
    Parse MAVLink message directly using dialect (avoids serial dependency).
    """
    if not PYMAVLINK_AVAILABLE:
        return parse_mavlink_basic(payload_bytes)
    
    try:
        if len(payload_bytes) < 8:
            LOG.debug("Payload too short: %d bytes", len(payload_bytes))
            return None
        
        magic = payload_bytes[0]
        
        # Create MAVLink parser
        mav = MAVLINK_DIALECT.MAVLink(None)
        mav.robust_parsing = True
        
        # Parse buffer
        msgs = mav.parse_buffer(payload_bytes)
        
        if not msgs:
            LOG.debug("No messages parsed from buffer")
            return parse_mavlink_basic(payload_bytes)
        
        # Extract telemetry from first message
        msg = msgs[0]
        return extract_telemetry_from_msg(msg)
        
    except Exception as e:
        LOG.debug("Direct parsing failed: %s, using basic", e)
        return parse_mavlink_basic(payload_bytes)


def extract_telemetry_from_msg(msg):
    """Extract telemetry data from a parsed MAVLink message."""
    try:
        telemetry = {
            "timestamp": datetime.utcnow().isoformat(),
            "msg_type": msg.get_type(),
        }
        
        msg_type = msg.get_type()
        
        if msg_type == "GLOBAL_POSITION_INT":
            telemetry.update({
                "latitude": msg.lat / 1e7,
                "longitude": msg.lon / 1e7,
                "altitude_msl": msg.alt / 1000.0,
                "altitude_relative": msg.relative_alt / 1000.0,
                "velocity_x": msg.vx / 100.0,
                "velocity_y": msg.vy / 100.0,
                "velocity_z": msg.vz / 100.0,
                "heading": msg.hdg / 100.0,
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
                "voltage_battery": msg.voltage_battery / 1000.0,
                "current_battery": msg.current_battery / 100.0,
                "battery_remaining": msg.battery_remaining,
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
                "system_status": msg.system_status,
            })
        
        return telemetry
    except Exception as e:
        LOG.debug("Failed to extract telemetry: %s", e)
        return None


def parse_mavlink_basic(payload_bytes):
    """Basic MAVLink parsing - header only."""
    try:
        if len(payload_bytes) < 8:
            return None
        
        magic = payload_bytes[0]
        
        if magic == 0xFE:  # MAVLink v1
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 1,
                "payload_length": payload_bytes[1],
                "seq": payload_bytes[2],
                "system_id": payload_bytes[3],
                "component_id": payload_bytes[4],
                "message_id": payload_bytes[5],
                "parsing": "basic",
            }
        elif magic == 0xFD:  # MAVLink v2
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 2,
                "payload_length": payload_bytes[1],
                "seq": payload_bytes[4],
                "system_id": payload_bytes[5],
                "component_id": payload_bytes[6],
                "message_id": int.from_bytes(payload_bytes[7:10], byteorder='little'),
                "parsing": "basic",
            }
        else:
            LOG.warning("Unknown MAVLink magic byte: 0x%02X", magic)
            return None
    except Exception as e:
        LOG.debug("Basic parsing failed: %s", e)
        return None


def send_cloudwatch_metrics(telemetry, drone_id=DRONE_ID):
    """Send telemetry as CloudWatch metrics."""
    try:
        metric_data = []
        timestamp = datetime.utcnow()
        
        dimensions = [
            {"Name": "DroneId", "Value": drone_id},
            {"Name": "MessageType", "Value": telemetry.get("msg_type", "UNKNOWN")},
        ]
        
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
        
        # Send in batches
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
    """Process a single SQS message."""
    body = msg.get("Body")
    
    if not body:
        LOG.warning("Empty message body")
        return False
    
    try:
        # Try to parse as JSON
        try:
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                body = body_json.get("data") or body_json.get("payload") or body
        except json.JSONDecodeError:
            pass
        
        # Decrypt
        plaintext = decrypt_payload(body)
        LOG.info("Decrypted payload: %d bytes", len(plaintext))
        LOG.debug("First 32 bytes (hex): %s", plaintext[:32].hex())
        
        # Parse MAVLink
        telemetry = parse_mavlink_direct(plaintext)
        
        if telemetry:
            LOG.info("✓ Parsed telemetry: %s", json.dumps(telemetry, default=str, indent=2))
            send_cloudwatch_metrics(telemetry)
        else:
            LOG.warning("Could not parse MAVLink message (hex dump below)")
            LOG.warning("Payload: %s", plaintext.hex()[:200])
        
        return True
    except Exception as e:
        LOG.exception("Failed to process message: %s", e)
        
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
    """Main consumer loop."""
    LOG.info("=" * 60)
    LOG.info("Drone Telemetry Consumer (Auto-Install Version)")
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
            response = sqs.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=POLL_WAIT,
                VisibilityTimeout=VISIBILITY_TIMEOUT,
            )
            
            messages = response.get("Messages", [])
            
            if not messages:
                continue
            
            for message in messages:
                message_count += 1
                LOG.info("Processing message #%d (MessageId: %s)", 
                        message_count, message.get("MessageId", "unknown"))
                
                if process_message(message):
                    sqs.delete_message(
                        QueueUrl=SQS_QUEUE_URL,
                        ReceiptHandle=message["ReceiptHandle"]
                    )
                    LOG.info("✓ Message processed and deleted successfully")
                else:
                    LOG.warning("✗ Processing failed; message will remain in queue")
        
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