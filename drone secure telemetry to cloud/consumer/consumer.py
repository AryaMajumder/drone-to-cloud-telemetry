#!/usr/bin/env python3
"""
consumer.py - FINAL PRODUCTION VERSION

Features:
- Auto-installs pymavlink + pyserial if missing
- Extensive logging at every step
- Multiple parsing fallbacks
- Handles all MAVLink message types
- CloudWatch metrics integration
- Robust error handling
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

# Configure logging with DEBUG level for troubleshooting
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
LOG = logging.getLogger(__name__)

# ============================================================================
# AUTO-INSTALL DEPENDENCIES
# ============================================================================
PYMAVLINK_AVAILABLE = False
MAVLINK_DIALECT = None

def install_dependencies():
    """Install pymavlink and pyserial if missing."""
    LOG.info("=" * 70)
    LOG.info("STEP 1: Checking Dependencies")
    LOG.info("=" * 70)
    
    try:
        import pymavlink
        LOG.info("✓ pymavlink already installed (version: %s)", getattr(pymavlink, '__version__', 'unknown'))
        return True
    except ImportError:
        LOG.warning("✗ pymavlink not found - will auto-install")
        
        try:
            LOG.info("Installing: pymavlink pyserial")
            LOG.info("Command: pip install pymavlink pyserial --break-system-packages")
            
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "pymavlink", "pyserial", "--break-system-packages"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                LOG.info("✓ Installation successful!")
                LOG.info("Output: %s", result.stdout[:500])
                return True
            else:
                LOG.error("✗ Installation failed!")
                LOG.error("Error: %s", result.stderr[:500])
                return False
                
        except subprocess.TimeoutExpired:
            LOG.error("✗ Installation timed out after 120 seconds")
            return False
        except Exception as e:
            LOG.error("✗ Installation error: %s", e)
            return False

# Install dependencies
if install_dependencies():
    LOG.info("-" * 70)
    LOG.info("STEP 2: Importing MAVLink Dialect")
    LOG.info("-" * 70)
    
    # Try MAVLink v2 first
    try:
        from pymavlink.dialects.v20 import common as mavlink2
        PYMAVLINK_AVAILABLE = True
        MAVLINK_DIALECT = mavlink2
        LOG.info("✓ Imported MAVLink v2 dialect successfully")
        LOG.info("  Dialect module: %s", MAVLINK_DIALECT.__name__)
    except ImportError as e:
        LOG.warning("✗ MAVLink v2 import failed: %s", e)
        
        # Fallback to MAVLink v1
        try:
            from pymavlink.dialects.v10 import common as mavlink1
            PYMAVLINK_AVAILABLE = True
            MAVLINK_DIALECT = mavlink1
            LOG.info("✓ Imported MAVLink v1 dialect successfully")
            LOG.info("  Dialect module: %s", MAVLINK_DIALECT.__name__)
        except ImportError as e2:
            LOG.error("✗ MAVLink v1 import also failed: %s", e2)
            LOG.error("✗ Will use basic parsing only")
            PYMAVLINK_AVAILABLE = False
else:
    LOG.error("✗ Dependency installation failed - using basic parsing only")

LOG.info("=" * 70)

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
            LOG.info("✓ Loaded 32-byte encryption key from AEAD_KEY_B64")
            return key
        except Exception as e:
            LOG.error("✗ Invalid AEAD_KEY_B64: %s", e)
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
                    LOG.info("✓ Loaded encryption key from Secrets Manager: %s", secret_name)
                    return key
        except Exception as e:
            LOG.warning("✗ Failed to load key from Secrets Manager: %s", e)
    
    LOG.error("✗ No valid AEAD key provided (set AEAD_KEY_B64 or AEAD_KEY_SECRET_NAME)")
    sys.exit(1)


KEY = get_encryption_key()
AEAD = ChaCha20Poly1305(KEY)


def decrypt_payload(b64_ciphertext):
    """Decrypt a base64-encoded encrypted payload."""
    try:
        raw = base64.b64decode(b64_ciphertext)
        LOG.debug("  Encrypted data: %d bytes", len(raw))
        
        nonce = raw[:12]
        ct_and_tag = raw[12:]
        LOG.debug("  Nonce: %s", nonce.hex())
        LOG.debug("  Ciphertext+Tag: %d bytes", len(ct_and_tag))
        
        plaintext = AEAD.decrypt(nonce, ct_and_tag, associated_data=None)
        LOG.debug("  ✓ Decryption successful: %d bytes plaintext", len(plaintext))
        return plaintext
    except Exception as e:
        LOG.exception("✗ Decryption failed: %s", e)
        raise


def parse_mavlink_with_dialect(payload_bytes):
    """Parse MAVLink using imported dialect (primary method)."""
    if not PYMAVLINK_AVAILABLE or not MAVLINK_DIALECT:
        LOG.debug("  Dialect not available, skipping")
        return None
    
    try:
        LOG.debug("  Attempting dialect parsing...")
        LOG.debug("  Payload length: %d bytes", len(payload_bytes))
        LOG.debug("  First 20 bytes (hex): %s", payload_bytes[:20].hex())
        
        if len(payload_bytes) < 8:
            LOG.warning("  ✗ Payload too short: %d bytes (need >= 8)", len(payload_bytes))
            return None
        
        magic = payload_bytes[0]
        LOG.debug("  Magic byte: 0x%02X", magic)
        
        # Create MAVLink parser
        mav = MAVLINK_DIALECT.MAVLink(None)
        mav.robust_parsing = True
        
        # Parse buffer
        LOG.debug("  Calling parse_buffer...")
        msgs = mav.parse_buffer(payload_bytes)
        
        if not msgs:
            LOG.warning("  ✗ parse_buffer returned no messages")
            return None
        
        LOG.info("  ✓ Parsed %d message(s) from buffer", len(msgs))
        
        # Extract telemetry from first message
        msg = msgs[0]
        msg_type = msg.get_type()
        LOG.info("  Message type: %s", msg_type)
        
        return extract_telemetry_from_msg(msg)
        
    except Exception as e:
        LOG.warning("  ✗ Dialect parsing failed: %s", e, exc_info=True)
        return None


def extract_telemetry_from_msg(msg):
    """Extract telemetry data from a parsed MAVLink message."""
    try:
        msg_type = msg.get_type()
        
        telemetry = {
            "timestamp": datetime.utcnow().isoformat(),
            "msg_type": msg_type,
        }
        
        LOG.debug("  Extracting fields for %s...", msg_type)
        
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
            LOG.info("  ✓ Extracted GLOBAL_POSITION_INT: lat=%.6f, lon=%.6f, alt=%.1fm", 
                    telemetry["latitude"], telemetry["longitude"], telemetry["altitude_msl"])
                    
        elif msg_type == "ATTITUDE":
            telemetry.update({
                "roll": msg.roll,
                "pitch": msg.pitch,
                "yaw": msg.yaw,
                "rollspeed": msg.rollspeed,
                "pitchspeed": msg.pitchspeed,
                "yawspeed": msg.yawspeed,
            })
            LOG.info("  ✓ Extracted ATTITUDE: roll=%.2f, pitch=%.2f, yaw=%.2f", 
                    telemetry["roll"], telemetry["pitch"], telemetry["yaw"])
                    
        elif msg_type == "VFR_HUD":
            telemetry.update({
                "airspeed": msg.airspeed,
                "groundspeed": msg.groundspeed,
                "heading": msg.heading,
                "throttle": msg.throttle,
                "altitude": msg.alt,
                "climb_rate": msg.climb,
            })
            LOG.info("  ✓ Extracted VFR_HUD: speed=%.1f m/s, alt=%.1fm, throttle=%d%%", 
                    telemetry["groundspeed"], telemetry["altitude"], telemetry["throttle"])
                    
        elif msg_type == "SYS_STATUS":
            telemetry.update({
                "voltage_battery": msg.voltage_battery / 1000.0,
                "current_battery": msg.current_battery / 100.0,
                "battery_remaining": msg.battery_remaining,
            })
            LOG.info("  ✓ Extracted SYS_STATUS: battery=%.1fV, remaining=%d%%", 
                    telemetry["voltage_battery"], telemetry["battery_remaining"])
                    
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
            LOG.info("  ✓ Extracted GPS_RAW_INT: fix=%d, sats=%d, lat=%.6f, lon=%.6f", 
                    telemetry["gps_fix_type"], telemetry["satellites_visible"],
                    telemetry["latitude"], telemetry["longitude"])
                    
        elif msg_type == "HEARTBEAT":
            telemetry.update({
                "type": msg.type,
                "autopilot": msg.autopilot,
                "base_mode": msg.base_mode,
                "system_status": msg.system_status,
            })
            LOG.info("  ✓ Extracted HEARTBEAT: type=%d, autopilot=%d, status=%d", 
                    telemetry["type"], telemetry["autopilot"], telemetry["system_status"])
        else:
            LOG.info("  ℹ Unknown message type '%s' - storing basic info only", msg_type)
        
        return telemetry
        
    except Exception as e:
        LOG.warning("  ✗ Failed to extract telemetry: %s", e, exc_info=True)
        return None


def parse_mavlink_basic(payload_bytes):
    """Basic MAVLink parsing - header only (fallback)."""
    LOG.debug("  Using basic parsing (header-only)...")
    
    try:
        if len(payload_bytes) < 8:
            LOG.warning("  ✗ Payload too short for basic parsing: %d bytes", len(payload_bytes))
            return None
        
        magic = payload_bytes[0]
        LOG.debug("  Magic byte: 0x%02X", magic)
        
        if magic == 0xFE:  # MAVLink v1
            telemetry = {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 1,
                "payload_length": payload_bytes[1],
                "seq": payload_bytes[2],
                "system_id": payload_bytes[3],
                "component_id": payload_bytes[4],
                "message_id": payload_bytes[5],
                "parsing": "basic_v1",
            }
            LOG.info("  ✓ Basic parsing (v1): seq=%d, sys=%d, comp=%d, msg_id=%d",
                    telemetry["seq"], telemetry["system_id"], 
                    telemetry["component_id"], telemetry["message_id"])
            return telemetry
            
        elif magic == 0xFD:  # MAVLink v2
            telemetry = {
                "timestamp": datetime.utcnow().isoformat(),
                "mavlink_version": 2,
                "payload_length": payload_bytes[1],
                "seq": payload_bytes[4],
                "system_id": payload_bytes[5],
                "component_id": payload_bytes[6],
                "message_id": int.from_bytes(payload_bytes[7:10], byteorder='little'),
                "parsing": "basic_v2",
            }
            LOG.info("  ✓ Basic parsing (v2): seq=%d, sys=%d, comp=%d, msg_id=%d",
                    telemetry["seq"], telemetry["system_id"], 
                    telemetry["component_id"], telemetry["message_id"])
            return telemetry
            
        else:
            LOG.warning("  ✗ Unknown MAVLink magic byte: 0x%02X (expected 0xFE or 0xFD)", magic)
            LOG.warning("  First 32 bytes: %s", payload_bytes[:32].hex())
            return None
            
    except Exception as e:
        LOG.warning("  ✗ Basic parsing failed: %s", e, exc_info=True)
        return None


def send_cloudwatch_metrics(telemetry, drone_id=DRONE_ID):
    """Send telemetry as CloudWatch metrics."""
    try:
        LOG.debug("  Preparing CloudWatch metrics...")
        metric_data = []
        timestamp = datetime.utcnow()
        
        dimensions = [
            {"Name": "DroneId", "Value": drone_id},
            {"Name": "MessageType", "Value": telemetry.get("msg_type", telemetry.get("parsing", "UNKNOWN"))},
        ]
        
        # Always send message count
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
        
        # Send in batches of 20 (CloudWatch limit)
        for i in range(0, len(metric_data), 20):
            batch = metric_data[i:i+20]
            cloudwatch.put_metric_data(
                Namespace=CLOUDWATCH_NAMESPACE,
                MetricData=batch
            )
            LOG.debug("  Sent batch of %d metrics", len(batch))
        
        LOG.info("  ✓ Sent %d total metrics to CloudWatch namespace '%s'", 
                len(metric_data), CLOUDWATCH_NAMESPACE)
                
    except Exception as e:
        LOG.exception("  ✗ Failed to send CloudWatch metrics: %s", e)


def process_message(msg):
    """Process a single SQS message."""
    body = msg.get("Body")
    
    if not body:
        LOG.warning("✗ Received message with empty body")
        return False
    
    LOG.debug("Message body length: %d characters", len(body))
    LOG.debug("Message body (first 100 chars): %s", body[:100])
    
    try:
        # Step 1: Try to parse as JSON (IoT Core might wrap it)
        LOG.debug("STEP: Checking if body is JSON...")
        try:
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                LOG.debug("  Body is JSON dict with keys: %s", list(body_json.keys()))
                body = body_json.get("data") or body_json.get("payload") or body
            else:
                LOG.debug("  Body is JSON but not a dict")
        except json.JSONDecodeError:
            LOG.debug("  Body is not JSON (raw base64 string)")
        
        # Step 2: Decrypt
        LOG.info("STEP: Decrypting payload...")
        plaintext = decrypt_payload(body)
        LOG.info("  ✓ Decrypted: %d bytes", len(plaintext))
        
        # Step 3: Parse MAVLink (try dialect first, then basic)
        LOG.info("STEP: Parsing MAVLink...")
        telemetry = parse_mavlink_with_dialect(plaintext)
        
        if not telemetry:
            LOG.info("  Dialect parsing failed, trying basic parsing...")
            telemetry = parse_mavlink_basic(plaintext)
        
        # Step 4: Send metrics if we got telemetry
        if telemetry:
            LOG.info("✓ TELEMETRY EXTRACTED:")
            LOG.info(json.dumps(telemetry, indent=2, default=str))
            
            LOG.info("STEP: Sending to CloudWatch...")
            send_cloudwatch_metrics(telemetry)
        else:
            LOG.warning("✗ Could not parse MAVLink message")
            LOG.warning("  Payload hex dump (first 100 bytes): %s", plaintext[:100].hex())
        
        return True
        
    except Exception as e:
        LOG.exception("✗ FAILED to process message: %s", e)
        
        # Send error metric
        try:
            cloudwatch.put_metric_data(
                Namespace=CLOUDWATCH_NAMESPACE,
                MetricData=[{
                    "MetricName": "ProcessingErrors",
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
    LOG.info("╔" + "=" * 68 + "╗")
    LOG.info("║" + " " * 68 + "║")
    LOG.info("║" + "  Drone Telemetry Consumer - PRODUCTION VERSION".center(68) + "║")
    LOG.info("║" + " " * 68 + "║")
    LOG.info("╚" + "=" * 68 + "╝")
    LOG.info("")
    LOG.info("Configuration:")
    LOG.info("  SQS Queue: %s", SQS_QUEUE_URL)
    LOG.info("  AWS Region: %s", AWS_REGION)
    LOG.info("  CloudWatch Namespace: %s", CLOUDWATCH_NAMESPACE)
    LOG.info("  Drone ID: %s", DRONE_ID)
    LOG.info("  PyMAVLink Available: %s", PYMAVLINK_AVAILABLE)
    if PYMAVLINK_AVAILABLE:
        LOG.info("  MAVLink Dialect: %s", MAVLINK_DIALECT.__name__)
    LOG.info("  Poll Wait: %d seconds", POLL_WAIT)
    LOG.info("")
    LOG.info("Starting message processing loop...")
    LOG.info("-" * 70)
    
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
                LOG.debug("No messages in queue, continuing to poll...")
                continue
            
            for message in messages:
                message_count += 1
                message_id = message.get("MessageId", "unknown")
                
                LOG.info("")
                LOG.info("╔" + "=" * 68 + "╗")
                LOG.info("║  MESSAGE #%d (ID: %s)" % (message_count, message_id[:40].ljust(40)) + "  ║")
                LOG.info("╚" + "=" * 68 + "╝")
                
                if process_message(message):
                    sqs.delete_message(
                        QueueUrl=SQS_QUEUE_URL,
                        ReceiptHandle=message["ReceiptHandle"]
                    )
                    LOG.info("✓ Message #%d processed and deleted from queue", message_count)
                else:
                    LOG.warning("✗ Message #%d processing failed; will remain in queue", message_count)
                
                LOG.info("-" * 70)
        
        except ClientError as e:
            LOG.exception("AWS client error: %s", e)
            time.sleep(5)
        
        except KeyboardInterrupt:
            LOG.info("")
            LOG.info("Received shutdown signal (Ctrl+C)")
            LOG.info("Shutting down gracefully...")
            break
        
        except Exception as e:
            LOG.exception("Unexpected error in main loop: %s", e)
            time.sleep(2)
    
    LOG.info("")
    LOG.info("╔" + "=" * 68 + "╗")
    LOG.info("║  Consumer stopped. Total messages processed: %d" % message_count + " " * (68 - 47 - len(str(message_count))) + "║")
    LOG.info("╚" + "=" * 68 + "╝")


if __name__ == "__main__":
    main()