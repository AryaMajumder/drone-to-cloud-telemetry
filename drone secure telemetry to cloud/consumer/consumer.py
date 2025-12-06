# consumer_enhanced.py - Full telemetry parsing with CloudWatch Logs + Metrics
import os
import time
import base64
import logging
import json
import struct
from datetime import datetime
from typing import Dict, List, Optional, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import boto3
from botocore.exceptions import ClientError

# Try to import pymavlink for full decoding
try:
    from pymavlink import mavutil
    PYMAVLINK_AVAILABLE = True
except ImportError:
    PYMAVLINK_AVAILABLE = False
    logging.warning("pymavlink not available - will use basic parsing only")

# Configure structured logging for CloudWatch
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

# Required
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
AEAD_KEY_B64 = os.environ.get("AEAD_KEY_B64")
AEAD_KEY_SECRET_ARN = os.environ.get("AEAD_KEY_SECRET_ARN")

# CloudWatch configuration
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "DroneTelemetry")
DRONE_ID = os.environ.get("DRONE_ID", "UNKNOWN")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Processing configuration
POLL_WAIT = int(os.environ.get("SQS_WAIT", "10"))
VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY", "30"))
METRICS_BATCH_SIZE = int(os.environ.get("METRICS_BATCH_SIZE", "20"))

# Feature flags
LOG_FULL_TELEMETRY = os.environ.get("LOG_FULL_TELEMETRY", "true").lower() == "true"
PUBLISH_TELEMETRY_METRICS = os.environ.get("PUBLISH_TELEMETRY_METRICS", "true").lower() == "true"

# Validation
if not SQS_QUEUE_URL:
    logger.error("SQS_QUEUE_URL env var is required")
    raise SystemExit(1)

# =============================================================================
# AWS CLIENTS
# =============================================================================

sqs = boto3.client("sqs", region_name=AWS_REGION)
cloudwatch = boto3.client("cloudwatch", region_name=AWS_REGION)

# =============================================================================
# SECRETS MANAGEMENT
# =============================================================================

def get_secret_from_secrets_manager(secret_arn: str) -> Optional[str]:
    """Retrieve a secret from AWS Secrets Manager."""
    try:
        secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
        response = secrets_client.get_secret_value(SecretId=secret_arn)
        
        if 'SecretString' in response:
            secret = response['SecretString']
            try:
                secret_dict = json.loads(secret)
                if 'AEAD_KEY_B64' in secret_dict:
                    return secret_dict['AEAD_KEY_B64']
                elif 'key' in secret_dict:
                    return secret_dict['key']
                elif 'encryption_key' in secret_dict:
                    return secret_dict['encryption_key']
                else:
                    return list(secret_dict.values())[0]
            except json.JSONDecodeError:
                return secret
        return None
    except ClientError as e:
        logger.error(f"Error retrieving secret: {e}")
        return None

def get_key() -> bytes:
    """Get the AEAD encryption key."""
    if AEAD_KEY_B64:
        logger.info("Using AEAD key from AEAD_KEY_B64 environment variable")
        try:
            k = base64.b64decode(AEAD_KEY_B64)
            if len(k) != 32:
                raise ValueError("AEAD key must be 32 bytes")
            return k
        except Exception as e:
            logger.error(f"Invalid AEAD_KEY_B64: {e}")
            raise
    
    if AEAD_KEY_SECRET_ARN:
        logger.info(f"Fetching AEAD key from Secrets Manager: {AEAD_KEY_SECRET_ARN}")
        secret_value = get_secret_from_secrets_manager(AEAD_KEY_SECRET_ARN)
        if secret_value:
            try:
                k = base64.b64decode(secret_value.strip())
                if len(k) != 32:
                    raise ValueError(f"AEAD key must be 32 bytes, got {len(k)}")
                logger.info("Successfully loaded AEAD key from Secrets Manager")
                return k
            except Exception as e:
                logger.error(f"Invalid AEAD key from Secrets Manager: {e}")
                raise
    
    logger.error("No AEAD key provided")
    raise SystemExit("No AEAD key provided (AEAD_KEY_B64 or AEAD_KEY_SECRET_ARN)")

KEY = get_key()
AEAD = ChaCha20Poly1305(KEY)

# =============================================================================
# DECRYPTION
# =============================================================================

def decrypt_payload(b64_ciphertext: str) -> bytes:
    """Decrypt a base64-encoded ciphertext."""
    try:
        raw = base64.b64decode(b64_ciphertext)
    except Exception as e:
        logger.error(f"Failed to decode base64 ciphertext: {e}")
        raise
    
    if len(raw) < 12:
        raise ValueError(f"Ciphertext too short: {len(raw)} bytes")
    
    nonce = raw[:12]
    ct_and_tag = raw[12:]
    
    try:
        plaintext = AEAD.decrypt(nonce, ct_and_tag, associated_data=None)
        return plaintext
    except Exception as e:
        logger.exception(f"Decryption failed: {e}")
        raise

# =============================================================================
# ENHANCED MAVLINK PARSING WITH PYMAVLINK
# =============================================================================

def parse_mavlink_full(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse MAVLink message and extract full telemetry data.
    Uses pymavlink if available, falls back to basic parsing.
    """
    if not PYMAVLINK_AVAILABLE:
        return parse_mavlink_basic(data)
    
    try:
        # Create MAVLink parser
        mav_file = mavutil.mavlink_connection('tcp:localhost:0', source_system=255, dialect='ardupilotmega')
        
        # Parse the message
        try:
            # Try to decode using pymavlink
            msg = mav_file.mav.decode(data)
            if msg is None:
                return parse_mavlink_basic(data)
        except Exception:
            return parse_mavlink_basic(data)
        
        # Extract common fields
        result = {
            'message_id': msg.get_msgId(),
            'message_name': msg.get_type(),
            'sequence': getattr(msg, '_seq', 0),
            'system_id': getattr(msg, '_header', {}).srcSystem if hasattr(msg, '_header') else 0,
            'component_id': getattr(msg, '_header', {}).srcComponent if hasattr(msg, '_header') else 0,
        }
        
        # Extract telemetry based on message type
        msg_type = msg.get_type()
        telemetry = extract_telemetry_by_type(msg, msg_type)
        
        if telemetry:
            result['telemetry'] = telemetry
        
        return result
        
    except Exception as e:
        logger.debug(f"pymavlink parse failed, using basic: {e}")
        return parse_mavlink_basic(data)

def extract_telemetry_by_type(msg, msg_type: str) -> Optional[Dict[str, Any]]:
    """Extract telemetry data based on MAVLink message type."""
    
    try:
        if msg_type == 'HEARTBEAT':
            return {
                'type': msg.type,
                'autopilot': msg.autopilot,
                'base_mode': msg.base_mode,
                'custom_mode': msg.custom_mode,
                'system_status': msg.system_status,
                'mavlink_version': msg.mavlink_version
            }
        
        elif msg_type == 'GLOBAL_POSITION_INT':
            return {
                'latitude': msg.lat / 1e7,
                'longitude': msg.lon / 1e7,
                'altitude_msl': msg.alt / 1000.0,
                'altitude_relative': msg.relative_alt / 1000.0,
                'velocity_x': msg.vx / 100.0,  # cm/s to m/s
                'velocity_y': msg.vy / 100.0,
                'velocity_z': msg.vz / 100.0,
                'heading': msg.hdg / 100.0 if msg.hdg != 65535 else None
            }
        
        elif msg_type == 'ATTITUDE':
            return {
                'roll': msg.roll,
                'pitch': msg.pitch,
                'yaw': msg.yaw,
                'rollspeed': msg.rollspeed,
                'pitchspeed': msg.pitchspeed,
                'yawspeed': msg.yawspeed
            }
        
        elif msg_type == 'VFR_HUD':
            return {
                'airspeed': msg.airspeed,
                'groundspeed': msg.groundspeed,
                'altitude': msg.alt,
                'climb_rate': msg.climb,
                'heading': msg.heading,
                'throttle': msg.throttle
            }
        
        elif msg_type == 'GPS_RAW_INT':
            return {
                'latitude': msg.lat / 1e7,
                'longitude': msg.lon / 1e7,
                'altitude': msg.alt / 1000.0,
                'eph': msg.eph / 100.0,  # cm to m
                'epv': msg.epv / 100.0,
                'velocity': msg.vel / 100.0,
                'cog': msg.cog / 100.0 if msg.cog != 65535 else None,
                'fix_type': msg.fix_type,
                'satellites_visible': msg.satellites_visible
            }
        
        elif msg_type == 'SYS_STATUS':
            return {
                'voltage_battery': msg.voltage_battery / 1000.0,  # mV to V
                'current_battery': msg.current_battery / 100.0 if msg.current_battery != -1 else None,  # cA to A
                'battery_remaining': msg.battery_remaining,
                'drop_rate_comm': msg.drop_rate_comm / 100.0,
                'errors_comm': msg.errors_comm,
                'errors_count1': msg.errors_count1,
                'errors_count2': msg.errors_count2,
                'errors_count3': msg.errors_count3,
                'errors_count4': msg.errors_count4
            }
        
        elif msg_type == 'BATTERY_STATUS':
            return {
                'id': msg.id,
                'battery_function': msg.battery_function,
                'type': msg.type,
                'temperature': msg.temperature / 100.0 if msg.temperature != 32767 else None,
                'voltages': [v / 1000.0 if v != 65535 else None for v in msg.voltages],
                'current_battery': msg.current_battery / 100.0 if msg.current_battery != -1 else None,
                'current_consumed': msg.current_consumed,
                'energy_consumed': msg.energy_consumed,
                'battery_remaining': msg.battery_remaining
            }
        
        elif msg_type == 'RC_CHANNELS':
            return {
                'chan1_raw': msg.chan1_raw,
                'chan2_raw': msg.chan2_raw,
                'chan3_raw': msg.chan3_raw,
                'chan4_raw': msg.chan4_raw,
                'chan5_raw': msg.chan5_raw,
                'chan6_raw': msg.chan6_raw,
                'chan7_raw': msg.chan7_raw,
                'chan8_raw': msg.chan8_raw,
                'rssi': msg.rssi
            }
        
        elif msg_type == 'MISSION_CURRENT':
            return {
                'seq': msg.seq
            }
        
        elif msg_type == 'NAV_CONTROLLER_OUTPUT':
            return {
                'nav_roll': msg.nav_roll,
                'nav_pitch': msg.nav_pitch,
                'nav_bearing': msg.nav_bearing,
                'target_bearing': msg.target_bearing,
                'wp_dist': msg.wp_dist,
                'alt_error': msg.alt_error,
                'aspd_error': msg.aspd_error,
                'xtrack_error': msg.xtrack_error
            }
        
        elif msg_type == 'SERVO_OUTPUT_RAW':
            return {
                'servo1_raw': msg.servo1_raw,
                'servo2_raw': msg.servo2_raw,
                'servo3_raw': msg.servo3_raw,
                'servo4_raw': msg.servo4_raw,
                'servo5_raw': msg.servo5_raw,
                'servo6_raw': msg.servo6_raw,
                'servo7_raw': msg.servo7_raw,
                'servo8_raw': msg.servo8_raw,
                'port': msg.port
            }
        
        else:
            # For unknown message types, return generic info
            return {
                'raw_fields': {k: v for k, v in msg.to_dict().items() if not k.startswith('_')}
            }
            
    except Exception as e:
        logger.debug(f"Error extracting telemetry for {msg_type}: {e}")
        return None

def parse_mavlink_basic(data: bytes) -> Optional[Dict[str, Any]]:
    """Basic MAVLink parsing (fallback when pymavlink not available)."""
    if len(data) < 8:
        return None
    
    try:
        if data[0] == 0xFE:  # MAVLink v1
            return parse_mavlink_v1(data)
        elif data[0] == 0xFD:  # MAVLink v2
            return parse_mavlink_v2(data)
        else:
            logger.warning(f"Unknown MAVLink version byte: 0x{data[0]:02x}")
            return None
    except Exception as e:
        logger.error(f"Error parsing MAVLink: {e}")
        return None

def parse_mavlink_v1(data: bytes) -> Dict[str, Any]:
    """Parse MAVLink v1 frame (basic)."""
    if len(data) < 8:
        return None
    
    magic, length, seq, sys_id, comp_id, msg_id = struct.unpack('<BBBBBB', data[:6])
    
    return {
        'version': 1,
        'length': length,
        'sequence': seq,
        'system_id': sys_id,
        'component_id': comp_id,
        'message_id': msg_id,
        'message_name': 'UNKNOWN',
        'payload_hex': data[6:6+length].hex() if len(data) >= 6+length else None,
    }

def parse_mavlink_v2(data: bytes) -> Dict[str, Any]:
    """Parse MAVLink v2 frame (basic)."""
    if len(data) < 10:
        return None
    
    magic, length, incompat_flags, compat_flags, seq, sys_id, comp_id = struct.unpack('<BBBBBBB', data[:7])
    msg_id = struct.unpack('<I', data[7:10] + b'\x00')[0]
    
    return {
        'version': 2,
        'length': length,
        'incompat_flags': incompat_flags,
        'compat_flags': compat_flags,
        'sequence': seq,
        'system_id': sys_id,
        'component_id': comp_id,
        'message_id': msg_id,
        'message_name': 'UNKNOWN',
        'payload_hex': data[10:10+length].hex() if len(data) >= 10+length else None,
    }

# =============================================================================
# CLOUDWATCH METRICS
# =============================================================================

class CloudWatchMetricsWriter:
    """Batched CloudWatch Metrics writer."""
    
    def __init__(self, namespace: str, batch_size: int = 20):
        self.namespace = namespace
        self.batch_size = batch_size
        self.metrics_batch = []
        self.client = cloudwatch
        
    def add_metric(self, metric_name: str, value: float, unit: str = 'None', 
                   dimensions: List[Dict[str, str]] = None, timestamp: datetime = None):
        """Add a metric to the batch."""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        metric = {
            'MetricName': metric_name,
            'Value': value,
            'Unit': unit,
            'Timestamp': timestamp
        }
        
        if dimensions:
            metric['Dimensions'] = dimensions
        
        self.metrics_batch.append(metric)
        
        # Flush if batch is full
        if len(self.metrics_batch) >= self.batch_size:
            self.flush()
    
    def flush(self):
        """Write metrics batch to CloudWatch."""
        if not self.metrics_batch:
            return
        
        try:
            # CloudWatch accepts max 20 metrics per call
            for i in range(0, len(self.metrics_batch), 20):
                batch = self.metrics_batch[i:i+20]
                self.client.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=batch
                )
            logger.debug(f"Wrote {len(self.metrics_batch)} metrics to CloudWatch")
            self.metrics_batch = []
        except ClientError as e:
            logger.error(f"Error writing metrics to CloudWatch: {e}")
            raise

# Initialize metrics writer
metrics_writer = CloudWatchMetricsWriter(CLOUDWATCH_NAMESPACE, METRICS_BATCH_SIZE)

# =============================================================================
# MESSAGE PROCESSING
# =============================================================================

# Statistics tracking
stats = {
    'messages_processed': 0,
    'messages_failed': 0,
    'decryption_errors': 0,
    'parse_errors': 0,
    'start_time': time.time()
}

def log_structured_message(event: str, data: Dict[str, Any], level: str = "INFO"):
    """
    Log structured JSON messages for CloudWatch Logs Insights.
    Format: {"event": "...", "drone_id": "...", "timestamp": "...", "data": {...}}
    """
    log_entry = {
        'event': event,
        'drone_id': DRONE_ID,
        'timestamp': datetime.utcnow().isoformat(),
        'data': data
    }
    
    # Log as JSON for CloudWatch Logs Insights queries
    log_message = json.dumps(log_entry)
    
    if level == "ERROR":
        logger.error(log_message)
    elif level == "WARNING":
        logger.warning(log_message)
    elif level == "DEBUG":
        logger.debug(log_message)
    else:
        logger.info(log_message)

def publish_telemetry_metrics(telemetry: Dict[str, Any], mavlink_data: Dict[str, Any]):
    """Publish telemetry-specific metrics to CloudWatch."""
    if not PUBLISH_TELEMETRY_METRICS or not telemetry:
        return
    
    dimensions = [{'Name': 'DroneId', 'Value': DRONE_ID}]
    msg_name = mavlink_data.get('message_name', 'UNKNOWN')
    
    try:
        # GPS metrics
        if 'latitude' in telemetry and 'longitude' in telemetry:
            metrics_writer.add_metric('Latitude', telemetry['latitude'], 'None', dimensions)
            metrics_writer.add_metric('Longitude', telemetry['longitude'], 'None', dimensions)
        
        if 'altitude_msl' in telemetry:
            metrics_writer.add_metric('AltitudeMSL', telemetry['altitude_msl'], 'None', dimensions)
        
        if 'altitude_relative' in telemetry:
            metrics_writer.add_metric('AltitudeRelative', telemetry['altitude_relative'], 'None', dimensions)
        
        if 'altitude' in telemetry:
            metrics_writer.add_metric('Altitude', telemetry['altitude'], 'None', dimensions)
        
        # Velocity metrics
        if 'groundspeed' in telemetry:
            metrics_writer.add_metric('Groundspeed', telemetry['groundspeed'], 'None', dimensions)
        
        if 'airspeed' in telemetry:
            metrics_writer.add_metric('Airspeed', telemetry['airspeed'], 'None', dimensions)
        
        if 'climb_rate' in telemetry:
            metrics_writer.add_metric('ClimbRate', telemetry['climb_rate'], 'None', dimensions)
        
        # Battery metrics
        if 'voltage_battery' in telemetry:
            metrics_writer.add_metric('BatteryVoltage', telemetry['voltage_battery'], 'None', dimensions)
        
        if 'current_battery' in telemetry and telemetry['current_battery'] is not None:
            metrics_writer.add_metric('BatteryCurrent', telemetry['current_battery'], 'None', dimensions)
        
        if 'battery_remaining' in telemetry:
            metrics_writer.add_metric('BatteryRemaining', float(telemetry['battery_remaining']), 'Percent', dimensions)
        
        # Attitude metrics
        if 'roll' in telemetry:
            metrics_writer.add_metric('Roll', telemetry['roll'], 'None', dimensions)
        
        if 'pitch' in telemetry:
            metrics_writer.add_metric('Pitch', telemetry['pitch'], 'None', dimensions)
        
        if 'yaw' in telemetry:
            metrics_writer.add_metric('Yaw', telemetry['yaw'], 'None', dimensions)
        
        # GPS quality metrics
        if 'fix_type' in telemetry:
            metrics_writer.add_metric('GPSFixType', float(telemetry['fix_type']), 'None', dimensions)
        
        if 'satellites_visible' in telemetry:
            metrics_writer.add_metric('GPSSatellites', float(telemetry['satellites_visible']), 'Count', dimensions)
        
        if 'eph' in telemetry:
            metrics_writer.add_metric('GPSHorizontalAccuracy', telemetry['eph'], 'None', dimensions)
        
        # Heading
        if 'heading' in telemetry and telemetry['heading'] is not None:
            metrics_writer.add_metric('Heading', telemetry['heading'], 'None', dimensions)
        
    except Exception as e:
        logger.debug(f"Error publishing telemetry metrics: {e}")

def publish_metrics(mavlink_data: Dict[str, Any]):
    """Publish message-level metrics to CloudWatch."""
    dimensions = [
        {'Name': 'DroneId', 'Value': DRONE_ID},
    ]
    
    if 'system_id' in mavlink_data:
        dimensions.append({'Name': 'SystemId', 'Value': str(mavlink_data['system_id'])})
    
    # Message count
    metrics_writer.add_metric(
        'MessagesProcessed',
        1.0,
        'Count',
        dimensions
    )
    
    # Message ID distribution
    if 'message_id' in mavlink_data:
        msg_dims = dimensions + [{'Name': 'MessageId', 'Value': str(mavlink_data['message_id'])}]
        metrics_writer.add_metric(
            'MessageIdCount',
            1.0,
            'Count',
            msg_dims
        )
    
    # Message name distribution
    if 'message_name' in mavlink_data and mavlink_data['message_name'] != 'UNKNOWN':
        msg_dims = dimensions + [{'Name': 'MessageName', 'Value': mavlink_data['message_name']}]
        metrics_writer.add_metric(
            'MessageNameCount',
            1.0,
            'Count',
            msg_dims
        )
    
    # Sequence tracking (for gap detection)
    if 'sequence' in mavlink_data:
        metrics_writer.add_metric(
            'SequenceNumber',
            float(mavlink_data['sequence']),
            'None',
            dimensions
        )
    
    # Message length
    if 'length' in mavlink_data:
        metrics_writer.add_metric(
            'MessageLength',
            float(mavlink_data['length']),
            'Bytes',
            dimensions
        )

def process_message(msg: Dict) -> bool:
    """Process a single SQS message."""
    body = msg.get("Body")
    
    if not body:
        logger.warning("Empty message body")
        stats['messages_failed'] += 1
        return False
    
    try:
        # Decrypt
        plaintext = decrypt_payload(body)
        
        # Parse MAVLink (full decoding if pymavlink available)
        mavlink_data = parse_mavlink_full(plaintext)
        
        if not mavlink_data:
            logger.warning("Failed to parse MAVLink frame")
            stats['parse_errors'] += 1
            stats['messages_failed'] += 1
            
            # Still log the failure with structured data
            log_structured_message('parse_failed', {
                'message_length': len(plaintext),
                'first_bytes': plaintext[:10].hex()
            }, level="WARNING")
            
            # Metric for parse errors
            metrics_writer.add_metric(
                'ParseErrors',
                1.0,
                'Count',
                [{'Name': 'DroneId', 'Value': DRONE_ID}]
            )
            
            return True  # Don't retry parse errors
        
        # Prepare log data
        log_data = {
            'message_id': mavlink_data.get('message_id'),
            'message_name': mavlink_data.get('message_name'),
            'sequence': mavlink_data.get('sequence'),
            'system_id': mavlink_data.get('system_id'),
            'component_id': mavlink_data.get('component_id'),
        }
        
        # Add full telemetry if available and enabled
        if LOG_FULL_TELEMETRY and 'telemetry' in mavlink_data:
            log_data['telemetry'] = mavlink_data['telemetry']
        
        # Log structured telemetry data
        log_structured_message('telemetry_received', log_data)
        
        # Publish message-level metrics
        publish_metrics(mavlink_data)
        
        # Publish telemetry-specific metrics
        if 'telemetry' in mavlink_data:
            publish_telemetry_metrics(mavlink_data['telemetry'], mavlink_data)
        
        stats['messages_processed'] += 1
        return True
        
    except Exception as e:
        logger.exception(f"Failed to process message: {e}")
        stats['messages_failed'] += 1
        stats['decryption_errors'] += 1
        
        # Log structured error
        log_structured_message('processing_error', {
            'error_type': type(e).__name__,
            'error_message': str(e)
        }, level="ERROR")
        
        # Metric for decryption errors
        metrics_writer.add_metric(
            'DecryptionErrors',
            1.0,
            'Count',
            [{'Name': 'DroneId', 'Value': DRONE_ID}]
        )
        
        return False

def publish_system_metrics():
    """Publish system-level metrics."""
    dimensions = [{'Name': 'DroneId', 'Value': DRONE_ID}]
    
    # Success rate
    total = stats['messages_processed'] + stats['messages_failed']
    if total > 0:
        success_rate = (stats['messages_processed'] / total) * 100
        metrics_writer.add_metric('SuccessRate', success_rate, 'Percent', dimensions)
    
    # Error rates
    metrics_writer.add_metric('TotalProcessed', float(stats['messages_processed']), 'Count', dimensions)
    metrics_writer.add_metric('TotalFailed', float(stats['messages_failed']), 'Count', dimensions)
    metrics_writer.add_metric('DecryptionErrors', float(stats['decryption_errors']), 'Count', dimensions)
    metrics_writer.add_metric('ParseErrors', float(stats['parse_errors']), 'Count', dimensions)
    
    # Uptime
    uptime = time.time() - stats['start_time']
    metrics_writer.add_metric('UptimeSeconds', uptime, 'Seconds', dimensions)
    
    # Processing rate (messages per second)
    if uptime > 0:
        rate = stats['messages_processed'] / uptime
        metrics_writer.add_metric('ProcessingRate', rate, 'Count/Second', dimensions)

# =============================================================================
# MAIN LOOP
# =============================================================================

def shutdown():
    """Flush pending metrics before shutdown."""
    logger.info("Shutting down - flushing metrics")
    try:
        publish_system_metrics()
        metrics_writer.flush()
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

def main():
    logger.info("="*60)
    logger.info("Drone Telemetry Consumer Starting (Enhanced)")
    logger.info("="*60)
    logger.info(f"SQS Queue: {SQS_QUEUE_URL}")
    logger.info(f"Drone ID: {DRONE_ID}")
    logger.info(f"CloudWatch Namespace: {CLOUDWATCH_NAMESPACE}")
    logger.info(f"AWS Region: {AWS_REGION}")
    logger.info(f"pymavlink Available: {PYMAVLINK_AVAILABLE}")
    logger.info(f"Log Full Telemetry: {LOG_FULL_TELEMETRY}")
    logger.info(f"Publish Telemetry Metrics: {PUBLISH_TELEMETRY_METRICS}")
    logger.info("="*60)
    
    # Initial system metrics
    log_structured_message('consumer_started', {
        'queue_url': SQS_QUEUE_URL,
        'namespace': CLOUDWATCH_NAMESPACE,
        'pymavlink_available': PYMAVLINK_AVAILABLE,
        'log_full_telemetry': LOG_FULL_TELEMETRY
    })
    
    consecutive_errors = 0
    max_consecutive_errors = 10
    last_metrics_publish = time.time()
    metrics_publish_interval = 60  # Publish system metrics every 60 seconds
    
    try:
        while True:
            try:
                resp = sqs.receive_message(
                    QueueUrl=SQS_QUEUE_URL,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=POLL_WAIT,
                    VisibilityTimeout=VISIBILITY_TIMEOUT
                )
                
                msgs = resp.get("Messages", [])
                
                if not msgs:
                    consecutive_errors = 0
                    
                    # Publish periodic system metrics
                    if time.time() - last_metrics_publish > metrics_publish_interval:
                        publish_system_metrics()
                        metrics_writer.flush()
                        last_metrics_publish = time.time()
                    
                    continue
                
                for m in msgs:
                    success = process_message(m)
                    
                    if success:
                        sqs.delete_message(
                            QueueUrl=SQS_QUEUE_URL,
                            ReceiptHandle=m["ReceiptHandle"]
                        )
                        consecutive_errors = 0
                    else:
                        logger.warning("Processing failed; message will remain in queue")
                        consecutive_errors += 1
                        
                        if consecutive_errors >= max_consecutive_errors:
                            logger.error(f"Too many consecutive errors ({consecutive_errors})")
                            shutdown()
                            time.sleep(30)
                            consecutive_errors = 0
                
                # Publish periodic system metrics
                if time.time() - last_metrics_publish > metrics_publish_interval:
                    publish_system_metrics()
                    metrics_writer.flush()
                    last_metrics_publish = time.time()
                            
            except ClientError as e:
                logger.exception(f"AWS client error: {e}")
                consecutive_errors += 1
                
                log_structured_message('aws_error', {
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }, level="ERROR")
                
                time.sleep(5)
                
                if consecutive_errors >= max_consecutive_errors:
                    logger.error("Too many consecutive AWS errors")
                    shutdown()
                    time.sleep(60)
                    consecutive_errors = 0
                    
            except KeyboardInterrupt:
                logger.info("Received interrupt signal")
                raise
                
            except Exception as e:
                logger.exception(f"Unexpected error: {e}")
                consecutive_errors += 1
                
                log_structured_message('unexpected_error', {
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }, level="ERROR")
                
                time.sleep(2)
                
                if consecutive_errors >= max_consecutive_errors:
                    logger.error("Too many consecutive unexpected errors")
                    shutdown()
                    time.sleep(60)
                    consecutive_errors = 0
    
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully")
    finally:
        shutdown()

if __name__ == "__main__":
    main()