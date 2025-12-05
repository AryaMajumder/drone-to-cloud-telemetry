# consumer.py - CloudWatch Logs + Metrics focused version
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
# MAVLINK PARSING
# =============================================================================

def parse_mavlink_basic(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse basic MAVLink v1/v2 frame."""
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
    """Parse MAVLink v1 frame."""
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
        'payload': data[6:6+length].hex() if len(data) >= 6+length else None,
    }

def parse_mavlink_v2(data: bytes) -> Dict[str, Any]:
    """Parse MAVLink v2 frame."""
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
        'payload': data[10:10+length].hex() if len(data) >= 10+length else None,
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

def publish_metrics(mavlink_data: Dict[str, Any]):
    """Publish key metrics to CloudWatch."""
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
        
        # Parse MAVLink
        mavlink_data = parse_mavlink_basic(plaintext)
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
        
        # Log structured telemetry data
        log_structured_message('telemetry_received', {
            'message_id': mavlink_data.get('message_id'),
            'sequence': mavlink_data.get('sequence'),
            'system_id': mavlink_data.get('system_id'),
            'component_id': mavlink_data.get('component_id'),
            'length': mavlink_data.get('length'),
            'version': mavlink_data.get('version')
        })
        
        # Publish metrics
        publish_metrics(mavlink_data)
        
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
    logger.info("Drone Telemetry Consumer Starting")
    logger.info("="*60)
    logger.info(f"SQS Queue: {SQS_QUEUE_URL}")
    logger.info(f"Drone ID: {DRONE_ID}")
    logger.info(f"CloudWatch Namespace: {CLOUDWATCH_NAMESPACE}")
    logger.info(f"AWS Region: {AWS_REGION}")
    logger.info("="*60)
    
    # Initial system metrics
    log_structured_message('consumer_started', {
        'queue_url': SQS_QUEUE_URL,
        'namespace': CLOUDWATCH_NAMESPACE
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