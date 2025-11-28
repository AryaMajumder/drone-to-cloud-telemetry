# consumer.py
import os
import time
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL")
POLL_WAIT = int(os.environ.get("SQS_WAIT", "10"))
VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY", "30"))

# KEY: either provide AEAD_KEY_B64 (base64 of 32 bytes) or implement secrets retrieval
AEAD_KEY_B64 = os.environ.get("AEAD_KEY_B64")

if not SQS_QUEUE_URL:
    logging.error("SQS_QUEUE_URL env var is required")
    raise SystemExit(1)

def get_key():
    if AEAD_KEY_B64:
        try:
            k = base64.b64decode(AEAD_KEY_B64)
            if len(k) != 32:
                raise ValueError("AEAD key must be 32 bytes")
            return k
        except Exception as e:
            logging.error("Invalid AEAD_KEY_B64: %s", e)
            raise
    # placeholder: read from Secrets Manager if you implement
    raise SystemExit("No AEAD key provided (AEAD_KEY_B64)")

KEY = get_key()
AEAD = ChaCha20Poly1305(KEY)

sqs = boto3.client("sqs")

def decrypt_payload(b64_ciphertext):
    # expected format: base64(nonce + ciphertext + tag) or JSON-wrapped — adapt if your producer uses different scheme
    raw = base64.b64decode(b64_ciphertext)
    # choose nonce length 12 (96 bits) used by ChaCha20-Poly1305
    nonce = raw[:12]
    ct_and_tag = raw[12:]
    try:
        plaintext = AEAD.decrypt(nonce, ct_and_tag, associated_data=None)
        return plaintext
    except Exception as e:
        logging.exception("decrypt failed")
        raise

def process_message(msg):
    body = msg.get("Body")
    receipt = msg.get("ReceiptHandle")
    if not body:
        logging.warning("empty body")
        return False
    try:
        pt = decrypt_payload(body)
        # For now, log bytes (hex) and base64 of plaintext
        logging.info("Decrypted payload len=%d hex=%s", len(pt), pt.hex()[:200])
        # TODO: parse MAVLink, forward to Timestream / OpenSearch / S3
        return True
    except Exception:
        return False

def main():
    logging.info("Starting consumer; polling %s", SQS_QUEUE_URL)
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
                continue
            for m in msgs:
                if process_message(m):
                    sqs.delete_message(QueueUrl=SQS_QUEUE_URL, ReceiptHandle=m["ReceiptHandle"])
                else:
                    logging.warning("Processing failed; leaving message (visibility will expire)")
        except ClientError as e:
            logging.exception("AWS client error")
            time.sleep(5)
        except KeyboardInterrupt:
            logging.info("Shutting down")
            return
        except Exception:
            logging.exception("unexpected error")
            time.sleep(2)

if __name__ == "__main__":
    main()
