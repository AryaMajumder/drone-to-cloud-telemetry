#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG ---
OUTDIR="/etc/drone-pub"
KEYFILE="$OUTDIR/drone_key.bin"
CREDENTIAL_FILE="$OUTDIR/credentials.env"

# --- OPTIONS ---
FORCE=0
if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
fi

# --- FUNCTION: generate 32-byte AES256 key ---
gen_hex() {
    openssl rand -hex 32
}

# --- PREPARE DIR ---
sudo mkdir -p "$OUTDIR"
sudo chown root:root "$OUTDIR"

# --- KEY GENERATION ---
if [[ -f "$KEYFILE" && $FORCE -eq 0 ]]; then
    echo "[INFO] Keyfile already exists: $KEYFILE"
    echo "       Use --force to regenerate."
    ENCKEY_HEX=$(xxd -p "$KEYFILE")
else
    echo "[INFO] Generating new AES-256 encryption key..."
    ENCKEY_HEX=$(gen_hex)

    echo "[INFO] Writing raw binary key to $KEYFILE"
    printf "%s" "$ENCKEY_HEX" | xxd -r -p | sudo tee "$KEYFILE" >/dev/null
fi

# --- SAVE SUMMARY (plaintext) ---
echo "[INFO] Writing ENCRYPTION_KEY to $CREDENTIAL_FILE"
sudo bash -c "cat > $CREDENTIAL_FILE" <<EOF
ENCRYPTION_KEY=$ENCKEY_HEX
EOF

# --- PERMISSIONS ---
sudo chown companion:companion "$KEYFILE"
sudo chmod 600 "$KEYFILE"

sudo chown root:root "$CREDENTIAL_FILE"
sudo chmod 640 "$CREDENTIAL_FILE"

# --- DONE ---
echo
echo "=============================="
echo "  AES-256 ENCRYPTION KEY DONE"
echo "=============================="
echo "Encryption key (hex):  $ENCKEY_HEX"
echo "Key file (binary):     $KEYFILE"
echo "Summary file:          $CREDENTIAL_FILE"
echo
echo "Make sure env.conf contains:"
echo "-------------------------------------------"
echo "KEYFILE=$KEYFILE"
echo "-------------------------------------------"
echo
echo "[OK] Complete.