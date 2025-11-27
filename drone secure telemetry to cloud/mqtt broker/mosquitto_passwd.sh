# Run as root
set -euxo pipefail

# 1) Ensure system python3 exists
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found; aborting" >&2
  exit 1
fi

# 2) Ensure pip exists & install bcrypt; install build deps first if pip bcrypt fails
if ! python3 -m pip --version >/dev/null 2>&1; then
  python3 -m ensurepip --upgrade || true
  python3 -m pip install --upgrade pip
fi

# Try to install bcrypt; if compilation fails, install dev packages and retry
if ! python3 -m pip install --upgrade bcrypt >/dev/null 2>&1; then
  echo "pip install bcrypt failed — installing build deps and retrying" >&2
  dnf -y install gcc python3-devel openssl-devel libffi-devel || true
  python3 -m pip install --upgrade pip
  python3 -m pip install --upgrade bcrypt
fi

# 3) Prepare directories
PW_DIR="/usr/local/etc/mosquitto"
PASSFILE="${PW_DIR}/passwords"
ROOTCREDS="/root/mosquitto_drone_credentials.txt"
mkdir -p "$PW_DIR"

# 4) Generate random passwords
DRONE_PW=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)
CONSUMER_PW=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | cut -c1-20)

# 5) Compute bcrypt hashes safely using python -c and pass the password as a shell argument
DRONE_HASH=$(python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" "$DRONE_PW")
CONSUMER_HASH=$(python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" "$CONSUMER_PW")

# Verify hash lengths (sanity)
if [ -z "$DRONE_HASH" ] || [ -z "$CONSUMER_HASH" ]; then
  echo "ERROR: empty hash produced; aborting" >&2
  python3 -V
  python3 -m pip show bcrypt || true
  exit 1
fi

# 6) Write the password file in mosquitto bcrypt format: username:hash
printf "%s:%s\n" "drone" "$DRONE_HASH" > "$PASSFILE"
printf "%s:%s\n" "consumer" "$CONSUMER_HASH" >> "$PASSFILE"

# lock down file
if id -u mosquitto >/dev/null 2>&1; then
  chown mosquitto:mosquitto "$PASSFILE" || true
fi
chmod 600 "$PASSFILE"

# 7) Save human-readable creds for root only
printf "drone:%s\nconsumer:%s\n" "$DRONE_PW" "$CONSUMER_PW" > "$ROOTCREDS"
chmod 600 "$ROOTCREDS"

# 8) Print short status and file locations
echo "Wrote password file: $PASSFILE"
echo "Credentials saved (root-only): $ROOTCREDS"
echo "Password-file contents (first lines):"
sed -n '1,20p' "$PASSFILE" || true

echo
echo "Test locally on EC2 (replace <pw> from $ROOTCREDS):"
echo "  mosquitto_sub -h 127.0.0.1 -p 1883 -u consumer -P '<consumer_pw>' -t '#' -v -C 1"
echo "  mosquitto_pub -h 127.0.0.1 -p 1883 -u drone -P '<drone_pw>' -t 'drone/test' -m 'hello'"
