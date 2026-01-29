#!/bin/bash
set -e

# ClusterSH Client Installation Script
# Usage: curl -fsSL http://coordinator:5672/install_client.sh | bash

COORDINATOR_URL="${COORDINATOR_URL:-}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/clustersh/client}"

if [ -z "$COORDINATOR_URL" ]; then
    echo "Error: COORDINATOR_URL environment variable is required"
    echo "Usage: COORDINATOR_URL=http://coordinator:5672 $0"
    exit 1
fi

echo "Installing ClusterSH Client..."

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Platform: $OS/$ARCH"

# Download binary
BINARY_URL="${COORDINATOR_URL}/releases/clustersh-${OS}-${ARCH}"
echo "Downloading clustersh..."

if command -v curl &> /dev/null; then
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/clustersh" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clustersh@latest || {
            echo "Failed to install. Please build manually."
            exit 1
        }
        INSTALL_DIR=$(go env GOPATH)/bin
    }
elif command -v wget &> /dev/null; then
    wget -q "$BINARY_URL" -O "$INSTALL_DIR/clustersh" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clustersh@latest
        INSTALL_DIR=$(go env GOPATH)/bin
    }
fi

[ -f "$INSTALL_DIR/clustersh" ] && chmod +x "$INSTALL_DIR/clustersh"

# Download CA certificate
echo "Downloading CA certificate..."
curl -fsSL "${COORDINATOR_URL}/ca.crt" -o "$CONFIG_DIR/ca.crt"

# Generate keypair
echo "Generating keypair..."
cd "$CONFIG_DIR"
openssl ecparam -genkey -name prime256v1 -noout -out client.key
chmod 600 client.key

# Extract public key
openssl ec -in client.key -pubout -out client.pub 2>/dev/null

# Calculate fingerprint
FINGERPRINT=$(openssl ec -in client.key -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}')

# Create timestamp and signature for login
TIMESTAMP=$(date +%s)
SIGNATURE=$(echo -n "$TIMESTAMP" | openssl dgst -sha256 -sign client.key | base64 | tr -d '\n')
PUBLIC_KEY=$(cat client.pub)

# Create config
cat > config.json << EOF
{
  "coordinator_url": "$COORDINATOR_URL",
  "default_timeout": "5m"
}
EOF

# Request login
echo "Requesting login approval..."
RESPONSE=$(curl -s -X POST "${COORDINATOR_URL}/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"public_key\": $(echo "$PUBLIC_KEY" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))"),
        \"fingerprint\": \"$FINGERPRINT\",
        \"signature\": \"$SIGNATURE\",
        \"timestamp\": $TIMESTAMP
    }")

STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")

if [ "$STATUS" = "approved" ]; then
    # Extract certificate
    echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('certificate',''))" > client.crt
    echo "Login approved! Certificate saved."
else
    echo ""
    echo "Login request submitted. Your fingerprint is:"
    echo ""
    echo "  $FINGERPRINT"
    echo ""
    echo "Ask an administrator to run:"
    echo ""
    echo "  clusterd approve $FINGERPRINT"
    echo ""
    echo "Then run 'clustersh login $COORDINATOR_URL' again to get your certificate."
fi

echo ""
echo "Configuration saved to $CONFIG_DIR"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Add this to your shell profile:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
fi
