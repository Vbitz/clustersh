#!/bin/bash
set -e

# ClusterSH Agent Installation Script
# Usage: curl -fsSL http://coordinator:5672/install.sh | bash
#
# This script is typically served by the coordinator at /install.sh
# and contains the coordinator URL embedded.

COORDINATOR_URL="${COORDINATOR_URL:-}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/clustersh/agent}"

if [ -z "$COORDINATOR_URL" ]; then
    echo "Error: COORDINATOR_URL environment variable is required"
    echo "Usage: COORDINATOR_URL=http://coordinator:5672 $0"
    exit 1
fi

echo "Installing ClusterSH Agent..."

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

# Try to download binary
BINARY_URL="${COORDINATOR_URL}/releases/clusteragent-${OS}-${ARCH}"
echo "Downloading clusteragent..."

if command -v curl &> /dev/null; then
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/clusteragent" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clusteragent@latest || {
            echo "Failed to install. Please build manually."
            exit 1
        }
        INSTALL_DIR=$(go env GOPATH)/bin
    }
elif command -v wget &> /dev/null; then
    wget -q "$BINARY_URL" -O "$INSTALL_DIR/clusteragent" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clusteragent@latest
        INSTALL_DIR=$(go env GOPATH)/bin
    }
fi

[ -f "$INSTALL_DIR/clusteragent" ] && chmod +x "$INSTALL_DIR/clusteragent"

# Generate keypair and CSR
MACHINE_NAME=$(hostname)
echo "Generating keypair for $MACHINE_NAME..."

cd "$CONFIG_DIR"

# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out agent.key
chmod 600 agent.key

# Generate CSR
openssl req -new -key agent.key -out agent.csr -subj "/CN=$MACHINE_NAME/O=ClusterSH"

# Submit CSR to coordinator
echo "Requesting certificate from coordinator..."

RESPONSE=$(curl -s -X POST "${COORDINATOR_URL}/agent/csr" \
    -H "Content-Type: application/json" \
    -d "{\"csr\": \"$(cat agent.csr)\", \"machine_name\": \"$MACHINE_NAME\"}")

# Extract certificate from response
echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('certificate',''))" > agent.crt
echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ca_cert',''))" > ca.crt

if [ ! -s agent.crt ]; then
    echo "Failed to get certificate from coordinator"
    echo "Response: $RESPONSE"
    exit 1
fi

# Create config
cat > config.json << EOF
{
  "coordinator_url": "$COORDINATOR_URL",
  "machine_name": "$MACHINE_NAME"
}
EOF

echo "Configuration saved to $CONFIG_DIR"

# Install service based on OS
if [ "$OS" = "linux" ]; then
    echo "Installing systemd user service..."
    mkdir -p "$HOME/.config/systemd/user"
    cat > "$HOME/.config/systemd/user/clusteragent.service" << EOF
[Unit]
Description=Cluster Shell Agent

[Service]
ExecStart=$INSTALL_DIR/clusteragent
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable clusteragent
    systemctl --user start clusteragent
    echo "Service installed and started"

elif [ "$OS" = "darwin" ]; then
    echo "Installing launchd agent..."
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$HOME/Library/LaunchAgents/com.clustersh.agent.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.clustersh.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/clusteragent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$CONFIG_DIR/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$CONFIG_DIR/stderr.log</string>
</dict>
</plist>
EOF
    launchctl load "$HOME/Library/LaunchAgents/com.clustersh.agent.plist"
    echo "Service installed and started"
fi

echo ""
echo "ClusterSH Agent installation complete!"
echo "Machine name: $MACHINE_NAME"
