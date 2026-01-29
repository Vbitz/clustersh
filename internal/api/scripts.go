package api

import (
	"fmt"
	"net/http"
)

func (s *Server) handleInstallSh(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	coordinatorURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`#!/bin/bash
set -e

# ClusterSH Agent Installation Script
COORDINATOR_URL="%s"
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/clustersh/agent"

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

# Download binary (assuming releases are hosted)
BINARY_URL="${COORDINATOR_URL}/releases/clusteragent-${OS}-${ARCH}"
echo "Downloading clusteragent from $BINARY_URL..."

if command -v curl &> /dev/null; then
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/clusteragent" || {
        echo "Binary download failed. You may need to build from source."
        echo "  go install j5.nz/clustersh/cmd/clusteragent@latest"
        exit 1
    }
elif command -v wget &> /dev/null; then
    wget -q "$BINARY_URL" -O "$INSTALL_DIR/clusteragent" || {
        echo "Binary download failed. You may need to build from source."
        exit 1
    }
else
    echo "Neither curl nor wget found. Please install one of them."
    exit 1
fi

chmod +x "$INSTALL_DIR/clusteragent"

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
CSR_CONTENT=$(cat agent.csr | base64 | tr -d '\n')

RESPONSE=$(curl -s -X POST "${COORDINATOR_URL}/agent/csr" \
    -H "Content-Type: application/json" \
    -d "{\"csr\": \"$(cat agent.csr)\", \"machine_name\": \"$MACHINE_NAME\"}")

# Extract certificate from response
echo "$RESPONSE" | grep -o '"certificate":"[^"]*"' | sed 's/"certificate":"//;s/"$//' > agent.crt
echo "$RESPONSE" | grep -o '"ca_cert":"[^"]*"' | sed 's/"ca_cert":"//;s/"$//' > ca.crt

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
    <string>$HOME/.config/clustersh/agent/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.config/clustersh/agent/stderr.log</string>
</dict>
</plist>
EOF
    launchctl load "$HOME/Library/LaunchAgents/com.clustersh.agent.plist"
    echo "Service installed and started"
fi

echo ""
echo "ClusterSH Agent installation complete!"
echo "Machine name: $MACHINE_NAME"
`, coordinatorURL)

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(script))
}

func (s *Server) handleInstallPs1(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	coordinatorURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`# ClusterSH Agent Installation Script for Windows
$ErrorActionPreference = "Stop"

$CoordinatorURL = "%s"
$InstallDir = "$env:LOCALAPPDATA\ClusterSH\bin"
$ConfigDir = "$env:LOCALAPPDATA\ClusterSH\agent"

Write-Host "Installing ClusterSH Agent..."

# Create directories
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# Download binary
$BinaryURL = "$CoordinatorURL/releases/clusteragent-windows-amd64.exe"
Write-Host "Downloading clusteragent from $BinaryURL..."

try {
    Invoke-WebRequest -Uri $BinaryURL -OutFile "$InstallDir\clusteragent.exe"
} catch {
    Write-Host "Binary download failed. You may need to build from source."
    Write-Host "  go install j5.nz/clustersh/cmd/clusteragent@latest"
    exit 1
}

# Generate keypair
$MachineName = $env:COMPUTERNAME
Write-Host "Generating keypair for $MachineName..."

Set-Location $ConfigDir

# Use certutil or openssl if available
if (Get-Command openssl -ErrorAction SilentlyContinue) {
    openssl ecparam -genkey -name prime256v1 -noout -out agent.key
    openssl req -new -key agent.key -out agent.csr -subj "/CN=$MachineName/O=ClusterSH"
} else {
    Write-Host "OpenSSL not found. Please install OpenSSL or use WSL."
    exit 1
}

# Submit CSR to coordinator
Write-Host "Requesting certificate from coordinator..."
$CSR = Get-Content agent.csr -Raw
$Body = @{
    csr = $CSR
    machine_name = $MachineName
} | ConvertTo-Json

$Response = Invoke-RestMethod -Uri "$CoordinatorURL/agent/csr" -Method Post -Body $Body -ContentType "application/json"
$Response.certificate | Out-File -FilePath agent.crt -Encoding ASCII
$Response.ca_cert | Out-File -FilePath ca.crt -Encoding ASCII

# Create config
@{
    coordinator_url = $CoordinatorURL
    machine_name = $MachineName
} | ConvertTo-Json | Out-File -FilePath config.json -Encoding ASCII

Write-Host "Configuration saved to $ConfigDir"

# Create scheduled task
Write-Host "Creating scheduled task..."
$Action = New-ScheduledTaskAction -Execute "$InstallDir\clusteragent.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "ClusterSH Agent" -Action $Action -Trigger $Trigger -Settings $Settings -Force

# Start the task now
Start-ScheduledTask -TaskName "ClusterSH Agent"

Write-Host ""
Write-Host "ClusterSH Agent installation complete!"
Write-Host "Machine name: $MachineName"
`, coordinatorURL)

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(script))
}

func (s *Server) handleInstallClientSh(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	coordinatorURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`#!/bin/bash
set -e

# ClusterSH Client Installation Script
COORDINATOR_URL="%s"
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/clustersh/client"

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

# Download binary
BINARY_URL="${COORDINATOR_URL}/releases/clustersh-${OS}-${ARCH}"
echo "Downloading clustersh from $BINARY_URL..."

if command -v curl &> /dev/null; then
    curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/clustersh" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clustersh@latest 2>/dev/null || {
            echo "Failed to install. Please build manually."
            exit 1
        }
    }
elif command -v wget &> /dev/null; then
    wget -q "$BINARY_URL" -O "$INSTALL_DIR/clustersh" 2>/dev/null || {
        echo "Binary download failed. Building from source..."
        go install j5.nz/clustersh/cmd/clustersh@latest
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
TIMESTAMP=$(date +%%s)
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
        \"public_key\": $(echo "$PUBLIC_KEY" | jq -Rs .),
        \"fingerprint\": \"$FINGERPRINT\",
        \"signature\": \"$SIGNATURE\",
        \"timestamp\": $TIMESTAMP
    }")

STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | sed 's/"status":"//;s/"$//')

if [ "$STATUS" = "approved" ]; then
    # Extract certificate
    echo "$RESPONSE" | grep -o '"certificate":"[^"]*"' | sed 's/"certificate":"//;s/"$//' > client.crt
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
`, coordinatorURL)

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(script))
}
