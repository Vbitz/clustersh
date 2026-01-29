# ClusterSH Agent Installation Script for Windows
# Usage: iex ((New-Object System.Net.WebClient).DownloadString('http://coordinator:5672/install.ps1'))

$ErrorActionPreference = "Stop"

$CoordinatorURL = $env:COORDINATOR_URL
if (-not $CoordinatorURL) {
    Write-Host "Error: COORDINATOR_URL environment variable is required"
    Write-Host 'Usage: $env:COORDINATOR_URL = "http://coordinator:5672"; .\install.ps1'
    exit 1
}

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
    Write-Host "Binary download failed. Attempting to build from source..."
    try {
        go install j5.nz/clustersh/cmd/clusteragent@latest
        $GoPath = (go env GOPATH)
        Copy-Item "$GoPath\bin\clusteragent.exe" "$InstallDir\clusteragent.exe"
    } catch {
        Write-Host "Failed to install. Please build manually."
        exit 1
    }
}

# Generate keypair
$MachineName = $env:COMPUTERNAME
Write-Host "Generating keypair for $MachineName..."

Set-Location $ConfigDir

# Use openssl if available
if (Get-Command openssl -ErrorAction SilentlyContinue) {
    openssl ecparam -genkey -name prime256v1 -noout -out agent.key
    openssl req -new -key agent.key -out agent.csr -subj "/CN=$MachineName/O=ClusterSH"
} else {
    Write-Host "OpenSSL not found. Please install OpenSSL or use WSL."
    Write-Host "Download from: https://slproweb.com/products/Win32OpenSSL.html"
    exit 1
}

# Submit CSR to coordinator
Write-Host "Requesting certificate from coordinator..."
$CSR = Get-Content agent.csr -Raw
$Body = @{
    csr = $CSR
    machine_name = $MachineName
} | ConvertTo-Json

try {
    $Response = Invoke-RestMethod -Uri "$CoordinatorURL/agent/csr" -Method Post -Body $Body -ContentType "application/json"
    $Response.certificate | Out-File -FilePath agent.crt -Encoding ASCII
    $Response.ca_cert | Out-File -FilePath ca.crt -Encoding ASCII
} catch {
    Write-Host "Failed to get certificate from coordinator: $_"
    exit 1
}

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

try {
    Unregister-ScheduledTask -TaskName "ClusterSH Agent" -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

Register-ScheduledTask -TaskName "ClusterSH Agent" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null

# Start the task now
Start-ScheduledTask -TaskName "ClusterSH Agent"

Write-Host ""
Write-Host "ClusterSH Agent installation complete!"
Write-Host "Machine name: $MachineName"
