// Package service handles service installation for different platforms.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Install installs the agent as a system service.
func Install(binaryPath string) error {
	switch runtime.GOOS {
	case "linux":
		return installLinux(binaryPath)
	case "darwin":
		return installDarwin(binaryPath)
	case "windows":
		return installWindows(binaryPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Uninstall removes the agent service.
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallLinux()
	case "darwin":
		return uninstallDarwin()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Status returns the service status.
func Status() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return statusLinux()
	case "darwin":
		return statusDarwin()
	case "windows":
		return statusWindows()
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func installLinux(binaryPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	serviceDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("create service directory: %w", err)
	}

	servicePath := filepath.Join(serviceDir, "clusteragent.service")
	serviceContent := fmt.Sprintf(`[Unit]
Description=Cluster Shell Agent

[Service]
ExecStart=%s
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`, binaryPath)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	// Reload and enable
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}

	if err := exec.Command("systemctl", "--user", "enable", "clusteragent").Run(); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}

	if err := exec.Command("systemctl", "--user", "start", "clusteragent").Run(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	return nil
}

func installDarwin(binaryPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	launchAgentsDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "clustersh", "agent")
	plistPath := filepath.Join(launchAgentsDir, "com.clustersh.agent.plist")
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.clustersh.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>%s/stderr.log</string>
</dict>
</plist>
`, binaryPath, configDir, configDir)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist file: %w", err)
	}

	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("load launchd agent: %w", err)
	}

	return nil
}

func installWindows(binaryPath string) error {
	// Create scheduled task
	taskName := "ClusterSH Agent"

	// Delete existing task if any (ignore error if task doesn't exist)
	_ = exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()

	// Create new task
	cmd := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", binaryPath,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("create scheduled task: %w", err)
	}

	// Start the task
	if err := exec.Command("schtasks", "/Run", "/TN", taskName).Run(); err != nil {
		return fmt.Errorf("start task: %w", err)
	}

	return nil
}

func uninstallLinux() error {
	// Ignore errors if service not running/enabled
	_ = exec.Command("systemctl", "--user", "stop", "clusteragent").Run()
	_ = exec.Command("systemctl", "--user", "disable", "clusteragent").Run()

	home, _ := os.UserHomeDir()
	servicePath := filepath.Join(home, ".config", "systemd", "user", "clusteragent.service")
	_ = os.Remove(servicePath)

	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

func uninstallDarwin() error {
	home, _ := os.UserHomeDir()
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "com.clustersh.agent.plist")

	_ = exec.Command("launchctl", "unload", plistPath).Run()
	_ = os.Remove(plistPath)
	return nil
}

func uninstallWindows() error {
	taskName := "ClusterSH Agent"
	return exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()
}

func statusLinux() (string, error) {
	output, err := exec.Command("systemctl", "--user", "status", "clusteragent").Output()
	if err != nil {
		if strings.Contains(string(output), "could not be found") {
			return "not installed", nil
		}
		return "stopped", nil
	}
	if strings.Contains(string(output), "Active: active") {
		return "running", nil
	}
	return "stopped", nil
}

func statusDarwin() (string, error) {
	output, err := exec.Command("launchctl", "list", "com.clustersh.agent").Output()
	if err != nil {
		return "not installed", nil
	}
	if strings.Contains(string(output), "com.clustersh.agent") {
		return "running", nil
	}
	return "stopped", nil
}

func statusWindows() (string, error) {
	output, err := exec.Command("schtasks", "/Query", "/TN", "ClusterSH Agent").Output()
	if err != nil {
		return "not installed", nil
	}
	if strings.Contains(string(output), "Running") {
		return "running", nil
	}
	return "stopped", nil
}
