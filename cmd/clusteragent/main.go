// Package main implements the clusteragent backend agent.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"j5.nz/clustersh/internal/agent"
	"j5.nz/clustersh/internal/service"
	"j5.nz/clustersh/internal/storage"
)

var configDir string

func main() {
	rootCmd := &cobra.Command{
		Use:   "clusteragent",
		Short: "ClusterSH Backend Agent",
		Long:  "Agent that connects to the coordinator and executes commands.",
		RunE:  runAgent,
	}

	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "Configuration directory (default: ~/.config/clustersh/agent)")

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a system service",
		RunE:  runInstall,
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall the system service",
		RunE:  runUninstall,
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show service status",
		RunE:  runStatus,
	}

	rootCmd.AddCommand(installCmd, uninstallCmd, statusCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getConfigDir() (string, error) {
	if configDir != "" {
		return configDir, nil
	}
	return storage.EnsureConfigDir("agent")
}

func runAgent(cmd *cobra.Command, args []string) error {
	dir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("get config directory: %w", err)
	}

	// Load config
	configPath := filepath.Join(dir, "config.json")
	var config storage.AgentConfig
	if err := storage.LoadJSON(configPath, &config); err != nil {
		return fmt.Errorf("load config: %w (run install script first)", err)
	}

	if config.CoordinatorURL == "" {
		return fmt.Errorf("coordinator_url not configured")
	}

	// Create agent
	ag, err := agent.New(&config, dir)
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}
	defer ag.Close()

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("Starting agent %s, connecting to %s", config.MachineName, config.CoordinatorURL)
	return ag.Run(ctx)
}

func runInstall(cmd *cobra.Command, args []string) error {
	// Get current executable path
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	if err := service.Install(exe); err != nil {
		return fmt.Errorf("install service: %w", err)
	}

	fmt.Println("Service installed successfully")
	return nil
}

func runUninstall(cmd *cobra.Command, args []string) error {
	if err := service.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}

	fmt.Println("Service uninstalled successfully")
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	status, err := service.Status()
	if err != nil {
		return err
	}

	fmt.Printf("Service status: %s\n", status)
	return nil
}
