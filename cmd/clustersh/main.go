// Package main implements the clustersh frontend CLI.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"j5.nz/clustersh/internal/client"
	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/storage"
)

var (
	configDir      string
	timeout        time.Duration
	files          []string
	waitForApproval bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "clustersh",
		Short: "ClusterSH Frontend CLI",
		Long:  "Command-line interface for executing commands on remote machines.",
	}

	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "Configuration directory (default: ~/.config/clustersh/client)")

	machinesCmd := &cobra.Command{
		Use:   "machines",
		Short: "List connected machines",
		RunE:  runMachines,
	}

	runCmd := &cobra.Command{
		Use:   "run <machine> <command>",
		Short: "Execute a command on a machine",
		Args:  cobra.MinimumNArgs(2),
		RunE:  runRun,
	}
	runCmd.Flags().StringArrayVarP(&files, "file", "f", nil, "File to transfer (format: local:remote)")
	runCmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Minute, "Command timeout")

	catCmd := &cobra.Command{
		Use:   "cat <uuid>",
		Short: "Retrieve full output of a command",
		Args:  cobra.ExactArgs(1),
		RunE:  runCat,
	}

	historyCmd := &cobra.Command{
		Use:   "history <machine>",
		Short: "Show command history for a machine",
		Args:  cobra.ExactArgs(1),
		RunE:  runHistory,
	}

	cancelCmd := &cobra.Command{
		Use:   "cancel <uuid>",
		Short: "Cancel a running command",
		Args:  cobra.ExactArgs(1),
		RunE:  runCancel,
	}

	loginCmd := &cobra.Command{
		Use:   "login <url>",
		Short: "Generate keypair and request access",
		Args:  cobra.ExactArgs(1),
		RunE:  runLogin,
	}
	loginCmd.Flags().BoolVarP(&waitForApproval, "wait", "w", false, "Wait for approval")

	rootCmd.AddCommand(machinesCmd, runCmd, catCmd, historyCmd, cancelCmd, loginCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getClient() (*client.Client, error) {
	dir := configDir
	if dir == "" {
		var err error
		dir, err = storage.EnsureConfigDir("client")
		if err != nil {
			return nil, fmt.Errorf("get config directory: %w", err)
		}
	}

	configPath := filepath.Join(dir, "config.json")
	config := storage.DefaultClientConfig()
	_ = storage.LoadJSON(configPath, config) // Ignore error, use defaults if file doesn't exist

	return client.New(config, dir)
}

func runMachines(cmd *cobra.Command, args []string) error {
	c, err := getClient()
	if err != nil {
		return err
	}

	machines, err := c.Machines()
	if err != nil {
		return fmt.Errorf("list machines: %w", err)
	}

	if len(machines) == 0 {
		fmt.Println("No machines connected")
		return nil
	}

	fmt.Printf("%-20s %-10s %-10s %-10s %-8s %s\n", "NAME", "OS", "ARCH", "STATUS", "JOBS", "LAST SEEN")
	for _, m := range machines {
		status := "offline"
		if m.Connected {
			status = "online"
		}
		lastSeen := m.LastSeen.Format("15:04:05")
		if time.Since(m.LastSeen) > 24*time.Hour {
			lastSeen = m.LastSeen.Format("2006-01-02")
		}
		fmt.Printf("%-20s %-10s %-10s %-10s %-8d %s\n", m.Name, m.OS, m.Arch, status, m.RunningJobs, lastSeen)
	}

	return nil
}

func runRun(cmd *cobra.Command, args []string) error {
	c, err := getClient()
	if err != nil {
		return err
	}

	machine := args[0]
	command := strings.Join(args[1:], " ")

	// Parse file transfers
	var fileTransfers []protocol.File
	for _, f := range files {
		parts := strings.SplitN(f, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid file format: %s (use local:remote)", f)
		}

		localPath := parts[0]
		remotePath := parts[1]

		content, err := os.ReadFile(localPath)
		if err != nil {
			return fmt.Errorf("read file %s: %w", localPath, err)
		}

		info, err := os.Stat(localPath)
		if err != nil {
			return fmt.Errorf("stat file %s: %w", localPath, err)
		}

		fileTransfers = append(fileTransfers, protocol.File{
			Path:    remotePath,
			Content: content,
			Mode:    uint32(info.Mode()),
		})
	}

	jobID, err := c.Run(machine, command, fileTransfers, timeout)
	if err != nil {
		return fmt.Errorf("run command: %w", err)
	}

	fmt.Printf("Job started: %s\n", jobID)

	// Poll for result
	for {
		output, err := c.Output(jobID)
		if err != nil {
			return fmt.Errorf("get output: %w", err)
		}

		if output.Status == "completed" || output.Status == "failed" || output.Status == "cancelled" {
			if output.Output != "" {
				fmt.Print(output.Output)
				if !strings.HasSuffix(output.Output, "\n") {
					fmt.Println()
				}
			}
			if output.Truncated {
				fmt.Printf("\n[Output truncated. Use 'clustersh cat %s' to retrieve full output from agent]\n", jobID)
			}
			if output.Error != "" {
				fmt.Printf("Error: %s\n", output.Error)
			}
			if output.Status != "completed" || output.ExitCode != 0 {
				fmt.Printf("Exit code: %d\n", output.ExitCode)
				os.Exit(output.ExitCode)
			}
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func runCat(cmd *cobra.Command, args []string) error {
	c, err := getClient()
	if err != nil {
		return err
	}

	jobID := args[0]
	output, err := c.Output(jobID)
	if err != nil {
		return fmt.Errorf("get output: %w", err)
	}

	fmt.Print(output.Output)
	return nil
}

func runHistory(cmd *cobra.Command, args []string) error {
	c, err := getClient()
	if err != nil {
		return err
	}

	machine := args[0]
	history, err := c.History(machine)
	if err != nil {
		return fmt.Errorf("get history: %w", err)
	}

	if len(history) == 0 {
		fmt.Println("No command history")
		return nil
	}

	fmt.Printf("%-36s %-12s %-6s %s\n", "JOB ID", "STATUS", "EXIT", "COMMAND")
	for _, h := range history {
		command := h.Command
		if len(command) > 40 {
			command = command[:37] + "..."
		}
		fmt.Printf("%-36s %-12s %-6d %s\n", h.JobID, h.Status, h.ExitCode, command)
	}

	return nil
}

func runCancel(cmd *cobra.Command, args []string) error {
	c, err := getClient()
	if err != nil {
		return err
	}

	jobID := args[0]
	if err := c.Cancel(jobID); err != nil {
		return fmt.Errorf("cancel command: %w", err)
	}

	fmt.Printf("Cancelled: %s\n", jobID)
	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	dir := configDir
	if dir == "" {
		var err error
		dir, err = storage.EnsureConfigDir("client")
		if err != nil {
			return fmt.Errorf("get config directory: %w", err)
		}
	}

	config := storage.DefaultClientConfig()
	c, err := client.New(config, dir)
	if err != nil {
		return err
	}

	coordinatorURL := args[0]
	fingerprint, err := c.Login(coordinatorURL)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	if fingerprint == "" {
		fmt.Println("Login successful! Certificate saved.")
		return nil
	}

	fmt.Println("Login request submitted.")
	fmt.Println()
	fmt.Printf("Your fingerprint: %s\n", fingerprint)
	fmt.Println()
	fmt.Println("Ask an administrator to run:")
	fmt.Printf("  clusterd approve %s\n", fingerprint)

	if waitForApproval {
		fmt.Println()
		fmt.Println("Waiting for approval...")
		if err := c.WaitForApproval(fingerprint, 10*time.Minute); err != nil {
			return fmt.Errorf("wait for approval: %w", err)
		}
		fmt.Println("Approved! Certificate saved.")
	} else {
		fmt.Println()
		fmt.Println("Then run this command again to complete login.")
	}

	return nil
}
