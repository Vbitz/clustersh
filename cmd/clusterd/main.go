// Package main implements the clusterd coordinator daemon.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"j5.nz/clustersh/internal/api"
	"j5.nz/clustersh/internal/coordinator"
	"j5.nz/clustersh/internal/security"
	"j5.nz/clustersh/internal/storage"
)

var (
	configDir string
	listenAddr string
	port       int
	noTLS      bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "clusterd",
		Short: "ClusterSH Coordinator Daemon",
		Long:  "Coordinator daemon for managing remote agents and dispatching commands.",
		RunE:  runDaemon,
	}

	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "Configuration directory (default: ~/.config/clustersh/coordinator)")
	rootCmd.PersistentFlags().StringVar(&listenAddr, "listen", "", "Listen address (default: 0.0.0.0)")
	rootCmd.PersistentFlags().IntVar(&port, "port", 0, "Listen port (default: 5672)")
	rootCmd.PersistentFlags().BoolVar(&noTLS, "no-tls", false, "Disable TLS (for development only)")

	approveCmd := &cobra.Command{
		Use:   "approve <fingerprint> [name]",
		Short: "Approve a pending client login",
		Args:  cobra.RangeArgs(1, 2),
		RunE:  runApprove,
	}

	pendingCmd := &cobra.Command{
		Use:   "pending",
		Short: "List pending login requests",
		RunE:  runPending,
	}

	rootCmd.AddCommand(approveCmd, pendingCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getConfigDir() (string, error) {
	if configDir != "" {
		return configDir, nil
	}
	return storage.EnsureConfigDir("coordinator")
}

func runDaemon(cmd *cobra.Command, args []string) error {
	dir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("get config directory: %w", err)
	}

	// Load or create config
	configPath := filepath.Join(dir, "config.json")
	config := storage.DefaultCoordinatorConfig()
	if err := storage.LoadJSON(configPath, config); err != nil {
		storage.SaveJSON(configPath, config)
	}

	// Override with flags
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}
	if port != 0 {
		config.Port = port
	}

	// Load or create CA
	caKeyPath := filepath.Join(dir, "ca.key")
	caCertPath := filepath.Join(dir, "ca.crt")

	var ca *security.CA
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		log.Println("Generating new CA...")
		ca, err = security.NewCA()
		if err != nil {
			return fmt.Errorf("create CA: %w", err)
		}
		if err := ca.SaveToFiles(caCertPath, caKeyPath); err != nil {
			return fmt.Errorf("save CA: %w", err)
		}
		log.Println("CA created successfully")
	} else {
		ca, err = security.LoadCAFromFiles(caCertPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
	}

	// Create server certificate
	serverKeyPath := filepath.Join(dir, "server.key")
	serverCertPath := filepath.Join(dir, "server.crt")

	var serverKeyPair *security.KeyPair
	if _, err := os.Stat(serverKeyPath); os.IsNotExist(err) {
		log.Println("Generating server certificate...")
		serverKeyPair, err = security.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate server key: %w", err)
		}

		csr, err := serverKeyPair.GenerateCSR("clusterd")
		if err != nil {
			return fmt.Errorf("generate CSR: %w", err)
		}

		certPEM, err := ca.SignCSR(csr, 365*24*time.Hour)
		if err != nil {
			return fmt.Errorf("sign certificate: %w", err)
		}

		serverKeyPair.SetCertificate(certPEM)
		if err := serverKeyPair.SaveToFiles(serverKeyPath, serverCertPath); err != nil {
			return fmt.Errorf("save server certificate: %w", err)
		}
	} else {
		serverKeyPair, err = security.LoadKeyPairFromFiles(serverKeyPath, serverCertPath)
		if err != nil {
			return fmt.Errorf("load server certificate: %w", err)
		}
	}

	// Create job store
	jobStore, err := storage.NewJobStore(dir)
	if err != nil {
		return fmt.Errorf("create job store: %w", err)
	}

	// Create audit log
	auditPath := filepath.Join(dir, "audit.log")
	auditLog, err := storage.NewAuditLog(auditPath)
	if err != nil {
		return fmt.Errorf("create audit log: %w", err)
	}
	defer auditLog.Close()

	// Create coordinator
	coord := coordinator.New(jobStore, auditLog)

	// Create auth manager
	authManager, err := coordinator.NewAuthManager(ca, dir)
	if err != nil {
		return fmt.Errorf("create auth manager: %w", err)
	}

	// Create API server
	apiServer := api.NewServer(coord, authManager)

	// Set up HTTP server
	addr := fmt.Sprintf("%s:%d", config.ListenAddr, config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: apiServer.Handler(),
	}

	if !noTLS {
		tlsConfig, err := security.NewServerTLSConfig(ca, serverKeyPair)
		if err != nil {
			return fmt.Errorf("create TLS config: %w", err)
		}
		// Allow unauthenticated clients for /login, /ca.crt, /agent/csr
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		server.TLSConfig = tlsConfig
	}

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		server.Shutdown(context.Background())
	}()

	log.Printf("Starting coordinator on %s", addr)
	if noTLS {
		log.Println("WARNING: TLS disabled - for development only!")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			return err
		}
	} else {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			return err
		}
	}

	<-ctx.Done()
	return nil
}

func runApprove(cmd *cobra.Command, args []string) error {
	dir, err := getConfigDir()
	if err != nil {
		return err
	}

	fingerprint := args[0]
	name := "client-" + fingerprint[:8]
	if len(args) > 1 {
		name = args[1]
	}

	// Load CA for auth manager
	caKeyPath := filepath.Join(dir, "ca.key")
	caCertPath := filepath.Join(dir, "ca.crt")
	ca, err := security.LoadCAFromFiles(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	authManager, err := coordinator.NewAuthManager(ca, dir)
	if err != nil {
		return err
	}

	if err := authManager.Approve(fingerprint, name); err != nil {
		return err
	}

	fmt.Printf("Approved client %s as %s\n", fingerprint, name)
	return nil
}

func runPending(cmd *cobra.Command, args []string) error {
	dir, err := getConfigDir()
	if err != nil {
		return err
	}

	// Load pending logins
	var pending storage.PendingLogins
	pendingPath := filepath.Join(dir, "pending_logins.json")
	if err := storage.LoadJSON(pendingPath, &pending); err != nil {
		fmt.Println("No pending login requests")
		return nil
	}

	if len(pending.Logins) == 0 {
		fmt.Println("No pending login requests")
		return nil
	}

	fmt.Println("Pending login requests:")
	fmt.Println()
	for _, login := range pending.Logins {
		fmt.Printf("  Fingerprint: %s\n", login.Fingerprint)
		fmt.Printf("  Requested:   %s\n", login.RequestedAt.Format(time.RFC3339))
		fmt.Printf("  Approve:     clusterd approve %s\n", login.Fingerprint)
		fmt.Println()
	}

	return nil
}
