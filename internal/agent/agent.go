// Package agent implements the backend agent logic.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/storage"
)

// MaxOutputSize is the maximum output size sent to coordinator (100KB).
const MaxOutputSize = 100 * 1024

// DefaultOutputLimit is the default limit for live output requests (10MB).
const DefaultOutputLimit = 10 * 1024 * 1024

// Agent represents the backend agent.
type Agent struct {
	config    *storage.AgentConfig
	configDir string
	conn      *websocket.Conn
	jobs      *storage.JobStore
	running   map[string]context.CancelFunc
	mu        sync.Mutex
}

// New creates a new agent.
func New(config *storage.AgentConfig, configDir string) (*Agent, error) {
	jobStore, err := storage.NewJobStore(configDir)
	if err != nil {
		return nil, fmt.Errorf("create job store: %w", err)
	}

	return &Agent{
		config:    config,
		configDir: configDir,
		jobs:      jobStore,
		running:   make(map[string]context.CancelFunc),
	}, nil
}

// Connect establishes a WebSocket connection to the coordinator.
func (a *Agent) Connect(ctx context.Context) error {
	wsURL := a.config.CoordinatorURL + "/ws/agent"
	// Convert http(s) to ws(s)
	if len(wsURL) > 4 && wsURL[:4] == "http" {
		wsURL = "ws" + wsURL[4:]
	}

	// Load CA certificate
	caCertPath := filepath.Join(a.configDir, "ca.crt")
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Load agent certificate and key for mTLS
	certPath := filepath.Join(a.configDir, "agent.crt")
	keyPath := filepath.Join(a.configDir, "agent.key")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load agent certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	a.conn = conn

	// Send registration
	reg := &protocol.RegisterPayload{
		MachineName: a.config.MachineName,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}

	msg, err := protocol.NewMessage(protocol.MsgRegister, reg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("create registration: %w", err)
	}

	if err := conn.WriteJSON(msg); err != nil {
		conn.Close()
		return fmt.Errorf("send registration: %w", err)
	}

	log.Printf("Connected to coordinator at %s", a.config.CoordinatorURL)
	return nil
}

// Run starts the agent main loop.
func (a *Agent) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if a.conn == nil {
			if err := a.Connect(ctx); err != nil {
				log.Printf("Connection failed: %v, retrying in 10 minutes", err)
				select {
				case <-time.After(10 * time.Minute):
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}
		}

		// Start heartbeat
		go a.heartbeat(ctx)

		// Read messages
		if err := a.readMessages(ctx); err != nil {
			log.Printf("Connection error: %v", err)
			a.conn.Close()
			a.conn = nil
			// Short delay before reconnect
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.conn == nil {
				return
			}

			a.mu.Lock()
			runningJobs := make([]string, 0, len(a.running))
			for jobID := range a.running {
				runningJobs = append(runningJobs, jobID)
			}
			a.mu.Unlock()

			status := &protocol.StatusPayload{
				MachineName: a.config.MachineName,
				RunningJobs: runningJobs,
			}

			msg, err := protocol.NewMessage(protocol.MsgStatus, status)
			if err != nil {
				continue
			}

			if err := a.conn.WriteJSON(msg); err != nil {
				log.Printf("Heartbeat failed: %v", err)
				return
			}
		}
	}
}

func (a *Agent) readMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var msg protocol.Message
		if err := a.conn.ReadJSON(&msg); err != nil {
			return fmt.Errorf("read message: %w", err)
		}

		switch msg.Type {
		case protocol.MsgExecute:
			var payload protocol.ExecutePayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("Failed to decode execute payload: %v", err)
				continue
			}
			go a.executeCommand(ctx, &payload)

		case protocol.MsgCancel:
			var payload protocol.CancelPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("Failed to decode cancel payload: %v", err)
				continue
			}
			a.cancelCommand(payload.JobID)

		case protocol.MsgStatus:
			// Heartbeat response, ignore

		case protocol.MsgGetOutput:
			var payload protocol.GetOutputPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("Failed to decode get_output payload: %v", err)
				continue
			}
			go a.handleGetOutput(&payload)

		default:
			log.Printf("Unknown message type: %s", msg.Type)
		}
	}
}

func (a *Agent) executeCommand(ctx context.Context, payload *protocol.ExecutePayload) {
	jobID := payload.JobID
	startedAt := time.Now()

	// Create cancellable context
	timeout := time.Duration(payload.Timeout)
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)

	a.mu.Lock()
	a.running[jobID] = cancel
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		delete(a.running, jobID)
		a.mu.Unlock()
		cancel()
	}()

	// Write files if any
	for _, file := range payload.Files {
		dir := filepath.Dir(file.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			a.sendResult(jobID, startedAt, -1, "", fmt.Sprintf("failed to create directory: %v", err))
			return
		}
		mode := os.FileMode(file.Mode)
		if mode == 0 {
			mode = 0644
		}
		if err := os.WriteFile(file.Path, file.Content, mode); err != nil {
			a.sendResult(jobID, startedAt, -1, "", fmt.Sprintf("failed to write file: %v", err))
			return
		}
	}

	// Create output file for streaming output
	outputPath := a.jobs.OutputPath(jobID)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		a.sendResult(jobID, startedAt, -1, "", fmt.Sprintf("failed to create output file: %v", err))
		return
	}

	// Save job as running so output file can be found
	runningJob := &storage.Job{
		JobID:     jobID,
		Machine:   a.config.MachineName,
		Command:   payload.Command,
		Status:    "running",
		CreatedAt: startedAt,
		StartedAt: startedAt,
	}
	if err := a.jobs.Save(runningJob); err != nil {
		log.Printf("Failed to save running job: %v", err)
	}

	// Execute command with output piped to file
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cmdCtx, "powershell", "-NoProfile", "-Command", payload.Command)
	} else {
		cmd = exec.CommandContext(cmdCtx, "bash", "-c", payload.Command)
	}

	cmd.Stdout = outputFile
	cmd.Stderr = outputFile

	err = cmd.Run()
	outputFile.Close()
	finishedAt := time.Now()

	exitCode := 0
	errMsg := ""
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			errMsg = err.Error()
		}
	}

	// Read output from file
	output, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		log.Printf("Failed to read output file: %v", readErr)
		output = []byte{}
	}

	// Truncate output if too large for sending
	outputStr := string(output)
	truncated := false
	if len(outputStr) > MaxOutputSize {
		outputStr = outputStr[:MaxOutputSize]
		truncated = true
	}

	// Save locally
	job := &storage.Job{
		JobID:      jobID,
		Machine:    a.config.MachineName,
		Command:    payload.Command,
		Status:     "completed",
		ExitCode:   exitCode,
		Output:     string(output), // Full output stored locally
		Truncated:  truncated,
		Error:      errMsg,
		CreatedAt:  startedAt,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
	}
	if err := a.jobs.Save(job); err != nil {
		log.Printf("Failed to save job locally: %v", err)
	}

	// Send result to coordinator
	a.sendResult(jobID, startedAt, exitCode, outputStr, errMsg)
	a.sendResultWithDetails(jobID, startedAt, finishedAt, exitCode, outputStr, truncated, errMsg)
}

func (a *Agent) sendResult(jobID string, startedAt time.Time, exitCode int, output, errMsg string) {
	// This is kept for compatibility, actual sending is done by sendResultWithDetails
}

func (a *Agent) sendResultWithDetails(jobID string, startedAt, finishedAt time.Time, exitCode int, output string, truncated bool, errMsg string) {
	result := &protocol.ResultPayload{
		JobID:      jobID,
		ExitCode:   exitCode,
		Output:     output,
		Truncated:  truncated,
		Error:      errMsg,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
	}

	msg, err := protocol.NewMessage(protocol.MsgResult, result)
	if err != nil {
		log.Printf("Failed to create result message: %v", err)
		return
	}

	if a.conn != nil {
		if err := a.conn.WriteJSON(msg); err != nil {
			log.Printf("Failed to send result: %v", err)
		}
	}
}

func (a *Agent) cancelCommand(jobID string) {
	a.mu.Lock()
	cancel, ok := a.running[jobID]
	a.mu.Unlock()

	if ok {
		cancel()
		log.Printf("Cancelled job: %s", jobID)
	}
}

func (a *Agent) handleGetOutput(payload *protocol.GetOutputPayload) {
	outputPath := a.jobs.OutputPath(payload.JobID)

	// Check if output file exists
	info, err := os.Stat(outputPath)
	if err != nil {
		a.sendOutputData(&protocol.OutputDataPayload{
			JobID:     payload.JobID,
			RequestID: payload.RequestID,
			Error:     fmt.Sprintf("output file not found: %v", err),
		})
		return
	}

	totalSize := info.Size()

	// Open file and seek to offset
	file, err := os.Open(outputPath)
	if err != nil {
		a.sendOutputData(&protocol.OutputDataPayload{
			JobID:     payload.JobID,
			RequestID: payload.RequestID,
			Error:     fmt.Sprintf("failed to open output file: %v", err),
		})
		return
	}
	defer file.Close()

	// Determine limit
	limit := payload.Limit
	if limit <= 0 {
		limit = DefaultOutputLimit
	}

	// Seek to offset
	offset := payload.Offset
	if offset > 0 {
		if _, err := file.Seek(offset, 0); err != nil {
			a.sendOutputData(&protocol.OutputDataPayload{
				JobID:     payload.JobID,
				RequestID: payload.RequestID,
				Error:     fmt.Sprintf("failed to seek: %v", err),
			})
			return
		}
	}

	// Read data
	buf := make([]byte, limit)
	n, err := file.Read(buf)
	if err != nil && err.Error() != "EOF" {
		a.sendOutputData(&protocol.OutputDataPayload{
			JobID:     payload.JobID,
			RequestID: payload.RequestID,
			Error:     fmt.Sprintf("failed to read output: %v", err),
		})
		return
	}

	hasMore := offset+int64(n) < totalSize

	a.sendOutputData(&protocol.OutputDataPayload{
		JobID:     payload.JobID,
		RequestID: payload.RequestID,
		Output:    string(buf[:n]),
		Offset:    offset,
		TotalSize: totalSize,
		HasMore:   hasMore,
	})
}

func (a *Agent) sendOutputData(payload *protocol.OutputDataPayload) {
	msg, err := protocol.NewMessage(protocol.MsgOutputData, payload)
	if err != nil {
		log.Printf("Failed to create output_data message: %v", err)
		return
	}

	if a.conn != nil {
		if err := a.conn.WriteJSON(msg); err != nil {
			log.Printf("Failed to send output_data: %v", err)
		}
	}
}

// Close closes the agent connection.
func (a *Agent) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}
