// Package coordinator implements the central coordinator logic.
package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/storage"
)

// MaxOutputSize is the maximum output size stored in job results (100KB).
const MaxOutputSize = 100 * 1024

// Agent represents a connected agent.
type Agent struct {
	Name        string
	OS          string
	Arch        string
	Conn        *websocket.Conn
	Connected   bool
	LastSeen    time.Time
	RunningJobs map[string]bool
	mu          sync.Mutex
}

// Coordinator manages agents and job dispatch.
type Coordinator struct {
	agents   map[string]*Agent
	jobs     *storage.JobStore
	audit    *storage.AuditLog
	mu       sync.RWMutex
	onResult func(jobID string, result *protocol.ResultPayload)
}

// New creates a new coordinator.
func New(jobStore *storage.JobStore, auditLog *storage.AuditLog) *Coordinator {
	return &Coordinator{
		agents: make(map[string]*Agent),
		jobs:   jobStore,
		audit:  auditLog,
	}
}

// SetResultCallback sets a callback for job results.
func (c *Coordinator) SetResultCallback(cb func(jobID string, result *protocol.ResultPayload)) {
	c.onResult = cb
}

// RegisterAgent registers a new agent connection.
func (c *Coordinator) RegisterAgent(conn *websocket.Conn, reg *protocol.RegisterPayload) (*Agent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	agent := &Agent{
		Name:        reg.MachineName,
		OS:          reg.OS,
		Arch:        reg.Arch,
		Conn:        conn,
		Connected:   true,
		LastSeen:    time.Now(),
		RunningJobs: make(map[string]bool),
	}

	c.agents[reg.MachineName] = agent

	if c.audit != nil {
		c.audit.LogAgentConnect(reg.MachineName)
	}

	log.Printf("Agent registered: %s (%s/%s)", reg.MachineName, reg.OS, reg.Arch)
	return agent, nil
}

// UnregisterAgent removes an agent connection.
func (c *Coordinator) UnregisterAgent(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if agent, ok := c.agents[name]; ok {
		agent.mu.Lock()
		agent.Connected = false
		agent.mu.Unlock()

		if c.audit != nil {
			c.audit.LogAgentDisconnect(name)
		}

		log.Printf("Agent disconnected: %s", name)
	}
}

// GetAgent returns an agent by name.
func (c *Coordinator) GetAgent(name string) *Agent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.agents[name]
}

// ListMachines returns all known machines.
func (c *Coordinator) ListMachines() []protocol.Machine {
	c.mu.RLock()
	defer c.mu.RUnlock()

	machines := make([]protocol.Machine, 0, len(c.agents))
	for _, agent := range c.agents {
		agent.mu.Lock()
		machines = append(machines, protocol.Machine{
			Name:        agent.Name,
			OS:          agent.OS,
			Arch:        agent.Arch,
			Connected:   agent.Connected,
			LastSeen:    agent.LastSeen,
			RunningJobs: len(agent.RunningJobs),
		})
		agent.mu.Unlock()
	}
	return machines
}

// ExecuteCommand sends a command to an agent.
func (c *Coordinator) ExecuteCommand(ctx context.Context, client string, req *protocol.RunRequest) (string, error) {
	agent := c.GetAgent(req.Machine)
	if agent == nil {
		return "", fmt.Errorf("machine not found: %s", req.Machine)
	}

	agent.mu.Lock()
	if !agent.Connected {
		agent.mu.Unlock()
		return "", fmt.Errorf("machine not connected: %s", req.Machine)
	}
	agent.mu.Unlock()

	jobID := uuid.New().String()

	job := &storage.Job{
		JobID:     jobID,
		Machine:   req.Machine,
		Command:   req.Command,
		Files:     req.Files,
		Timeout:   req.Timeout,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	if err := c.jobs.Save(job); err != nil {
		return "", fmt.Errorf("save job: %w", err)
	}

	payload := &protocol.ExecutePayload{
		JobID:   jobID,
		Command: req.Command,
		Files:   req.Files,
		Timeout: req.Timeout,
	}

	msg, err := protocol.NewMessage(protocol.MsgExecute, payload)
	if err != nil {
		return "", fmt.Errorf("create message: %w", err)
	}

	agent.mu.Lock()
	err = agent.Conn.WriteJSON(msg)
	if err != nil {
		agent.mu.Unlock()
		return "", fmt.Errorf("send command: %w", err)
	}
	agent.RunningJobs[jobID] = true
	agent.mu.Unlock()

	job.Status = "running"
	job.StartedAt = time.Now()
	c.jobs.Save(job)

	if c.audit != nil {
		c.audit.LogCommand(client, req.Machine, jobID, req.Command)
	}

	return jobID, nil
}

// CancelCommand sends a cancel request to an agent.
func (c *Coordinator) CancelCommand(client, jobID string) error {
	job, err := c.jobs.Load(jobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.Status != "running" && job.Status != "pending" {
		return fmt.Errorf("job not cancellable: %s", job.Status)
	}

	agent := c.GetAgent(job.Machine)
	if agent == nil || !agent.Connected {
		job.Status = "cancelled"
		job.FinishedAt = time.Now()
		c.jobs.Save(job)
		return nil
	}

	payload := &protocol.CancelPayload{JobID: jobID}
	msg, err := protocol.NewMessage(protocol.MsgCancel, payload)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}

	agent.mu.Lock()
	err = agent.Conn.WriteJSON(msg)
	agent.mu.Unlock()

	if err != nil {
		return fmt.Errorf("send cancel: %w", err)
	}

	if c.audit != nil {
		c.audit.LogCancel(client, job.Machine, jobID)
	}

	return nil
}

// HandleResult processes a job result from an agent.
func (c *Coordinator) HandleResult(agentName string, result *protocol.ResultPayload) error {
	job, err := c.jobs.Load(result.JobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", result.JobID)
	}

	output := result.Output
	truncated := result.Truncated
	if len(output) > MaxOutputSize {
		output = output[:MaxOutputSize]
		truncated = true
	}

	job.Status = "completed"
	job.ExitCode = result.ExitCode
	job.Output = output
	job.Truncated = truncated
	job.Error = result.Error
	job.StartedAt = result.StartedAt
	job.FinishedAt = result.FinishedAt

	if result.Error != "" {
		job.Status = "failed"
	}

	if err := c.jobs.Save(job); err != nil {
		return fmt.Errorf("save job: %w", err)
	}

	agent := c.GetAgent(agentName)
	if agent != nil {
		agent.mu.Lock()
		delete(agent.RunningJobs, result.JobID)
		agent.mu.Unlock()
	}

	if c.onResult != nil {
		c.onResult(result.JobID, result)
	}

	return nil
}

// GetOutput returns job output.
func (c *Coordinator) GetOutput(jobID string) (*protocol.JobOutput, error) {
	job, err := c.jobs.Load(jobID)
	if err != nil {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return &protocol.JobOutput{
		JobID:      job.JobID,
		Machine:    job.Machine,
		Command:    job.Command,
		ExitCode:   job.ExitCode,
		Output:     job.Output,
		Truncated:  job.Truncated,
		Error:      job.Error,
		Status:     job.Status,
		StartedAt:  job.StartedAt,
		FinishedAt: job.FinishedAt,
		CreatedAt:  job.CreatedAt,
	}, nil
}

// GetHistory returns command history for a machine.
func (c *Coordinator) GetHistory(machine string) ([]protocol.HistoryEntry, error) {
	return c.jobs.History(machine)
}

// UpdateAgentStatus updates an agent's last seen time.
func (c *Coordinator) UpdateAgentStatus(name string) {
	agent := c.GetAgent(name)
	if agent != nil {
		agent.mu.Lock()
		agent.LastSeen = time.Now()
		agent.mu.Unlock()
	}
}

// HandleAgentMessage processes a message from an agent.
func (c *Coordinator) HandleAgentMessage(agentName string, msg *protocol.Message) error {
	switch msg.Type {
	case protocol.MsgResult:
		var result protocol.ResultPayload
		if err := json.Unmarshal(msg.Payload, &result); err != nil {
			return fmt.Errorf("decode result: %w", err)
		}
		return c.HandleResult(agentName, &result)

	case protocol.MsgStatus:
		c.UpdateAgentStatus(agentName)
		return nil

	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}
