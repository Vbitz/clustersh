package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry represents a logged action.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Client    string    `json:"client,omitempty"`
	Machine   string    `json:"machine,omitempty"`
	JobID     string    `json:"job_id,omitempty"`
	Command   string    `json:"command,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// AuditLog handles audit logging to a file.
type AuditLog struct {
	path string
	mu   sync.Mutex
	file *os.File
}

// NewAuditLog creates a new audit log.
func NewAuditLog(path string) (*AuditLog, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &AuditLog{
		path: path,
		file: file,
	}, nil
}

// Log writes an entry to the audit log.
func (a *AuditLog) Log(entry AuditEntry) error {
	entry.Timestamp = time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	_, err = a.file.Write(append(data, '\n'))
	return err
}

// Close closes the audit log file.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// LogCommand logs a command execution.
func (a *AuditLog) LogCommand(client, machine, jobID, command string) error {
	return a.Log(AuditEntry{
		Action:  "execute",
		Client:  client,
		Machine: machine,
		JobID:   jobID,
		Command: command,
	})
}

// LogCancel logs a command cancellation.
func (a *AuditLog) LogCancel(client, machine, jobID string) error {
	return a.Log(AuditEntry{
		Action:  "cancel",
		Client:  client,
		Machine: machine,
		JobID:   jobID,
	})
}

// LogApprove logs a client approval.
func (a *AuditLog) LogApprove(fingerprint, name string) error {
	return a.Log(AuditEntry{
		Action:  "approve",
		Client:  fingerprint,
		Details: name,
	})
}

// LogAgentConnect logs an agent connection.
func (a *AuditLog) LogAgentConnect(machine string) error {
	return a.Log(AuditEntry{
		Action:  "agent_connect",
		Machine: machine,
	})
}

// LogAgentDisconnect logs an agent disconnection.
func (a *AuditLog) LogAgentDisconnect(machine string) error {
	return a.Log(AuditEntry{
		Action:  "agent_disconnect",
		Machine: machine,
	})
}
