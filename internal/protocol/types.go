// Package protocol defines shared types and WebSocket protocol messages.
package protocol

import (
	"encoding/json"
	"time"
)

// MessageType identifies the type of WebSocket message.
type MessageType string

const (
	// Coordinator to Agent messages
	MsgExecute MessageType = "execute"
	MsgCancel  MessageType = "cancel"

	// Agent to Coordinator messages
	MsgResult   MessageType = "result"
	MsgRegister MessageType = "register"

	// Bidirectional messages
	MsgStatus MessageType = "status"
	MsgError  MessageType = "error"
)

// Message is the envelope for all WebSocket messages.
type Message struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// ExecutePayload is sent from coordinator to agent to run a command.
type ExecutePayload struct {
	JobID   string   `json:"job_id"`
	Command string   `json:"command"`
	Files   []File   `json:"files,omitempty"`
	Timeout Duration `json:"timeout,omitempty"`
}

// File represents a file to be transferred to the agent before execution.
type File struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	Mode    uint32 `json:"mode"`
}

// CancelPayload is sent from coordinator to agent to cancel a job.
type CancelPayload struct {
	JobID string `json:"job_id"`
}

// ResultPayload is sent from agent to coordinator with job results.
type ResultPayload struct {
	JobID      string    `json:"job_id"`
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// RegisterPayload is sent from agent to coordinator on connection.
type RegisterPayload struct {
	MachineName string `json:"machine_name"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

// StatusPayload is used for heartbeats and status updates.
type StatusPayload struct {
	MachineName  string   `json:"machine_name,omitempty"`
	RunningJobs  []string `json:"running_jobs,omitempty"`
	LastSeen     string   `json:"last_seen,omitempty"`
	AgentVersion string   `json:"agent_version,omitempty"`
}

// ErrorPayload is sent when an error occurs.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Duration wraps time.Duration for JSON marshaling.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
	case string:
		dur, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(dur)
	}
	return nil
}

// NewMessage creates a new message with the given type and payload.
func NewMessage(msgType MessageType, payload interface{}) (*Message, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    msgType,
		Payload: data,
	}, nil
}

// DecodePayload decodes the message payload into the given type.
func (m *Message) DecodePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}
