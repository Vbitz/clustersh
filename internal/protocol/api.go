package protocol

import "time"

// Machine represents a connected agent machine.
type Machine struct {
	Name        string    `json:"name"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Connected   bool      `json:"connected"`
	LastSeen    time.Time `json:"last_seen"`
	RunningJobs int       `json:"running_jobs"`
}

// RunRequest is the request body for POST /run.
type RunRequest struct {
	Machine string   `json:"machine"`
	Command string   `json:"command"`
	Files   []File   `json:"files,omitempty"`
	Timeout Duration `json:"timeout,omitempty"`
}

// RunResponse is the response for POST /run.
type RunResponse struct {
	JobID string `json:"job_id"`
}

// JobOutput represents command output returned by GET /output/{uuid}.
type JobOutput struct {
	JobID      string    `json:"job_id"`
	Machine    string    `json:"machine"`
	Command    string    `json:"command"`
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Truncated  bool      `json:"truncated"`
	Error      string    `json:"error,omitempty"`
	Status     string    `json:"status"` // pending, running, completed, cancelled, failed
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// HistoryEntry represents a command in history.
type HistoryEntry struct {
	JobID     string    `json:"job_id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginRequest is the request body for POST /login.
type LoginRequest struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Signature   string `json:"signature"`
	Timestamp   int64  `json:"timestamp"`
}

// LoginResponse is the response for POST /login.
type LoginResponse struct {
	Status      string `json:"status"` // pending, approved
	Certificate string `json:"certificate,omitempty"`
	Message     string `json:"message,omitempty"`
}

// ApproveRequest is the request body for POST /approve/{fingerprint}.
type ApproveRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// APIError is the standard error response format.
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// CSRRequest is used by agents to request a signed certificate.
type CSRRequest struct {
	CSR         string `json:"csr"`
	MachineName string `json:"machine_name"`
}

// CSRResponse contains the signed certificate.
type CSRResponse struct {
	Certificate string `json:"certificate"`
	CACert      string `json:"ca_cert"`
}
