package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"j5.nz/clustersh/internal/protocol"
)

// JobStore manages job storage.
type JobStore struct {
	dir string
}

// NewJobStore creates a new job store in the given directory.
func NewJobStore(dir string) (*JobStore, error) {
	jobsDir := filepath.Join(dir, "jobs")
	if err := os.MkdirAll(jobsDir, 0700); err != nil {
		return nil, fmt.Errorf("create jobs directory: %w", err)
	}
	return &JobStore{dir: jobsDir}, nil
}

// Job represents a stored job.
type Job struct {
	JobID      string            `json:"job_id"`
	Machine    string            `json:"machine"`
	Command    string            `json:"command"`
	Files      []protocol.File   `json:"files,omitempty"`
	Timeout    protocol.Duration `json:"timeout,omitempty"`
	Status     string            `json:"status"` // pending, running, completed, cancelled, failed
	ExitCode   int               `json:"exit_code"`
	Output     string            `json:"output"`
	Truncated  bool              `json:"truncated"`
	Error      string            `json:"error,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	StartedAt  time.Time         `json:"started_at,omitempty"`
	FinishedAt time.Time         `json:"finished_at,omitempty"`
}

// Save persists a job to disk.
func (s *JobStore) Save(job *Job) error {
	path := filepath.Join(s.dir, job.JobID+".json")
	return SaveJSON(path, job)
}

// Load retrieves a job by ID.
func (s *JobStore) Load(jobID string) (*Job, error) {
	path := filepath.Join(s.dir, jobID+".json")
	var job Job
	if err := LoadJSON(path, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// Delete removes a job.
func (s *JobStore) Delete(jobID string) error {
	path := filepath.Join(s.dir, jobID+".json")
	return os.Remove(path)
}

// List returns all jobs, optionally filtered by machine.
func (s *JobStore) List(machine string) ([]*Job, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var jobs []*Job
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		jobID := entry.Name()[:len(entry.Name())-5] // Remove .json
		job, err := s.Load(jobID)
		if err != nil {
			continue // Skip invalid jobs
		}

		if machine == "" || job.Machine == machine {
			jobs = append(jobs, job)
		}
	}

	// Sort by creation time, newest first
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt.After(jobs[j].CreatedAt)
	})

	return jobs, nil
}

// ListByStatus returns jobs with the given status.
func (s *JobStore) ListByStatus(status string) ([]*Job, error) {
	all, err := s.List("")
	if err != nil {
		return nil, err
	}

	var filtered []*Job
	for _, job := range all {
		if job.Status == status {
			filtered = append(filtered, job)
		}
	}
	return filtered, nil
}

// History returns history entries for a machine.
func (s *JobStore) History(machine string) ([]protocol.HistoryEntry, error) {
	jobs, err := s.List(machine)
	if err != nil {
		return nil, err
	}

	entries := make([]protocol.HistoryEntry, len(jobs))
	for i, job := range jobs {
		entries[i] = protocol.HistoryEntry{
			JobID:     job.JobID,
			Command:   job.Command,
			Status:    job.Status,
			ExitCode:  job.ExitCode,
			CreatedAt: job.CreatedAt,
		}
	}
	return entries, nil
}
