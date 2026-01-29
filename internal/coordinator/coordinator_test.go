package coordinator

import (
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/storage"
)

func TestCoordinator_ListMachines(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	// Initially empty
	machines := coord.ListMachines()
	if len(machines) != 0 {
		t.Errorf("ListMachines() = %d machines, want 0", len(machines))
	}
}

func TestCoordinator_RegisterAgent(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	// Create mock connection (will be nil in tests, but we handle that)
	reg := &protocol.RegisterPayload{
		MachineName: "test-machine",
		OS:          "linux",
		Arch:        "amd64",
	}

	agent, err := coord.RegisterAgent(nil, reg)
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	if agent.Name != "test-machine" {
		t.Errorf("Agent.Name = %s, want test-machine", agent.Name)
	}
	if agent.OS != "linux" {
		t.Errorf("Agent.OS = %s, want linux", agent.OS)
	}

	machines := coord.ListMachines()
	if len(machines) != 1 {
		t.Errorf("ListMachines() = %d machines, want 1", len(machines))
	}
}

func TestCoordinator_UnregisterAgent(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	reg := &protocol.RegisterPayload{
		MachineName: "test-machine",
		OS:          "linux",
		Arch:        "amd64",
	}

	coord.RegisterAgent(nil, reg)
	coord.UnregisterAgent("test-machine")

	machines := coord.ListMachines()
	if len(machines) != 1 {
		t.Fatalf("Expected 1 machine, got %d", len(machines))
	}

	// Machine should be marked as disconnected
	if machines[0].Connected {
		t.Error("Machine should be disconnected")
	}
}

func TestCoordinator_GetOutput(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	// Create a job directly in storage
	job := &storage.Job{
		JobID:      "test-job",
		Machine:    "test-machine",
		Command:    "echo hello",
		Status:     "completed",
		ExitCode:   0,
		Output:     "hello\n",
		CreatedAt:  time.Now(),
		FinishedAt: time.Now(),
	}
	jobStore.Save(job)

	output, err := coord.GetOutput("test-job")
	if err != nil {
		t.Fatalf("GetOutput() error = %v", err)
	}

	if output.JobID != "test-job" {
		t.Errorf("JobID = %s, want test-job", output.JobID)
	}
	if output.Output != "hello\n" {
		t.Errorf("Output = %s, want hello\\n", output.Output)
	}
	if output.Status != "completed" {
		t.Errorf("Status = %s, want completed", output.Status)
	}
}

func TestCoordinator_GetHistory(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	// Create jobs
	jobs := []*storage.Job{
		{JobID: "job-1", Machine: "machine-a", Command: "cmd1", Status: "completed", CreatedAt: time.Now()},
		{JobID: "job-2", Machine: "machine-a", Command: "cmd2", Status: "completed", CreatedAt: time.Now()},
		{JobID: "job-3", Machine: "machine-b", Command: "cmd3", Status: "completed", CreatedAt: time.Now()},
	}
	for _, job := range jobs {
		jobStore.Save(job)
	}

	history, err := coord.GetHistory("machine-a")
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if len(history) != 2 {
		t.Errorf("GetHistory() = %d entries, want 2", len(history))
	}
}

func TestCoordinator_HandleResult(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := New(jobStore, nil)

	// Create a running job
	job := &storage.Job{
		JobID:     "running-job",
		Machine:   "test-machine",
		Command:   "echo test",
		Status:    "running",
		CreatedAt: time.Now(),
		StartedAt: time.Now(),
	}
	jobStore.Save(job)

	// Handle result
	result := &protocol.ResultPayload{
		JobID:      "running-job",
		ExitCode:   0,
		Output:     "test\n",
		Truncated:  false,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}

	if err := coord.HandleResult("test-machine", result); err != nil {
		t.Fatalf("HandleResult() error = %v", err)
	}

	// Verify job was updated
	output, err := coord.GetOutput("running-job")
	if err != nil {
		t.Fatalf("GetOutput() error = %v", err)
	}

	if output.Status != "completed" {
		t.Errorf("Status = %s, want completed", output.Status)
	}
	if output.Output != "test\n" {
		t.Errorf("Output = %s, want test\\n", output.Output)
	}
}

// MockWebSocketConn is a mock for websocket.Conn for testing
type MockWebSocketConn struct {
	*websocket.Conn
	writtenMessages []interface{}
}
