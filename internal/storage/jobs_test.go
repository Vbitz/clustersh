package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJobStore(t *testing.T) {
	// Create temp directory
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := NewJobStore(dir)
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	// Test Save and Load
	job := &Job{
		JobID:     "test-job-1",
		Machine:   "test-machine",
		Command:   "echo hello",
		Status:    "completed",
		ExitCode:  0,
		Output:    "hello\n",
		CreatedAt: time.Now(),
	}

	if err := store.Save(job); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-job-1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.JobID != job.JobID {
		t.Errorf("JobID = %s, want %s", loaded.JobID, job.JobID)
	}
	if loaded.Command != job.Command {
		t.Errorf("Command = %s, want %s", loaded.Command, job.Command)
	}
	if loaded.Output != job.Output {
		t.Errorf("Output = %s, want %s", loaded.Output, job.Output)
	}
}

func TestJobStore_List(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := NewJobStore(dir)
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	// Create multiple jobs
	jobs := []*Job{
		{JobID: "job-1", Machine: "machine-a", Command: "cmd1", Status: "completed", CreatedAt: time.Now().Add(-2 * time.Hour)},
		{JobID: "job-2", Machine: "machine-a", Command: "cmd2", Status: "running", CreatedAt: time.Now().Add(-1 * time.Hour)},
		{JobID: "job-3", Machine: "machine-b", Command: "cmd3", Status: "completed", CreatedAt: time.Now()},
	}

	for _, job := range jobs {
		if err := store.Save(job); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// List all
	all, err := store.List("")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(all) != 3 {
		t.Errorf("List() returned %d jobs, want 3", len(all))
	}

	// List by machine
	machineA, err := store.List("machine-a")
	if err != nil {
		t.Fatalf("List(machine-a) error = %v", err)
	}
	if len(machineA) != 2 {
		t.Errorf("List(machine-a) returned %d jobs, want 2", len(machineA))
	}

	// List by status
	completed, err := store.ListByStatus("completed")
	if err != nil {
		t.Fatalf("ListByStatus() error = %v", err)
	}
	if len(completed) != 2 {
		t.Errorf("ListByStatus(completed) returned %d jobs, want 2", len(completed))
	}
}

func TestJobStore_Delete(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := NewJobStore(dir)
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	job := &Job{
		JobID:     "delete-me",
		Machine:   "test",
		Command:   "test",
		Status:    "completed",
		CreatedAt: time.Now(),
	}

	if err := store.Save(job); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Delete("delete-me"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = store.Load("delete-me")
	if err == nil {
		t.Error("Load() should return error after delete")
	}
}

func TestJobStore_History(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := NewJobStore(dir)
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	job := &Job{
		JobID:     "history-job",
		Machine:   "test-machine",
		Command:   "echo test",
		Status:    "completed",
		ExitCode:  0,
		CreatedAt: time.Now(),
	}
	if err := store.Save(job); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	history, err := store.History("test-machine")
	if err != nil {
		t.Fatalf("History() error = %v", err)
	}

	if len(history) != 1 {
		t.Fatalf("History() returned %d entries, want 1", len(history))
	}

	if history[0].JobID != "history-job" {
		t.Errorf("JobID = %s, want history-job", history[0].JobID)
	}
	if history[0].Command != "echo test" {
		t.Errorf("Command = %s, want echo test", history[0].Command)
	}
}

func TestSaveLoadJSON(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	type TestConfig struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	path := filepath.Join(dir, "test.json")
	original := &TestConfig{Name: "test", Value: 42}

	if err := SaveJSON(path, original); err != nil {
		t.Fatalf("SaveJSON() error = %v", err)
	}

	var loaded TestConfig
	if err := LoadJSON(path, &loaded); err != nil {
		t.Fatalf("LoadJSON() error = %v", err)
	}

	if loaded.Name != original.Name {
		t.Errorf("Name = %s, want %s", loaded.Name, original.Name)
	}
	if loaded.Value != original.Value {
		t.Errorf("Value = %d, want %d", loaded.Value, original.Value)
	}
}
