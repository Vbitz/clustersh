//go:build integration

package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"j5.nz/clustersh/internal/api"
	"j5.nz/clustersh/internal/coordinator"
	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/security"
	"j5.nz/clustersh/internal/storage"
)

func setupTestServer(t *testing.T) (*httptest.Server, *coordinator.Coordinator, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "clustersh-integration-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}

	jobStore, err := storage.NewJobStore(dir)
	if err != nil {
		t.Fatalf("NewJobStore() error = %v", err)
	}

	coord := coordinator.New(jobStore, nil)

	ca, err := security.NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	authManager, err := coordinator.NewAuthManager(ca, dir)
	if err != nil {
		t.Fatalf("NewAuthManager() error = %v", err)
	}

	apiServer := api.NewServer(coord, authManager)
	server := httptest.NewServer(apiServer.Handler())

	return server, coord, dir
}

func TestIntegration_ListMachines(t *testing.T) {
	server, _, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	resp, err := http.Get(server.URL + "/machines")
	if err != nil {
		t.Fatalf("GET /machines error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var machines []protocol.Machine
	if err := json.NewDecoder(resp.Body).Decode(&machines); err != nil {
		t.Fatalf("Decode error = %v", err)
	}

	if len(machines) != 0 {
		t.Errorf("Expected 0 machines, got %d", len(machines))
	}
}

func TestIntegration_GetCACert(t *testing.T) {
	server, _, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	resp, err := http.Get(server.URL + "/ca.crt")
	if err != nil {
		t.Fatalf("GET /ca.crt error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-pem-file" {
		t.Errorf("Content-Type = %s, want application/x-pem-file", contentType)
	}
}

func TestIntegration_InstallScripts(t *testing.T) {
	server, _, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	tests := []struct {
		path        string
		contentType string
	}{
		{"/install.sh", "text/plain"},
		{"/install.ps1", "text/plain"},
		{"/install_client.sh", "text/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp, err := http.Get(server.URL + tt.path)
			if err != nil {
				t.Fatalf("GET %s error = %v", tt.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func TestIntegration_RunWithoutMachine(t *testing.T) {
	server, _, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	reqBody := `{"machine": "nonexistent", "command": "echo hello"}`
	resp, err := http.Post(server.URL+"/run", "application/json",
		strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /run error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestIntegration_OutputNotFound(t *testing.T) {
	server, _, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	resp, err := http.Get(server.URL + "/output/nonexistent-uuid")
	if err != nil {
		t.Fatalf("GET /output error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestIntegration_FullFlow(t *testing.T) {
	server, coord, dir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(dir)

	// Simulate agent registration
	reg := &protocol.RegisterPayload{
		MachineName: "test-agent",
		OS:          "linux",
		Arch:        "amd64",
	}
	agent, err := coord.RegisterAgent(nil, reg)
	if err != nil {
		t.Fatalf("RegisterAgent() error = %v", err)
	}

	// List machines - should show the agent
	resp, err := http.Get(server.URL + "/machines")
	if err != nil {
		t.Fatalf("GET /machines error = %v", err)
	}
	defer resp.Body.Close()

	var machines []protocol.Machine
	json.NewDecoder(resp.Body).Decode(&machines)

	if len(machines) != 1 {
		t.Fatalf("Expected 1 machine, got %d", len(machines))
	}

	if machines[0].Name != "test-agent" {
		t.Errorf("Machine name = %s, want test-agent", machines[0].Name)
	}

	// Unregister agent
	coord.UnregisterAgent(agent.Name)

	// Agent should still be listed but disconnected
	resp2, _ := http.Get(server.URL + "/machines")
	defer resp2.Body.Close()

	var machines2 []protocol.Machine
	json.NewDecoder(resp2.Body).Decode(&machines2)

	if machines2[0].Connected {
		t.Error("Machine should be disconnected")
	}
}

func TestIntegration_JobLifecycle(t *testing.T) {
	dir, err := os.MkdirTemp("", "clustersh-integration-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(dir)

	jobStore, _ := storage.NewJobStore(dir)
	coord := coordinator.New(jobStore, nil)

	// Register agent
	reg := &protocol.RegisterPayload{
		MachineName: "test-agent",
		OS:          "linux",
		Arch:        "amd64",
	}
	coord.RegisterAgent(nil, reg)

	// Skip ExecuteCommand test since it requires a real WebSocket connection
	// Just test job result handling directly

	// Manually create a job to test result handling
	job := &storage.Job{
		JobID:     "manual-job",
		Machine:   "test-agent",
		Command:   "echo hello",
		Status:    "running",
		CreatedAt: time.Now(),
		StartedAt: time.Now(),
	}
	jobStore.Save(job)

	// Handle result
	result := &protocol.ResultPayload{
		JobID:      "manual-job",
		ExitCode:   0,
		Output:     "hello\n",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}
	coord.HandleResult("test-agent", result)

	// Verify result
	output, err := coord.GetOutput("manual-job")
	if err != nil {
		t.Fatalf("GetOutput() error = %v", err)
	}

	if output.Status != "completed" {
		t.Errorf("Status = %s, want completed", output.Status)
	}
}
