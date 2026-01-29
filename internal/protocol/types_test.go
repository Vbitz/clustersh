package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		d    Duration
		want string
	}{
		{"zero", Duration(0), `"0s"`},
		{"second", Duration(time.Second), `"1s"`},
		{"minute", Duration(time.Minute), `"1m0s"`},
		{"complex", Duration(5*time.Minute + 30*time.Second), `"5m30s"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.d)
			if err != nil {
				t.Errorf("MarshalJSON() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Duration
		wantErr bool
	}{
		{"string_seconds", `"5s"`, Duration(5 * time.Second), false},
		{"string_minutes", `"10m"`, Duration(10 * time.Minute), false},
		{"string_complex", `"1h30m"`, Duration(90 * time.Minute), false},
		{"number", `1000000000`, Duration(time.Second), false},
		{"invalid", `"invalid"`, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && d != tt.want {
				t.Errorf("UnmarshalJSON() = %v, want %v", d, tt.want)
			}
		})
	}
}

func TestNewMessage(t *testing.T) {
	payload := ExecutePayload{
		JobID:   "test-123",
		Command: "echo hello",
		Timeout: Duration(5 * time.Minute),
	}

	msg, err := NewMessage(MsgExecute, payload)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	if msg.Type != MsgExecute {
		t.Errorf("Message type = %s, want %s", msg.Type, MsgExecute)
	}

	var decoded ExecutePayload
	if err := msg.DecodePayload(&decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}

	if decoded.JobID != payload.JobID {
		t.Errorf("JobID = %s, want %s", decoded.JobID, payload.JobID)
	}
	if decoded.Command != payload.Command {
		t.Errorf("Command = %s, want %s", decoded.Command, payload.Command)
	}
}

func TestMessage_JSON(t *testing.T) {
	payload := ResultPayload{
		JobID:      "job-456",
		ExitCode:   0,
		Output:     "hello world\n",
		Truncated:  false,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}

	msg, err := NewMessage(MsgResult, payload)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var msg2 Message
	if err := json.Unmarshal(data, &msg2); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if msg2.Type != MsgResult {
		t.Errorf("Type = %s, want %s", msg2.Type, MsgResult)
	}

	var decoded ResultPayload
	if err := msg2.DecodePayload(&decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}

	if decoded.JobID != payload.JobID {
		t.Errorf("JobID = %s, want %s", decoded.JobID, payload.JobID)
	}
	if decoded.Output != payload.Output {
		t.Errorf("Output = %s, want %s", decoded.Output, payload.Output)
	}
}
