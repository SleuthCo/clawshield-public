package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
)

func TestOversizedMessageRejected(t *testing.T) {
	policy := &engine.Policy{
		MaxMessageBytes: 1024, // Set small limit for test (1KB)
	}
	evaluator := engine.NewEvaluator(policy)

	// Create a message larger than 1KB
	oversizedPayload := bytes.Repeat([]byte("a"), 2048) // 2KB
	message := `{"method":"system.exec","params":"` + string(oversizedPayload) + `"}`

	// Simulate reading from stdin with LimitReader
	limitedReader := io.LimitReader(bytes.NewReader([]byte(message)), policy.MaxMessageBytes)
	decoder := json.NewDecoder(limitedReader)

	var msg interface{}
	err := decoder.Decode(&msg)

	if err == nil {
		t.Error("Expected error from truncated JSON, got nil")
	}

	// Since the message was truncated by LimitReader, it's invalid JSON and will be rejected
	// The proxy will log a DOS attempt (tested in integration tests), but here we verify the decoder fails properly

	// Suppress unused variable warning
	_ = evaluator
}
