package engine

import (
	"io"
	"strings"
	"testing"

	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
)

func TestScanningReader_SSE_CleanStream(t *testing.T) {
	sseData := "event: message\ndata: hello world\n\nevent: message\ndata: how are you\n\ndata: [DONE]\n\n"
	upstream := io.NopCloser(strings.NewReader(sseData))

	// Create evaluator with all scanners enabled
	policy := &Policy{
		DefaultAction: Allow,
		VulnScan: &scanner.VulnScanConfig{
			Enabled: true,
		},
		PromptInjection: &scanner.PromptInjectionConfig{
			Enabled:       true,
			ScanRequests:  true,
			ScanResponses: true,
		},
		MalwareScan: &scanner.MalwareScanConfig{
			Enabled: true,
		},
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanRequests:  true,
			ScanResponses: true,
		},
		PIIScan: &scanner.PIIConfig{
			Enabled:       true,
			ScanRequests:  true,
			ScanResponses: true,
		},
	}
	evaluator := NewEvaluator(policy)

	// Create StreamScanner
	streamScanner := evaluator.NewStreamScanner("chat.send", "")

	// Create ScanningReader with isSSE=true
	reader := NewScanningReader(upstream, streamScanner, true)

	// Read all output
	var output strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error reading: %v", err)
		}
	}

	// Assert output equals sseData (no modifications)
	if output.String() != sseData {
		t.Errorf("expected output to equal sseData, got:\n%q\nexpected:\n%q", output.String(), sseData)
	}

	// Assert scanner was not blocked
	if streamScanner.WasBlocked() {
		t.Errorf("expected scanner.WasBlocked() to be false, got true")
	}
}

func TestScanningReader_SSE_WithRedaction(t *testing.T) {
	sseData := "event: message\ndata: your key is AKIAIOSFODNN7EXAMPLE\n\ndata: [DONE]\n\n"
	upstream := io.NopCloser(strings.NewReader(sseData))

	// Create evaluator with secrets scanner in redact mode
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanRequests:  false,
			ScanResponses: true,
			Action:        "redact",
		},
	}
	evaluator := NewEvaluator(policy)

	// Create StreamScanner
	streamScanner := evaluator.NewStreamScanner("chat.send", "")

	// Create ScanningReader with isSSE=true
	reader := NewScanningReader(upstream, streamScanner, true)

	// Read all output
	var output strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error reading: %v", err)
		}
	}

	// Assert output does NOT contain the secret
	if strings.Contains(output.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected output to not contain AKIAIOSFODNN7EXAMPLE, but it does")
	}

	// Assert the stream was NOT blocked (redaction, not block)
	if streamScanner.WasBlocked() {
		t.Errorf("expected scanner.WasBlocked() to be false (redaction), got true")
	}
}

func TestScanningReader_NDJSON_CleanStream(t *testing.T) {
	ndjson := "{\"text\":\"hello\"}\n{\"text\":\"world\"}\n"
	upstream := io.NopCloser(strings.NewReader(ndjson))

	// Create evaluator with scanners enabled
	policy := &Policy{
		DefaultAction: Allow,
		SecretsScan: &scanner.SecretsConfig{
			Enabled:       true,
			ScanRequests:  false,
			ScanResponses: true,
		},
	}
	evaluator := NewEvaluator(policy)

	// Create StreamScanner
	streamScanner := evaluator.NewStreamScanner("chat.send", "")

	// Create ScanningReader with isSSE=false
	reader := NewScanningReader(upstream, streamScanner, false)

	// Read all output
	var output strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error reading: %v", err)
		}
	}

	// Assert output == ndjson
	if output.String() != ndjson {
		t.Errorf("expected output to equal ndjson, got:\n%q\nexpected:\n%q", output.String(), ndjson)
	}
}

func TestScanningReader_Close(t *testing.T) {
	data := "hello world\n"
	upstream := io.NopCloser(strings.NewReader(data))

	policy := &Policy{DefaultAction: Allow}
	evaluator := NewEvaluator(policy)
	streamScanner := evaluator.NewStreamScanner("chat.send", "")

	reader := NewScanningReader(upstream, streamScanner, false)

	// Call Close()
	err := reader.Close()
	if err != nil {
		t.Errorf("expected Close() to succeed, got error: %v", err)
	}

	// Assert subsequent Read returns io.EOF
	buf := make([]byte, 1024)
	_, err = reader.Read(buf)
	if err != io.EOF {
		t.Errorf("expected io.EOF after Close(), got error: %v", err)
	}
}
