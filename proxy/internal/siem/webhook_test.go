package siem

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestWebhookTransport_SendSuccess(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		received = body
		// Verify content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	transport, err := NewWebhookTransport(server.URL, "", 5000)
	if err != nil {
		t.Fatalf("NewWebhookTransport() failed: %v", err)
	}

	err = transport.Send([]byte(`{"test":"data"}`))
	if err != nil {
		t.Fatalf("Send() failed: %v", err)
	}

	mu.Lock()
	if string(received) != `{"test":"data"}` {
		t.Errorf("received = %q, want %q", string(received), `{"test":"data"}`)
	}
	mu.Unlock()
}

func TestWebhookTransport_AuthHeader(t *testing.T) {
	var gotAuth string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()

	transport, err := NewWebhookTransport(server.URL, "Bearer secret-token-123", 5000)
	if err != nil {
		t.Fatalf("NewWebhookTransport() failed: %v", err)
	}

	err = transport.Send([]byte(`{}`))
	if err != nil {
		t.Fatalf("Send() failed: %v", err)
	}

	mu.Lock()
	if gotAuth != "Bearer secret-token-123" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token-123")
	}
	mu.Unlock()
}

func TestWebhookTransport_ClientError_NoRetry(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(401) // Unauthorized
	}))
	defer server.Close()

	transport, err := NewWebhookTransport(server.URL, "", 1000)
	if err != nil {
		t.Fatalf("NewWebhookTransport() failed: %v", err)
	}

	err = transport.Send([]byte(`{}`))
	if err == nil {
		t.Fatal("Send() should fail on 401, want error")
	}
	if !strings.Contains(err.Error(), "client error") {
		t.Errorf("error should mention 'client error': %v", err)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("callCount = %d, want 1 (no retries on 4xx)", atomic.LoadInt32(&callCount))
	}
}

func TestWebhookTransport_EmptyURL_Error(t *testing.T) {
	_, err := NewWebhookTransport("", "", 5000)
	if err == nil {
		t.Fatal("NewWebhookTransport() should reject empty URL, want error")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should mention 'required': %v", err)
	}
}
