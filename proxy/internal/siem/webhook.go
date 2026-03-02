package siem

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookTransport implements the Transport interface for HTTP POST delivery
// of OCSF JSON events to a configurable webhook endpoint.
type WebhookTransport struct {
	url        string
	authHeader string
	client     *http.Client
	maxRetries int
}

// NewWebhookTransport creates a new webhook transport.
// authHeader is the value for the Authorization header (e.g. "Bearer token123").
// Pass an empty string for no authentication.
// timeoutMs is the HTTP client timeout in milliseconds.
func NewWebhookTransport(url, authHeader string, timeoutMs int) (*WebhookTransport, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	if timeoutMs <= 0 {
		timeoutMs = 5000
	}

	// Configure TLS for secure HTTPS connections
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true, // Use server's preferred cipher suite
	}

	httpClient := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
		},
	}

	return &WebhookTransport{
		url:        url,
		authHeader: authHeader,
		client:     httpClient,
		maxRetries: 3,
	}, nil
}

// Send delivers an OCSF JSON payload via HTTP POST.
// Retries on 5xx errors with exponential backoff.
// SECURITY: Does not retry on 4xx (client error) to avoid amplification.
func (w *WebhookTransport) Send(data []byte) error {
	var lastErr error

	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		if w.authHeader != "" {
			req.Header.Set("Authorization", w.authHeader)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
			time.Sleep(backoff)
			continue
		}

		// Read and discard body to allow connection reuse
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// SECURITY: Don't retry on 4xx — it's a client error, retrying won't help
		// and could amplify load on the SIEM endpoint.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("webhook returned client error: %d", resp.StatusCode)
		}

		// 5xx — server error, retry with backoff
		lastErr = fmt.Errorf("webhook returned server error: %d", resp.StatusCode)
		backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
		time.Sleep(backoff)
	}

	return fmt.Errorf("webhook send failed after %d retries: %w", w.maxRetries, lastErr)
}

// Close is a no-op for the webhook transport (HTTP client is stateless).
func (w *WebhookTransport) Close() error {
	return nil
}
