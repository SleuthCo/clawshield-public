package siem

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/SleuthCo/clawshield/shared/types"
)

// Transport is the interface for SIEM delivery backends.
type Transport interface {
	// Send delivers a serialized OCSF event to the SIEM endpoint.
	// Implementations should handle retries internally.
	Send(data []byte) error

	// Close gracefully shuts down the transport connection.
	Close() error
}

// SIEMConfig holds configuration for the SIEM log forwarder.
type SIEMConfig struct {
	Enabled           bool   `yaml:"enabled"`
	MinSeverity       int    `yaml:"min_severity"`        // OCSF severity_id threshold (default: 4 = High)
	Transport         string `yaml:"transport"`           // "syslog" or "webhook"
	SyslogAddress     string `yaml:"syslog_address"`      // e.g. "siem.company.com:514"
	SyslogTLS         bool   `yaml:"syslog_tls"`
	SyslogCertFile    string `yaml:"syslog_cert_file"`
	SyslogKeyFile     string `yaml:"syslog_key_file"`
	WebhookURL        string `yaml:"webhook_url"`
	WebhookAuthHeader string `yaml:"webhook_auth_header"` // e.g. "Bearer token123"
	WebhookTimeoutMs  int    `yaml:"webhook_timeout_ms"`  // default: 5000
	QueueSize         int    `yaml:"queue_size"`          // default: 10000
}

const (
	defaultQueueSize = 10000
	maxQueueSize     = 10000
)

// Forwarder receives ClawShield Decision events, filters by severity,
// converts to OCSF format, and forwards to a SIEM via the configured Transport.
// It uses an async bounded queue to avoid blocking the audit pipeline.
type Forwarder struct {
	transport   Transport
	minSeverity int
	queue       chan *types.Decision
	stop        chan struct{}
	wg          sync.WaitGroup
	closed      atomic.Bool
	forwarded   atomic.Int64
	dropped     atomic.Int64
	filtered    atomic.Int64
}

// NewForwarder creates a new SIEM forwarder with the given transport and severity threshold.
func NewForwarder(transport Transport, minSeverity int, queueSize int) *Forwarder {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	if minSeverity <= 0 {
		minSeverity = SeverityHigh // Default: only High and Critical
	}
	f := &Forwarder{
		transport:   transport,
		minSeverity: minSeverity,
		queue:       make(chan *types.Decision, queueSize),
		stop:        make(chan struct{}),
	}
	f.wg.Add(1)
	go f.loop()
	return f
}

// Forward enqueues a Decision for SIEM forwarding.
// The decision is first checked against the severity threshold.
// Non-blocking: drops events if the queue is full.
func (f *Forwarder) Forward(dec *types.Decision) {
	if f.closed.Load() {
		return
	}

	// Severity filter: only forward events at or above threshold
	severityID, _ := MapSeverity(dec)
	if severityID < f.minSeverity {
		f.filtered.Add(1)
		return
	}

	select {
	case f.queue <- dec:
		// enqueued
	default:
		f.dropped.Add(1)
		dropped := f.dropped.Load()
		if dropped == 1 || dropped%100 == 0 {
			log.Printf("WARNING: SIEM forwarder queue full, %d events dropped total", dropped)
		}
	}
}

// loop is the background goroutine that drains the queue and sends events.
func (f *Forwarder) loop() {
	defer f.wg.Done()

	for {
		select {
		case dec, ok := <-f.queue:
			if !ok {
				return
			}
			f.send(dec)

		case <-f.stop:
			// Drain remaining queue items
			for {
				select {
				case dec := <-f.queue:
					f.send(dec)
				default:
					return
				}
			}
		}
	}
}

// send converts a Decision to OCSF and sends it via the transport.
func (f *Forwarder) send(dec *types.Decision) {
	event := DecisionToOCSF(dec)
	data, err := MarshalOCSF(event)
	if err != nil {
		log.Printf("ERROR: SIEM forwarder failed to marshal OCSF event: %v", err)
		return
	}

	if err := f.transport.Send(data); err != nil {
		log.Printf("ERROR: SIEM forwarder failed to send event: %v", err)
		return
	}

	f.forwarded.Add(1)
}

// Close gracefully shuts down the forwarder, draining any remaining events.
func (f *Forwarder) Close() error {
	if f.closed.Swap(true) {
		return nil
	}
	close(f.stop)
	f.wg.Wait()

	log.Printf("SIEM forwarder closed: %d forwarded, %d filtered, %d dropped",
		f.forwarded.Load(), f.filtered.Load(), f.dropped.Load())

	return f.transport.Close()
}

// Stats returns forwarder statistics.
func (f *Forwarder) Stats() (forwarded, filtered, dropped int64) {
	return f.forwarded.Load(), f.filtered.Load(), f.dropped.Load()
}

// NewForwarderFromConfig creates a Forwarder with the appropriate transport
// based on SIEMConfig. Returns an error if the config is invalid or the
// transport cannot be initialized.
func NewForwarderFromConfig(cfg *SIEMConfig) (*Forwarder, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("SIEM forwarding is not enabled")
	}

	var transport Transport
	var err error

	switch cfg.Transport {
	case "syslog":
		transport, err = NewSyslogTransport(cfg.SyslogAddress, cfg.SyslogTLS, cfg.SyslogCertFile, cfg.SyslogKeyFile)
	case "webhook":
		timeoutMs := cfg.WebhookTimeoutMs
		if timeoutMs <= 0 {
			timeoutMs = 5000
		}
		transport, err = NewWebhookTransport(cfg.WebhookURL, cfg.WebhookAuthHeader, timeoutMs)
	default:
		return nil, fmt.Errorf("unsupported SIEM transport: %q (must be 'syslog' or 'webhook')", cfg.Transport)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create SIEM transport: %w", err)
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	return NewForwarder(transport, cfg.MinSeverity, queueSize), nil
}
