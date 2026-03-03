package siem

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// SyslogTransport implements the Transport interface for RFC 5424 syslog
// delivery over TCP or TLS. It automatically reconnects on connection
// failure with exponential backoff.
type SyslogTransport struct {
	address    string
	useTLS     bool
	tlsConfig  *tls.Config
	conn       net.Conn
	mu         sync.Mutex
	maxRetries int
}

// NewSyslogTransport creates a new syslog transport.
// If useTLS is true, certFile and keyFile are used for mutual TLS (optional —
// pass empty strings for server-only TLS verification).
func NewSyslogTransport(address string, useTLS bool, certFile, keyFile string) (*SyslogTransport, error) {
	if address == "" {
		return nil, fmt.Errorf("syslog address is required")
	}

	s := &SyslogTransport{
		address:    address,
		useTLS:     useTLS,
		maxRetries: 3,
	}

	if useTLS {
		// Extract hostname from address for ServerName (SNI) and certificate verification
		host := address
		if strings.Contains(address, ":") {
			var err error
			host, _, err = net.SplitHostPort(address)
			if err != nil {
				// If parsing fails, use the address as-is
				host = address
			}
		}

		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: false, // Explicitly require certificate verification
		}
		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS cert/key: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		s.tlsConfig = tlsCfg
	}

	// Initial connection attempt (non-fatal — will retry on first Send)
	if err := s.connect(); err != nil {
		log.Printf("WARNING: initial syslog connection to %s failed: %v (will retry on send)", address, err)
	}

	return s, nil
}

// connect establishes a TCP or TLS connection to the syslog server.
func (s *SyslogTransport) connect() error {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	if s.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", s.address, s.tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", s.address)
	}
	if err != nil {
		return err
	}

	s.conn = conn
	return nil
}

// Send delivers an OCSF JSON payload as an RFC 5424 syslog message.
// Format: <PRIORITY>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
// We use facility=local0 (16), severity=informational (6) -> priority = 16*8+6 = 134
// The actual OCSF severity is in the JSON payload, not the syslog priority.
func (s *SyslogTransport) Send(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// RFC 5424 formatted message
	timestamp := time.Now().UTC().Format(time.RFC3339)
	// Priority: facility=local0(16)*8 + severity=info(6) = 134
	msg := string(data)
	// SECURITY: Escape newlines and carriage returns to prevent log injection
	msg = strings.ReplaceAll(msg, "\n", "\\n")
	msg = strings.ReplaceAll(msg, "\r", "\\r")
	msg = fmt.Sprintf("<134>1 %s clawshield clawshield-proxy - - - %s\n", timestamp, msg)

	var lastErr error
	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if s.conn == nil {
			if err := s.connect(); err != nil {
				lastErr = err
				backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
				time.Sleep(backoff)
				continue
			}
		}

		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := s.conn.Write([]byte(msg))
		if err != nil {
			lastErr = err
			s.conn.Close()
			s.conn = nil
			backoff := time.Duration(1<<uint(attempt)) * 100 * time.Millisecond
			time.Sleep(backoff)
			continue
		}

		return nil
	}

	return fmt.Errorf("syslog send failed after %d retries: %w", s.maxRetries, lastErr)
}

// Close closes the syslog connection.
func (s *SyslogTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
