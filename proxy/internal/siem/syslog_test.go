package siem

import (
	"net"
	"strings"
	"testing"
	"time"
)

// mockNetAddr is a mock implementation of net.Addr
type mockNetAddr struct {
	network string
	address string
}

func (a *mockNetAddr) Network() string { return a.network }
func (a *mockNetAddr) String() string  { return a.address }

// mockSyslogConn records written data for testing
type mockSyslogConn struct {
	data []byte
}

func (m *mockSyslogConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockSyslogConn) Write(b []byte) (n int, err error) {
	m.data = append(m.data, b...)
	return len(b), nil
}

func (m *mockSyslogConn) Close() error {
	return nil
}

func (m *mockSyslogConn) LocalAddr() net.Addr {
	return &mockNetAddr{network: "tcp", address: "127.0.0.1:0"}
}

func (m *mockSyslogConn) RemoteAddr() net.Addr {
	return &mockNetAddr{network: "tcp", address: "localhost:514"}
}

func (m *mockSyslogConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockSyslogConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockSyslogConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestSyslog_NewlineEscaping verifies that embedded newlines and carriage returns
// are escaped to prevent log injection attacks.
func TestSyslog_NewlineEscaping(t *testing.T) {
	s := &SyslogTransport{
		address:    "localhost:514",
		useTLS:     false,
		maxRetries: 3,
	}

	// Create a message with embedded newlines and carriage returns
	msgWithNewlines := `{"event": "test", "data": "line1
line2
line3\r\n"}`

	err := s.Send([]byte(msgWithNewlines))
	if err == nil {
		// Expected to fail since we don't have a real connection, but that's OK
		// The important thing is the format was set up correctly
	}

	// Now set up a mock connection to verify escaping
	mockConn := &mockSyslogConn{}
	s.conn = mockConn

	err = s.Send([]byte(msgWithNewlines))
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	output := string(mockConn.data)

	// Verify the output contains escaped sequences, not literal newlines/CR
	if strings.Contains(output, "\nline2") {
		t.Errorf("output contains unescaped newline in message body: %q", output)
	}

	// Verify escaped newlines are present
	if !strings.Contains(output, "\\n") {
		t.Errorf("output missing escaped newline: %q", output)
	}

	// Verify escaped carriage returns are present
	if !strings.Contains(output, "\\r") {
		t.Errorf("output missing escaped carriage return: %q", output)
	}

	// Verify the final newline in RFC 5424 format is still present
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("output missing final RFC 5424 newline: %q", output)
	}
}

// TestSyslog_NoEscapingForValidJSON verifies that valid JSON without
// newlines/CR is passed through unchanged (except for the outer RFC 5424 wrapper).
func TestSyslog_NoEscapingForValidJSON(t *testing.T) {
	s := &SyslogTransport{
		address:    "localhost:514",
		useTLS:     false,
		maxRetries: 3,
	}

	validJSON := `{"event":"test","data":"clean"}`
	mockConn := &mockSyslogConn{}
	s.conn = mockConn

	err := s.Send([]byte(validJSON))
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	output := string(mockConn.data)

	// Verify the JSON is preserved in the output
	if !strings.Contains(output, `"event":"test"`) {
		t.Errorf("valid JSON was corrupted: %q", output)
	}

	// Verify we have exactly one newline at the end (RFC 5424 format)
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("output missing final newline: %q", output)
	}
}
