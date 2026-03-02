package engine

import (
	"bytes"
	"io"
	"strings"
	"sync"
)

// ScanningReader wraps an upstream response body and scans each SSE event
// or newline-delimited chunk through a StreamScanner before forwarding to
// the client. It implements io.ReadCloser.
//
// For SSE (Server-Sent Events) streams, it reassembles complete events
// (delimited by double newlines) before scanning, since SSE events can
// span multiple reads.
//
// For non-SSE chunked streams (NDJSON), it scans line by line.
//
// SECURITY: The scanner operates on complete semantic units (events/lines)
// to avoid splitting patterns across read boundaries. The StreamScanner's
// overlap window provides additional protection for patterns that span
// event boundaries.
type ScanningReader struct {
	upstream    io.ReadCloser
	scanner     *StreamScanner
	isSSE       bool
	buf         bytes.Buffer    // Accumulates partial reads from upstream
	outBuf      bytes.Buffer    // Buffered scanned output ready for client reads
	readBuf     []byte          // Reusable read buffer
	blocked     bool
	blockReason string
	mu          sync.Mutex
	closed      bool
}

// NewScanningReader creates a ScanningReader that scans upstream content
// through the given StreamScanner.
func NewScanningReader(upstream io.ReadCloser, scanner *StreamScanner, isSSE bool) *ScanningReader {
	return &ScanningReader{
		upstream: upstream,
		scanner:  scanner,
		isSSE:    isSSE,
		readBuf:  make([]byte, 32*1024), // 32KB read buffer
	}
}

// Read implements io.Reader. It reads from upstream, scans complete events/lines,
// and returns scanned (potentially redacted) content to the caller.
func (sr *ScanningReader) Read(p []byte) (int, error) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.closed {
		return 0, io.EOF
	}

	// If we already have scanned output buffered, serve from that
	if sr.outBuf.Len() > 0 {
		return sr.outBuf.Read(p)
	}

	// If the stream was blocked, return EOF
	if sr.blocked {
		return 0, io.EOF
	}

	// Read from upstream until we have at least one complete event/line
	for {
		n, readErr := sr.upstream.Read(sr.readBuf)
		if n > 0 {
			sr.buf.Write(sr.readBuf[:n])
		}

		// Process any complete events/lines in the buffer
		processed := sr.processBuffer()

		if sr.blocked {
			// Stream terminated by scanner — write error event to output
			if sr.isSSE {
				sr.outBuf.WriteString("event: error\ndata: {\"error\":\"blocked by security policy\"}\n\n")
			}
			if sr.outBuf.Len() > 0 {
				return sr.outBuf.Read(p)
			}
			return 0, io.EOF
		}

		if processed && sr.outBuf.Len() > 0 {
			return sr.outBuf.Read(p)
		}

		if readErr != nil {
			// Upstream ended — flush any remaining buffer content
			if sr.buf.Len() > 0 {
				sr.processRemainder()
				if sr.outBuf.Len() > 0 {
					return sr.outBuf.Read(p)
				}
			}
			return 0, readErr
		}
	}
}

// processBuffer extracts and scans complete events/lines from the accumulation buffer.
// Returns true if any events were processed.
func (sr *ScanningReader) processBuffer() bool {
	processed := false

	if sr.isSSE {
		// SSE events are delimited by double newlines (\n\n)
		for {
			content := sr.buf.String()
			idx := strings.Index(content, "\n\n")
			if idx < 0 {
				break
			}

			// Extract complete event (including the delimiter)
			event := content[:idx+2]
			sr.buf.Reset()
			sr.buf.WriteString(content[idx+2:])

			// Extract the data content from SSE event for scanning
			dataContent := extractSSEData(event)

			if dataContent == "" || dataContent == "[DONE]" {
				// Empty event or stream terminator — pass through
				sr.outBuf.WriteString(event)
				processed = true
				continue
			}

			// Scan the data content
			result := sr.scanner.ScanChunk(dataContent)

			if result.ShouldBlock {
				sr.blocked = true
				sr.blockReason = result.Reason
				return true
			}

			if result.WasRedacted {
				// Reconstruct SSE event with redacted data
				sr.outBuf.WriteString(replaceSSEData(event, result.RedactedChunk))
			} else {
				sr.outBuf.WriteString(event)
			}
			processed = true
		}
	} else {
		// NDJSON / line-delimited: scan line by line
		for {
			content := sr.buf.String()
			idx := strings.Index(content, "\n")
			if idx < 0 {
				break
			}

			line := content[:idx+1]
			sr.buf.Reset()
			sr.buf.WriteString(content[idx+1:])

			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				sr.outBuf.WriteString(line)
				processed = true
				continue
			}

			result := sr.scanner.ScanChunk(trimmed)

			if result.ShouldBlock {
				sr.blocked = true
				sr.blockReason = result.Reason
				return true
			}

			if result.WasRedacted {
				sr.outBuf.WriteString(result.RedactedChunk + "\n")
			} else {
				sr.outBuf.WriteString(line)
			}
			processed = true
		}
	}

	return processed
}

// processRemainder handles any remaining content in the buffer when the
// upstream stream ends (no trailing delimiter).
func (sr *ScanningReader) processRemainder() {
	remaining := sr.buf.String()
	sr.buf.Reset()

	if remaining == "" {
		return
	}

	if sr.isSSE {
		dataContent := extractSSEData(remaining)
		if dataContent == "" || dataContent == "[DONE]" {
			sr.outBuf.WriteString(remaining)
			return
		}
		result := sr.scanner.ScanChunk(dataContent)
		if result.ShouldBlock {
			sr.blocked = true
			sr.blockReason = result.Reason
			return
		}
		if result.WasRedacted {
			sr.outBuf.WriteString(replaceSSEData(remaining, result.RedactedChunk))
		} else {
			sr.outBuf.WriteString(remaining)
		}
	} else {
		trimmed := strings.TrimSpace(remaining)
		if trimmed == "" {
			sr.outBuf.WriteString(remaining)
			return
		}
		result := sr.scanner.ScanChunk(trimmed)
		if result.ShouldBlock {
			sr.blocked = true
			sr.blockReason = result.Reason
			return
		}
		if result.WasRedacted {
			sr.outBuf.WriteString(result.RedactedChunk + "\n")
		} else {
			sr.outBuf.WriteString(remaining)
		}
	}
}

// Close closes the upstream reader.
func (sr *ScanningReader) Close() error {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.closed = true
	return sr.upstream.Close()
}

// WasBlocked returns true if the stream was terminated by the scanner.
func (sr *ScanningReader) WasBlocked() bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.blocked
}

// extractSSEData extracts the concatenated data field content from an SSE event.
// SSE events have the format:
//
//	event: type\n
//	data: content\n
//	data: more content\n
//	\n
//
// Returns the concatenated data values with newlines between multi-line data.
func extractSSEData(event string) string {
	var parts []string
	for _, line := range strings.Split(event, "\n") {
		if strings.HasPrefix(line, "data: ") {
			parts = append(parts, strings.TrimPrefix(line, "data: "))
		} else if strings.HasPrefix(line, "data:") {
			parts = append(parts, strings.TrimPrefix(line, "data:"))
		}
	}
	return strings.Join(parts, "\n")
}

// replaceSSEData reconstructs an SSE event with replacement data content,
// preserving event type and other fields.
func replaceSSEData(event, newData string) string {
	var result strings.Builder
	dataReplaced := false

	for _, line := range strings.Split(event, "\n") {
		if strings.HasPrefix(line, "data:") {
			if !dataReplaced {
				result.WriteString("data: ")
				result.WriteString(newData)
				result.WriteString("\n")
				dataReplaced = true
			}
			// Skip subsequent data lines (replaced by single line)
		} else {
			result.WriteString(line)
			result.WriteString("\n")
		}
	}

	return result.String()
}
