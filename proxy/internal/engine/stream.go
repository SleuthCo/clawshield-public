package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/SleuthCo/clawshield/proxy/internal/scanner"
	"github.com/SleuthCo/clawshield/shared/types"
)

// DefaultOverlapLen is the number of characters retained from the end of the
// previous chunk and prepended to the next chunk for scanning. This ensures
// patterns that span chunk boundaries are still detected.
//
// 200 chars covers the longest scanner patterns:
// - Injection patterns: ~60 chars max
// - Secret patterns (base64 keys): ~40 chars
// - Entropy analysis window: 100 chars
// - Safety margin for multi-pattern overlap
const DefaultOverlapLen = 200

// StreamChunkResult holds the per-chunk scanning result.
type StreamChunkResult struct {
	// Decision is "allow", "deny", or "redact" for this chunk.
	Decision string

	// Reason is a human-readable explanation if denied or redacted.
	Reason string

	// RedactedChunk contains the chunk with sensitive content redacted.
	// Only populated when WasRedacted is true. Contains ONLY the new chunk
	// content (not the overlap prefix), ready to forward to the client.
	RedactedChunk string

	// WasRedacted is true if any scanner applied redaction to this chunk.
	WasRedacted bool

	// ShouldBlock is true if this chunk triggered a deny decision and the
	// stream should be terminated.
	ShouldBlock bool

	// Results contains per-scanner forensic details for this chunk.
	Results []types.ScanResult
}

// StreamScanner provides chunk-aware response scanning with a sliding overlap
// window. It wraps the existing scanner instances and maintains state across
// chunks to detect patterns that span chunk boundaries.
//
// Usage:
//
//	ss := evaluator.NewStreamScanner(ctx, "chat.send", params)
//	for chunk := range chunks {
//	    result := ss.ScanChunk(chunk)
//	    if result.ShouldBlock { break }
//	    forward(result.RedactedChunk or chunk)
//	}
//	detail := ss.Finalize()
type StreamScanner struct {
	// Scanner instances (may be nil if disabled)
	injectionDetector *scanner.InjectionDetector
	malwareScanner    *scanner.MalwareScanner
	secretsScanner    *scanner.SecretsScanner
	piiScanner        *scanner.PIIScanner

	// Request context for context-aware threshold adjustment
	requestCtx *RequestContext

	// Sliding window state
	overlapBuf string // Last overlapLen chars from previous chunk
	overlapLen int

	// Aggregated results across all chunks
	allResults  []types.ScanResult
	chunkCount  int
	startTime   time.Time
	wasRedacted bool
	blocked     bool
	blockReason string
}

// NewStreamScanner creates a StreamScanner configured with the evaluator's
// scanner instances and a classified RequestContext for context-carrying.
func (e *Evaluator) NewStreamScanner(requestMethod, requestParams string) *StreamScanner {
	return &StreamScanner{
		injectionDetector: e.injectionDetector,
		malwareScanner:    e.malwareScanner,
		secretsScanner:    e.secretsScanner,
		piiScanner:        e.piiScanner,
		requestCtx:        ClassifyIntent(requestMethod, requestParams),
		overlapLen:        DefaultOverlapLen,
		allResults:        []types.ScanResult{},
		startTime:         time.Now(),
	}
}

// ScanChunk processes a single chunk of streaming response content through
// all configured scanners. The chunk is prepended with the overlap buffer
// from the previous chunk to catch patterns that span boundaries.
//
// Returns a StreamChunkResult indicating whether the chunk should be
// forwarded, redacted, or if the stream should be terminated.
func (ss *StreamScanner) ScanChunk(chunk string) *StreamChunkResult {
	if ss.blocked {
		// Stream already terminated by a previous chunk
		return &StreamChunkResult{
			Decision:    Deny,
			Reason:      ss.blockReason,
			ShouldBlock: true,
		}
	}

	ss.chunkCount++

	// Build the scanning window: overlap from previous chunk + new chunk
	scanText := ss.overlapBuf + chunk

	// Update overlap buffer for next chunk
	ss.updateOverlap(chunk)

	result := &StreamChunkResult{
		Decision: Allow,
	}

	// --- Blocking scanners (injection, malware) ---

	// Injection scanning
	if ss.injectionDetector != nil {
		if scanResult := ss.injectionDetector.ScanResponseDetail("stream", scanText); scanResult != nil {
			// Context-carrying: if this is a code generation response,
			// skip some injection false positives that look like code comments
			// or instructional text
			if !ss.shouldSuppressInjection(scanResult) {
				ss.blocked = true
				ss.blockReason = scanResult.Description
				ss.allResults = append(ss.allResults, *scanResult)
				return &StreamChunkResult{
					Decision:    Deny,
					Reason:      scanResult.Description,
					ShouldBlock: true,
					Results:     []types.ScanResult{*scanResult},
				}
			}
		}
	}

	// Malware scanning
	if ss.malwareScanner != nil {
		if scanResult := ss.malwareScanner.ScanResponseDetail(scanText); scanResult != nil {
			// Context-carrying: code generation responses are expected to contain
			// script-like content (shebangs, imports, etc.)
			if !ss.shouldSuppressMalware(scanResult) {
				ss.blocked = true
				ss.blockReason = scanResult.Description
				ss.allResults = append(ss.allResults, *scanResult)
				return &StreamChunkResult{
					Decision:    Deny,
					Reason:      scanResult.Description,
					ShouldBlock: true,
					Results:     []types.ScanResult{*scanResult},
				}
			}
		}
	}

	// --- Redaction scanners (secrets, PII) ---
	// These scan the full window but only redact the NEW chunk portion.

	workingChunk := chunk

	// Secrets scanning + redaction
	if ss.secretsScanner != nil {
		if scanResult := ss.secretsScanner.ScanResponseDetail("stream", scanText); scanResult != nil {
			ss.allResults = append(ss.allResults, *scanResult)
			result.Results = append(result.Results, *scanResult)

			if ss.secretsScanner.Action() == "redact" {
				// Redact only the new chunk portion (not overlap)
				redacted, found := ss.secretsScanner.RedactSecrets(workingChunk)
				if len(found) > 0 {
					workingChunk = redacted
					result.WasRedacted = true
					ss.wasRedacted = true
				}
			} else {
				// Block mode
				ss.blocked = true
				ss.blockReason = scanResult.Description
				return &StreamChunkResult{
					Decision:    Deny,
					Reason:      scanResult.Description,
					ShouldBlock: true,
					Results:     result.Results,
				}
			}
		}
	}

	// PII scanning + redaction
	if ss.piiScanner != nil {
		if scanResult := ss.piiScanner.ScanResponseDetail("stream", scanText); scanResult != nil {
			ss.allResults = append(ss.allResults, *scanResult)
			result.Results = append(result.Results, *scanResult)

			if ss.piiScanner.Action() == "redact" {
				redacted, found := ss.piiScanner.RedactPII(workingChunk)
				if len(found) > 0 {
					workingChunk = redacted
					result.WasRedacted = true
					ss.wasRedacted = true
				}
			} else {
				// Block mode
				ss.blocked = true
				ss.blockReason = scanResult.Description
				return &StreamChunkResult{
					Decision:    Deny,
					Reason:      scanResult.Description,
					ShouldBlock: true,
					Results:     result.Results,
				}
			}
		}
	}

	// Set the final chunk content
	if result.WasRedacted {
		result.Decision = Allow
		result.Reason = "chunk redacted"
		result.RedactedChunk = workingChunk
	} else {
		result.RedactedChunk = chunk // unchanged
	}

	// Ensure the overlap buffer excludes any redacted content
	// (we want to scan the ORIGINAL text for overlap, not redacted text)
	// This is already handled because updateOverlap was called on the original chunk above.

	return result
}

// Finalize aggregates all chunk results into a final DecisionDetail.
// Should be called when the stream ends (EOF or block).
func (ss *StreamScanner) Finalize() *types.DecisionDetail {
	detail := &types.DecisionDetail{
		EvalDurationMs: time.Since(ss.startTime).Seconds() * 1000,
		ScanResults:    ss.allResults,
	}

	if ss.blocked {
		detail.PipelineStage = "stream_blocked"
	} else if ss.wasRedacted {
		detail.PipelineStage = "stream_redacted"
	} else {
		detail.PipelineStage = "stream_clean"
	}

	// Record context-carrying info in metadata
	if ss.requestCtx != nil && ss.requestCtx.IsCodeGeneration {
		detail.ActiveOverrides = append(detail.ActiveOverrides,
			fmt.Sprintf("context:code_generation(method=%s)", ss.requestCtx.RequestMethod))
	}

	return detail
}

// FinalizeAsResponseResult converts the finalized stream into a ResponseResult
// compatible with the existing audit logging path.
func (ss *StreamScanner) FinalizeAsResponseResult() ResponseResult {
	detail := ss.Finalize()

	if ss.blocked {
		return ResponseResult{
			Decision: Deny,
			Reason:   ss.blockReason,
			Details:  detail,
		}
	}

	if ss.wasRedacted {
		return ResponseResult{
			Decision:    Allow,
			Reason:      "streaming response redacted",
			WasRedacted: true,
			Details:     detail,
		}
	}

	return ResponseResult{
		Decision: Allow,
		Reason:   "streaming response clean",
		Details:  detail,
	}
}

// WasBlocked returns true if any chunk triggered a deny decision.
func (ss *StreamScanner) WasBlocked() bool {
	return ss.blocked
}

// WasRedacted returns true if any chunk was redacted.
func (ss *StreamScanner) WasRedacted() bool {
	return ss.wasRedacted
}

// ChunkCount returns the number of chunks processed.
func (ss *StreamScanner) ChunkCount() int {
	return ss.chunkCount
}

// updateOverlap updates the sliding window overlap buffer with the tail of
// the current chunk.
func (ss *StreamScanner) updateOverlap(chunk string) {
	if len(chunk) >= ss.overlapLen {
		ss.overlapBuf = chunk[len(chunk)-ss.overlapLen:]
	} else {
		// Chunk is smaller than overlap — combine with existing overlap
		combined := ss.overlapBuf + chunk
		if len(combined) > ss.overlapLen {
			ss.overlapBuf = combined[len(combined)-ss.overlapLen:]
		} else {
			ss.overlapBuf = combined
		}
	}
}

// shouldSuppressInjection returns true if an injection detection should be
// suppressed due to context (e.g., code generation responses often contain
// instructional text that triggers false positives).
//
// SECURITY: delimiter_injection is intentionally NOT suppressed here, as it
// detects critical cross-tool attacks (fake tool output boundaries, fake JSON-RPC
// responses). Even in code generation contexts, these patterns are security-critical.
func (ss *StreamScanner) shouldSuppressInjection(result *types.ScanResult) bool {
	if ss.requestCtx == nil || !ss.requestCtx.IsCodeGeneration {
		return false
	}

	// In code generation context, suppress only encoding_attack
	// which commonly triggers on code examples containing base64 or HTML entities.
	// DO NOT suppress delimiter_injection — it detects cross-tool exfiltration attacks.
	switch result.RuleID {
	case "encoding_attack":
		return true
	}
	return false
}

// shouldSuppressMalware returns true if a malware detection should be suppressed
// due to context (e.g., code generation is expected to produce script content).
func (ss *StreamScanner) shouldSuppressMalware(result *types.ScanResult) bool {
	if ss.requestCtx == nil || !ss.requestCtx.IsCodeGeneration {
		return false
	}

	// In code generation context, suppress script_detection since shebangs
	// and script patterns are expected output.
	switch result.RuleID {
	case "script_detection":
		return true
	}

	// Never suppress executable_magic, signature_match, zip_bomb, etc.
	// — even in code generation, binary executables are suspicious.
	return false
}

// isStreamingContentType returns true if the Content-Type indicates a streaming response.
func IsStreamingContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "text/event-stream") ||
		strings.Contains(ct, "application/x-ndjson") ||
		strings.Contains(ct, "application/stream+json")
}
