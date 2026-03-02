package engine

import "strings"

// RequestContext carries information about the original request that triggered
// a response, enabling context-aware response scanning. For example, a malware
// scanner can be less aggressive when the request intent is code generation,
// because code-like patterns (shebangs, import os, etc.) are expected.
type RequestContext struct {
	// RequestMethod is the tool/method that was called (e.g. "chat.send", "tools.run").
	RequestMethod string

	// RequestIntent classifies what the user asked for.
	RequestIntent string // "code_generation", "chat", "search", "file_operation", "unknown"

	// IsCodeGeneration is a convenience flag derived from RequestIntent.
	IsCodeGeneration bool
}

// Intent constants
const (
	IntentCodeGeneration = "code_generation"
	IntentChat           = "chat"
	IntentSearch         = "search"
	IntentFileOperation  = "file_operation"
	IntentUnknown        = "unknown"
)

// ClassifyIntent heuristically classifies a request's intent based on the
// tool method name and parameter content. This is intentionally conservative —
// it only classifies as code_generation when there are strong signals, to avoid
// accidentally reducing scanner sensitivity on non-code requests.
func ClassifyIntent(method, params string) *RequestContext {
	ctx := &RequestContext{
		RequestMethod: method,
		RequestIntent: IntentUnknown,
	}

	lowerMethod := strings.ToLower(method)
	lowerParams := strings.ToLower(params)

	// Code generation signals from method name
	codeMethodKeywords := []string{
		"code", "generate", "write_code", "create_file", "edit_file",
		"refactor", "implement", "compile", "build", "debug",
	}
	for _, kw := range codeMethodKeywords {
		if strings.Contains(lowerMethod, kw) {
			ctx.RequestIntent = IntentCodeGeneration
			ctx.IsCodeGeneration = true
			return ctx
		}
	}

	// File operation signals
	fileMethodKeywords := []string{"file.", "fs.", "read_file", "write_file", "list_dir"}
	for _, kw := range fileMethodKeywords {
		if strings.Contains(lowerMethod, kw) {
			ctx.RequestIntent = IntentFileOperation
			return ctx
		}
	}

	// Search signals
	searchMethodKeywords := []string{"search", "query", "find", "lookup", "browse"}
	for _, kw := range searchMethodKeywords {
		if strings.Contains(lowerMethod, kw) {
			ctx.RequestIntent = IntentSearch
			return ctx
		}
	}

	// Chat signals
	chatMethodKeywords := []string{"chat", "message", "send", "completions", "conversation"}
	for _, kw := range chatMethodKeywords {
		if strings.Contains(lowerMethod, kw) {
			// Check params for code generation intent within chat
			codeParamKeywords := []string{
				"write code", "write a script", "generate code", "create a function",
				"implement", "write a program", "code for", "write python",
				"write go", "write java", "write rust", "write typescript",
				"write javascript", "write sql", "bash script", "shell script",
			}
			for _, cpk := range codeParamKeywords {
				if strings.Contains(lowerParams, cpk) {
					ctx.RequestIntent = IntentCodeGeneration
					ctx.IsCodeGeneration = true
					return ctx
				}
			}
			ctx.RequestIntent = IntentChat
			return ctx
		}
	}

	return ctx
}
