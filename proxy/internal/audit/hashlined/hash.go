// Package hashlined provides argument hashing for privacy-preserving audit logging.
package hashlined

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// SensitiveKeys defines field names that should be redacted/hashed.
// All keys are normalized: lowercase with underscores and hyphens removed.
var SensitiveKeys = map[string]struct{}{
	"apikey":            {},
	"token":             {},
	"password":          {},
	"secret":            {},
	"credentials":       {},
	"authorization":     {},
	"bearer":            {},
	"jwt":               {},
	"privatekey":        {},
	"clientsecret":      {},
	"accesskey":         {},
	"accesstoken":       {},
	"refreshtoken":      {},
	"sessionid":         {},
	"creditcard":        {},
	"cvv":               {},
	"accountnumber":     {},
	"routingnumber":     {},
	"awsaccesskeyid":    {},
	"awssecretaccesskey":{},
	"githubtoken":       {},
	"email":             {},
	"phone":             {},
	"ssn":               {},
}

// HashArguments takes a JSON-encoded string of arguments and returns a SHA-256 hash.
// Sensitive fields are replaced with "[REDACTED]" before hashing.
func HashArguments(argsJSON string) (string, error) {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "", fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	redactedArgs := redactMap(args)

	raw, err := json.Marshal(redactedArgs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal redacted args: %w", err)
	}

	hash := sha256.Sum256(raw)
	return fmt.Sprintf("%x", hash), nil
}

// IsSensitiveKey reports whether a given key is considered sensitive.
// Normalizes input by converting to lowercase and removing underscores/hyphens.
func IsSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
	_, ok := SensitiveKeys[normalized]
	return ok
}

// RedactArguments returns a copy of args with sensitive fields redacted (for display).
func RedactArguments(argsJSON string) (string, error) {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return "", fmt.Errorf("failed to unmarshal arguments: %w", err)
	}

	redactedArgs := redactMap(args)

	raw, err := json.Marshal(redactedArgs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal redacted args: %w", err)
	}
	return string(raw), nil
}

// redactMap recursively redacts sensitive keys in a map.
func redactMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			result[k] = "[REDACTED]"
		} else if nested, ok := v.(map[string]interface{}); ok {
			result[k] = redactMap(nested)
		} else if arr, ok := v.([]interface{}); ok {
			result[k] = redactSlice(arr)
		} else {
			result[k] = v
		}
	}
	return result
}

// redactSlice recursively redacts sensitive keys in slice elements.
func redactSlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		if nested, ok := v.(map[string]interface{}); ok {
			result[i] = redactMap(nested)
		} else if arr, ok := v.([]interface{}); ok {
			result[i] = redactSlice(arr)
		} else {
			result[i] = v
		}
	}
	return result
}
