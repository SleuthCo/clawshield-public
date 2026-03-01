package config

import (
	"fmt"
	"os"

	"github.com/SleuthCo/clawshield/proxy/internal/engine"
	"gopkg.in/yaml.v3"
)

// Load reads and parses the policy YAML file
func Load(path string) (*engine.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var policy engine.Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse YAML policy: %w", err)
	}

	// Validate and default: fail-closed (deny) if not specified
	switch policy.DefaultAction {
	case "allow", "deny":
		// valid
	case "":
		policy.DefaultAction = "deny"
	default:
		return nil, fmt.Errorf("invalid default_action %q: must be \"allow\" or \"deny\"", policy.DefaultAction)
	}

	// Set default max message size if not specified (1MB)
	if policy.MaxMessageBytes <= 0 {
		policy.MaxMessageBytes = 1048576 // 1MB in bytes
	}

	return &policy, nil
}
