package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

func main() {
	schemaPath := flag.String("schema", "", "Path to JSON schema file (default: policy/schemas/policy.schema.json relative to executable)")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		log.Fatal("Usage: clawshield-validate [--schema <schema-file>] <policy-file.yaml>")
	}

	policyFile := args[0]

	// Resolve schema path
	if *schemaPath == "" {
		exeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		*schemaPath = filepath.Join(exeDir, "policy", "schemas", "policy.schema.json")
	}

	// Read policy YAML
	data, err := os.ReadFile(policyFile)
	if err != nil {
		log.Fatalf("Error reading policy file: %v", err)
	}

	// Parse YAML first
	var policyYAML interface{}
	if err := yaml.Unmarshal(data, &policyYAML); err != nil {
		log.Fatalf("Error parsing YAML: %v", err)
	}

	// Convert to JSON for schema validation
	jsonBytes, err := json.Marshal(policyYAML)
	if err != nil {
		log.Fatalf("Error converting YAML to JSON: %v", err)
	}

	var policy interface{}
	if err := json.Unmarshal(jsonBytes, &policy); err != nil {
		log.Fatalf("Error parsing converted JSON: %v", err)
	}

	// Load schema
	absSchemaPath, err := filepath.Abs(*schemaPath)
	if err != nil {
		log.Fatal(err)
	}
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + absSchemaPath)
	policyLoader := gojsonschema.NewGoLoader(policy)

	result, err := gojsonschema.Validate(schemaLoader, policyLoader)
	if err != nil {
		log.Fatalf("Schema validation error: %v", err)
	}

	if result.Valid() {
		fmt.Println("Policy is valid")
	} else {
		fmt.Println("Policy is invalid:")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}
}
