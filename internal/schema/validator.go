// Package schema provides validation for Code Clearance reports and configurations
// against their respective versioned JSON Schemas.
package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Schema represents the subset of JSON Schema keywords used by Code Clearance.
type Schema struct {
	ID                   string             `json:"$id"`
	Type                 string             `json:"type"`
	Required             []string           `json:"required"`
	Properties           map[string]*Schema `json:"properties"`
	Items                *Schema            `json:"items"`
	Enum                 []any              `json:"enum"`
	MinItems             *int               `json:"minItems"`
	AdditionalProperties *bool              `json:"additionalProperties"`
	Ref                  string             `json:"$ref"`
	Defs                 map[string]*Schema `json:"$defs"`
	AllOf                []ConditionalRule  `json:"allOf"`
}

type ConditionalRule struct {
	If   *Schema `json:"if"`
	Then *Schema `json:"then"`
}

// LoadSchema parses a JSON Schema file from path.
func LoadSchema(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema file: %w", err)
	}
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse schema JSON: %w", err)
	}
	return &s, nil
}

// Validator validates JSON instances against a loaded Schema.
type Validator struct {
	root *Schema
}

// NewValidator constructs a Validator for the given root schema.
func NewValidator(root *Schema) *Validator {
	return &Validator{root: root}
}

// ValidateBytes validates raw JSON bytes against the schema.
func (v *Validator) ValidateBytes(data []byte) error {
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return v.validateNode(v.root, instance, "$")
}

func (v *Validator) resolveRef(ref string) (*Schema, error) {
	if !strings.HasPrefix(ref, "#/$defs/") {
		return nil, fmt.Errorf("unsupported $ref format: %s", ref)
	}
	defName := strings.TrimPrefix(ref, "#/$defs/")
	if v.root.Defs == nil {
		return nil, fmt.Errorf("schema has no $defs")
	}
	target, ok := v.root.Defs[defName]
	if !ok {
		return nil, fmt.Errorf("definition %q not found in $defs", defName)
	}
	return target, nil
}

func (v *Validator) validateNode(s *Schema, val any, path string) error {
	if s == nil {
		return nil
	}

	// Follow $ref if present
	if s.Ref != "" {
		target, err := v.resolveRef(s.Ref)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return v.validateNode(target, val, path)
	}

	// Validate enum
	if len(s.Enum) > 0 {
		matched := false
		for _, e := range s.Enum {
			if fmt.Sprintf("%v", e) == fmt.Sprintf("%v", val) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %v not in enum %v", path, val, s.Enum)
		}
	}

	isObject := s.Type == "object" || (s.Type == "" && (len(s.Properties) > 0 || len(s.Required) > 0))
	isArray := s.Type == "array" || (s.Type == "" && (s.MinItems != nil || s.Items != nil))

	if isObject {
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: expected object, got %T", path, val)
		}

		// Check required properties
		for _, req := range s.Required {
			if _, exists := obj[req]; !exists {
				return fmt.Errorf("%s: missing required property %q", path, req)
			}
		}

		// Check properties
		for k, propVal := range obj {
			propSchema, hasProp := s.Properties[k]
			if hasProp {
				if err := v.validateNode(propSchema, propVal, path+"."+k); err != nil {
					return err
				}
			} else if s.AdditionalProperties != nil && !*s.AdditionalProperties {
				return fmt.Errorf("%s: unexpected property %q", path, k)
			}
		}
	} else if isArray {
		arr, ok := val.([]any)
		if !ok {
			return fmt.Errorf("%s: expected array, got %T", path, val)
		}
		if s.MinItems != nil && len(arr) < *s.MinItems {
			return fmt.Errorf("%s: array has %d items, minimum is %d", path, len(arr), *s.MinItems)
		}
		if s.Items != nil {
			for i, item := range arr {
				itemPath := fmt.Sprintf("%s[%d]", path, i)
				if err := v.validateNode(s.Items, item, itemPath); err != nil {
					return err
				}
			}
		}
	} else if s.Type != "" {
		switch s.Type {
		case "string":
			if _, ok := val.(string); !ok {
				return fmt.Errorf("%s: expected string, got %T", path, val)
			}

		case "integer":
			f, ok := val.(float64)
			if !ok || f != float64(int64(f)) {
				return fmt.Errorf("%s: expected integer, got %T (%v)", path, val, val)
			}

		case "number":
			if _, ok := val.(float64); !ok {
				return fmt.Errorf("%s: expected number, got %T", path, val)
			}

		case "boolean":
			if _, ok := val.(bool); !ok {
				return fmt.Errorf("%s: expected boolean, got %T", path, val)
			}
		}
	}

	// Validate allOf conditional rules (if/then)
	for idx, rule := range s.AllOf {
		if rule.If != nil && rule.Then != nil {
			// Check if 'if' condition matches without error
			ifMatches := (v.validateNode(rule.If, val, path) == nil)
			if ifMatches {
				if err := v.validateNode(rule.Then, val, path); err != nil {
					return fmt.Errorf("%s: allOf[%d] condition triggered violation: %w", path, idx, err)
				}
			}
		}
	}

	return nil
}

// FindSchemaPath locates a schema file relative to working directory or module root.
func FindSchemaPath(name string) (string, error) {
	candidates := []string{
		filepath.Join("schemas", name),
		filepath.Join("..", "schemas", name),
		filepath.Join("..", "..", "schemas", name),
		filepath.Join("..", "..", "..", "schemas", name),
		filepath.Join("..", "..", "..", "..", "schemas", name),
	}
	if envDir := os.Getenv("CODE_CLEARANCE_SCHEMAS_DIR"); envDir != "" {
		candidates = append([]string{filepath.Join(envDir, name)}, candidates...)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "schemas", name),
			filepath.Join(exeDir, "..", "schemas", name),
			filepath.Join(exeDir, "..", "..", "schemas", name),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("schema %s not found in candidate paths", name)
}

// ValidateReport validates report JSON bytes against schemas/report.schema.json.
func ValidateReport(data []byte) error {
	p, err := FindSchemaPath("report.schema.json")
	if err != nil {
		return err
	}
	s, err := LoadSchema(p)
	if err != nil {
		return err
	}
	return NewValidator(s).ValidateBytes(data)
}

// ValidateClearance validates clearance configuration JSON bytes against schemas/clearance.schema.json.
func ValidateClearance(data []byte) error {
	p, err := FindSchemaPath("clearance.schema.json")
	if err != nil {
		return err
	}
	s, err := LoadSchema(p)
	if err != nil {
		return err
	}
	return NewValidator(s).ValidateBytes(data)
}
