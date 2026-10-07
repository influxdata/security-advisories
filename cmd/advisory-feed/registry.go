package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// productNamePattern is the authoring guide's rule for package names:
// lowercase, hyphen-separated identifiers.
var productNamePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Registry is the allowlist of package names the pipeline recognizes. An
// advisory naming any other package fails validation.
type Registry struct {
	Products []string `json:"products"`
}

// LoadRegistry reads and validates a products.json file.
func LoadRegistry(path string) (Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Registry{}, fmt.Errorf("read registry: %w", err)
	}
	reg, err := ParseRegistry(data)
	if err != nil {
		return Registry{}, fmt.Errorf("registry %s: %w", path, err)
	}
	return reg, nil
}

// ParseRegistry decodes and validates registry JSON.
func ParseRegistry(data []byte) (Registry, error) {
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("parse: %w", err)
	}
	if len(reg.Products) == 0 {
		return Registry{}, errors.New("no products listed")
	}
	seen := make(map[string]bool, len(reg.Products))
	for _, name := range reg.Products {
		if !productNamePattern.MatchString(name) {
			return Registry{}, fmt.Errorf("invalid product name %q", name)
		}
		if seen[name] {
			return Registry{}, fmt.Errorf("duplicate product %q", name)
		}
		seen[name] = true
	}
	return reg, nil
}
