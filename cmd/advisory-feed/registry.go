package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
)

// productNamePattern is the authoring guide's rule for package names:
// lowercase, hyphen-separated identifiers.
var productNamePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Registry is the allowlist of package names the pipeline recognizes, and
// of the annotation block keys advisories may carry. An advisory naming any
// other package fails validation; a block with any other key is stripped
// with a warning.
type Registry struct {
	Products []string         `json:"products"`
	Blocks   map[string]Block `json:"blocks"`
}

// Block registers one annotation block key: the products that may carry it
// and the shape every entry must have. The generator knows nothing else
// about a key; meaning belongs to the product that reads the feed.
type Block struct {
	Products []string       `json:"products"`
	Entry    string         `json:"entry"`
	pattern  *regexp.Regexp // Entry compiled as ^(?:Entry)$, set by ParseRegistry
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
	for _, key := range slices.Sorted(maps.Keys(reg.Blocks)) {
		b := reg.Blocks[key]
		if !productNamePattern.MatchString(key) {
			return Registry{}, fmt.Errorf("invalid block key %q", key)
		}
		if len(b.Products) == 0 {
			return Registry{}, fmt.Errorf("block %q lists no products", key)
		}
		for i, p := range b.Products {
			if !seen[p] {
				return Registry{}, fmt.Errorf("block %q names unknown product %q", key, p)
			}
			if slices.Contains(b.Products[:i], p) {
				return Registry{}, fmt.Errorf("block %q lists product %q twice", key, p)
			}
		}
		if b.Entry == "" {
			return Registry{}, fmt.Errorf("block %q has no entry pattern", key)
		}
		pattern, err := regexp.Compile("^(?:" + b.Entry + ")$")
		if err != nil {
			return Registry{}, fmt.Errorf("block %q entry pattern: %w", key, err)
		}
		b.pattern = pattern
		reg.Blocks[key] = b
	}
	return reg, nil
}
