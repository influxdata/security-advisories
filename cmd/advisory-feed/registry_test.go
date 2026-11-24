package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// testRegistryJSON is the registry the tests load: both products, the key
// the repository ships, and a test-only key for Telegraf Controller whose
// pattern carries no anchors, to prove the generator treats every key alike
// and matches whole entries. No fixture uses the second key.
const testRegistryJSON = `{"products": ["telegraf", "telegraf-controller"], "blocks": {
  "affected-plugins": {"products": ["telegraf"], "entry": "^(inputs|outputs|processors|aggregators|secretstores)\\.[a-z0-9_]+$"},
  "affected-components": {"products": ["telegraf-controller"], "entry": "[a-z]+"}}}`

// mustRegistry parses a registry or panics, for package-level test state.
func mustRegistry(src string) Registry {
	reg, err := ParseRegistry([]byte(src))
	if err != nil {
		panic(err)
	}
	return reg
}

func TestLoadRegistryValid(t *testing.T) {
	path := writeTemp(t, "products.json", `{"products": ["telegraf", "telegraf-controller"]}`)
	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if !slices.Equal(reg.Products, []string{"telegraf", "telegraf-controller"}) {
		t.Errorf("products = %v", reg.Products)
	}
}

func TestParseRegistryRejectsBadInput(t *testing.T) {
	cases := []struct{ name, content, wantErr string }{
		{"uppercase", `{"products": ["Telegraf"]}`, "invalid product name"},
		{"underscore", `{"products": ["telegraf_controller"]}`, "invalid product name"},
		{"duplicate", `{"products": ["telegraf", "telegraf"]}`, "duplicate product"},
		{"empty", `{"products": []}`, "no products"},
		{"not json", `{"products": [`, "parse"},
		{"block key uppercase", `{"products": ["telegraf"], "blocks": {"Affected-Plugins": {"products": ["telegraf"], "entry": "^a$"}}}`, "invalid block key"},
		{"block key underscore", `{"products": ["telegraf"], "blocks": {"affected_plugins": {"products": ["telegraf"], "entry": "^a$"}}}`, "invalid block key"},
		{"block no products", `{"products": ["telegraf"], "blocks": {"k": {"products": [], "entry": "^a$"}}}`, "lists no products"},
		{"block unknown product", `{"products": ["telegraf"], "blocks": {"k": {"products": ["kapacitor"], "entry": "^a$"}}}`, "unknown product"},
		{"block duplicate product", `{"products": ["telegraf"], "blocks": {"k": {"products": ["telegraf", "telegraf"], "entry": "^a$"}}}`, "twice"},
		{"block empty pattern", `{"products": ["telegraf"], "blocks": {"k": {"products": ["telegraf"], "entry": ""}}}`, "no entry pattern"},
		{"block bad pattern", `{"products": ["telegraf"], "blocks": {"k": {"products": ["telegraf"], "entry": "("}}}`, "entry pattern"},
		{"block pattern that compiles only once wrapped", `{"products": ["telegraf"], "blocks": {"k": {"products": ["telegraf"], "entry": "a)|(b"}}}`, "entry pattern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRegistry([]byte(tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadRegistryMissingFile(t *testing.T) {
	if _, err := LoadRegistry(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadRegistryNamesTheFileOnBadContent(t *testing.T) {
	path := writeTemp(t, "products.json", `{"products": ["Telegraf"]}`)
	_, err := LoadRegistry(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error must name the file, got %v", err)
	}
}

func TestRepositoryRegistryLoads(t *testing.T) {
	reg, err := LoadRegistry("../../products.json")
	if err != nil {
		t.Fatalf("products.json at the repository root must load: %v", err)
	}
	if !slices.Contains(reg.Products, "telegraf") {
		t.Error("products.json must list telegraf")
	}
	if !slices.Contains(reg.Blocks["affected-plugins"].Products, "telegraf") {
		t.Error("products.json must register affected-plugins for telegraf")
	}
	p := reg.Blocks["affected-plugins"].pattern
	if !p.MatchString("inputs.http_listener_v2") || p.MatchString("Inputs.HTTP") || p.MatchString("http") {
		t.Error("the shipped affected-plugins pattern must accept a section header and reject anything else")
	}
}

func TestParseRegistryBlocks(t *testing.T) {
	reg := testRegistry
	b, ok := reg.Blocks["affected-plugins"]
	if !ok || !slices.Equal(b.Products, []string{"telegraf"}) {
		t.Fatalf("affected-plugins = %+v, %v", b, ok)
	}
	if b.pattern == nil || !b.pattern.MatchString("inputs.http") || b.pattern.MatchString("inputs.http extra") {
		t.Errorf("pattern must be compiled and anchored, got %v", b.pattern)
	}
	for _, src := range []string{`{"products": ["telegraf"]}`, `{"products": ["telegraf"], "blocks": {}}`} {
		reg, err := ParseRegistry([]byte(src))
		if err != nil || len(reg.Blocks) != 0 {
			t.Errorf("%s: blocks must be optional, got %v, %v", src, reg.Blocks, err)
		}
	}
}

// TestParseRegistryAnchorsPattern: a pattern without anchors still matches
// the whole entry.
func TestParseRegistryAnchorsPattern(t *testing.T) {
	reg := mustRegistry(`{"products": ["telegraf"], "blocks": {"k": {"products": ["telegraf"], "entry": "[a-z]+"}}}`)
	p := reg.Blocks["k"].pattern
	if !p.MatchString("api") || p.MatchString("api2") || p.MatchString("Api") {
		t.Error("pattern must be anchored on both sides")
	}
}
