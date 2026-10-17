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
}
