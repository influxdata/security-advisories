package main

import (
	"reflect"
	"strings"
	"testing"
)

// productsOr returns products, or Telegraf alone when a table row leaves
// it nil.
func productsOr(products []string) []string {
	if products == nil {
		return []string{"telegraf"}
	}
	return products
}

func TestExtractAnnotationsAccepts(t *testing.T) {
	cases := []struct {
		name            string
		description     string
		products        []string
		wantDescription string
		wantBlocks      map[string][]string
	}{
		{"crlf", "Text.\r\n\r\n<!-- affected-plugins\r\ninputs.http\r\n-->", nil, "Text.\r\n\r\n", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"lf", "Text.\n\n<!-- affected-plugins\ninputs.http\n-->\n", nil, "Text.\n\n", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"mixed", "Text.\r\n\n<!-- affected-plugins\ninputs.http\r\noutputs.file\n-->\r\n", nil, "Text.\r\n\n", map[string][]string{"affected-plugins": {"inputs.http", "outputs.file"}}},
		{"bare cr", "<!-- affected-plugins\rinputs.http\r-->", nil, "", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"comments blanks tabs", "<!-- affected-plugins\r\n\r\n\tinputs.http \t# CVE-2026-1, why\r\n   \r\n# whole-line comment\r\noutputs.file # x\r\n-->", nil, "", map[string][]string{"affected-plugins": {"inputs.http", "outputs.file"}}},
		{"comment on key line", "<!--  affected-plugins  # the key\r\ninputs.http\r\n-->", nil, "", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"authored order kept", "<!-- affected-plugins\noutputs.z\ninputs.a\n-->", nil, "", map[string][]string{"affected-plugins": {"outputs.z", "inputs.a"}}},
		{"close marker on entry line", "<!-- affected-plugins\ninputs.http -->", nil, "", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"mid text keeps blank lines", "A.\r\n\r\n<!-- affected-plugins\r\ninputs.http\r\n-->\r\n#### H\r\n", nil, "A.\r\n\r\n#### H\r\n", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"inline keeps the spacing around it", "a <!-- affected-plugins\ninputs.http\n--> b", nil, "a  b", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"block after prose keeps the line ending", "Impact text. <!-- affected-plugins\ninputs.http\n-->\n#### Workarounds", nil, "Impact text. \n#### Workarounds", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"indented own line goes whole", "A.\n  <!-- affected-plugins\n  inputs.http\n  -->  \nB.\n", nil, "A.\nB.\n", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"text after close marker stays", "<!-- affected-plugins\ninputs.http\n--> tail\n", nil, " tail\n", map[string][]string{"affected-plugins": {"inputs.http"}}},
		{"no comments unchanged", "Plain.\r\n", nil, "Plain.\r\n", map[string][]string{}},
		{"empty description", "", nil, "", map[string][]string{}},
		{"stray close marker", "a --> b\r\n", nil, "a --> b\r\n", map[string][]string{}},
		{"two keys two products", "<!-- affected-plugins\ninputs.http\n-->\n<!-- affected-components\napi\n-->\n", []string{"telegraf", "telegraf-controller"}, "", map[string][]string{"affected-plugins": {"inputs.http"}, "affected-components": {"api"}}},
		{"unanchored pattern accepts whole match", "<!-- affected-components\napi\n-->", []string{"telegraf-controller"}, "", map[string][]string{"affected-components": {"api"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractAnnotations(tc.description, productsOr(tc.products), testRegistry)
			if err != nil {
				t.Fatalf("extractAnnotations: %v", err)
			}
			if len(got.Warnings) != 0 {
				t.Errorf("warnings = %v, want none", got.Warnings)
			}
			if got.Description != tc.wantDescription {
				t.Errorf("description = %q, want %q", got.Description, tc.wantDescription)
			}
			if !reflect.DeepEqual(got.Blocks, tc.wantBlocks) {
				t.Errorf("blocks = %v, want %v", got.Blocks, tc.wantBlocks)
			}
		})
	}
}

func TestExtractAnnotationsRejects(t *testing.T) {
	cases := []struct {
		name        string
		description string
		products    []string
		wantErr     string
	}{
		{"empty block", "<!-- affected-plugins\r\n-->", nil, "no entries"},
		{"bad entry", "<!-- affected-plugins\nInputs.HTTP\n-->", nil, "does not match"},
		{"entry with space", "<!-- affected-plugins\ninputs.http extra\n-->", nil, "does not match"},
		{"nested opener", "<!-- affected-plugins\n<!-- inputs.http\n-->", nil, "does not match"},
		{"duplicate entry", "<!-- affected-plugins\ninputs.http\ninputs.http\n-->", nil, "duplicate entry"},
		{"duplicate differing in comment", "<!-- affected-plugins\ninputs.http # a\ninputs.http # b\n-->", nil, "duplicate entry"},
		{"second block", "<!-- affected-plugins\ninputs.http\n-->\n<!-- affected-plugins\noutputs.file\n-->", nil, "second block"},
		{"key not for product", "<!-- affected-plugins\ninputs.http\n-->", []string{"telegraf-controller"}, "not registered for any product"},
		{"unterminated", "Text <!-- affected-plugins\ninputs.http", nil, "unterminated"},
		{"unterminated after a block", "<!-- affected-plugins\ninputs.http\n-->\n<!-- oops", nil, "unterminated"},
		{"unanchored pattern rejects suffix", "<!-- affected-components\napi2\n-->", []string{"telegraf-controller"}, "does not match"},
		{"unanchored pattern rejects case", "<!-- affected-components\nApi\n-->", []string{"telegraf-controller"}, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractAnnotations(tc.description, productsOr(tc.products), testRegistry)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestExtractAnnotationsWarns: a comment whose first line is not a
// registered key is stripped and reported, never an error, and never a
// block.
func TestExtractAnnotationsWarns(t *testing.T) {
	cases := []struct {
		name            string
		description     string
		wantDescription string
		wantWarnings    []string // one substring per expected warning, in order
	}{
		{"template comment", "A.\r\n\r\n<!-- Omit if the release has no toolchain update. -->\r\n#### Go toolchain\r\n", "A.\r\n\r\n#### Go toolchain\r\n", []string{"Omit if the release"}},
		{"typo in key", "<!-- affected-plugin\ninputs.http\n-->", "", []string{"affected-plugin"}},
		{"uppercase key", "<!-- AFFECTED-PLUGINS\ninputs.http\n-->", "", []string{"AFFECTED-PLUGINS"}},
		{"key and entry on one line", "<!-- affected-plugins inputs.http -->", "", []string{"affected-plugins inputs.http"}},
		{"empty comment after text keeps the line ending", "x<!---->\n", "x\n", []string{"<!---->"}},
		{"comment after prose keeps the next heading", "Agents are not affected. <!-- reviewer note -->\r\n#### Patches\r\n", "Agents are not affected. \r\n#### Patches\r\n", []string{"reviewer note"}},
		{"comment inside a list item keeps the next item", "- inputs.http <!-- note -->\n- inputs.file\n", "- inputs.http \n- inputs.file\n", []string{"note"}},
		{"comment between words keeps the separator", "Fixed.<!-- x --> Next.", "Fixed. Next.", []string{"x"}},
		{"two template comments", "<!-- one -->\r\n<!-- two -->\r\ntext", "text", []string{"one", "two"}},
		{"long comment truncated", "<!-- " + strings.Repeat("a", 80) + " -->", "", []string{"..."}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractAnnotations(tc.description, []string{"telegraf"}, testRegistry)
			if err != nil {
				t.Fatalf("an unrecognized comment must not be an error: %v", err)
			}
			if len(got.Blocks) != 0 {
				t.Errorf("blocks = %v, want none", got.Blocks)
			}
			if got.Description != tc.wantDescription {
				t.Errorf("description = %q, want %q", got.Description, tc.wantDescription)
			}
			if len(got.Warnings) != len(tc.wantWarnings) {
				t.Fatalf("warnings = %v, want %d", got.Warnings, len(tc.wantWarnings))
			}
			for i, want := range tc.wantWarnings {
				if !strings.Contains(got.Warnings[i], "unrecognized HTML comment") || !strings.Contains(got.Warnings[i], want) {
					t.Errorf("warning %d = %q, want it to mention the comment and %q", i, got.Warnings[i], want)
				}
			}
		})
	}
}

func TestAnnotationsFor(t *testing.T) {
	reg := testRegistry
	found := map[string][]string{"affected-plugins": {"inputs.http"}, "affected-components": {"api"}}
	if got := reg.annotationsFor("telegraf", found); !reflect.DeepEqual(got, map[string][]string{"affected-plugins": {"inputs.http"}}) {
		t.Errorf("telegraf = %v", got)
	}
	if got := reg.annotationsFor("telegraf-controller", found); !reflect.DeepEqual(got, map[string][]string{"affected-components": {"api"}}) {
		t.Errorf("telegraf-controller = %v", got)
	}
	if got := reg.annotationsFor("kapacitor", found); got == nil || len(got) != 0 {
		t.Errorf("unrelated product must get an empty, non-nil map, got %#v", got)
	}
	if got := reg.annotationsFor("telegraf", nil); got == nil || len(got) != 0 {
		t.Errorf("nil blocks must give an empty, non-nil map, got %#v", got)
	}
}
