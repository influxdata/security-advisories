package main

import (
	"strings"
	"testing"
)

func str(s string) *string { return &s }

func TestParseRangeAccepts(t *testing.T) {
	cases := []struct {
		name           string
		rangeText      string
		patched        string
		wantIntroduced *string
		wantFixed      string
	}{
		{"both bounds", ">= 1.32.0, < 1.40.0", "1.40.0", str("1.32.0"), "1.40.0"},
		{"upper only", "< 1.39.2", "1.39.2", nil, "1.39.2"},
		{"upper only no patched", "< 1.39.2", "", nil, "1.39.2"},
		{"lower only with patched", ">= 1.38.0", "1.39.2", str("1.38.0"), "1.39.2"},
		{"no spaces", ">=1.32.0,<1.40.0", "", str("1.32.0"), "1.40.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRange(tc.rangeText, tc.patched)
			if err != nil {
				t.Fatalf("ParseRange(%q): %v", tc.rangeText, err)
			}
			if got.Fixed != tc.wantFixed {
				t.Errorf("fixed = %q, want %q", got.Fixed, tc.wantFixed)
			}
			switch {
			case tc.wantIntroduced == nil && got.Introduced != nil:
				t.Errorf("introduced = %q, want null", *got.Introduced)
			case tc.wantIntroduced != nil && (got.Introduced == nil || *got.Introduced != *tc.wantIntroduced):
				t.Errorf("introduced = %v, want %q", got.Introduced, *tc.wantIntroduced)
			}
		})
	}
}

func TestParseRangeRejects(t *testing.T) {
	cases := []struct {
		name      string
		rangeText string
		patched   string
		wantErr   string
	}{
		{"less or equal", "<= 1.39.2", "", "only >= and < are allowed"},
		{"greater than", "> 1.38.0, < 1.39.2", "", "only >= and < are allowed"},
		{"equals", "= 1.39.0", "", "only >= and < are allowed"},
		{"v prefix", "< v1.39.2", "", "invalid version"},
		{"two-part version", "< 1.39", "", "invalid version"},
		{"prerelease", "< 1.39.2-rc1", "", "invalid version"},
		{"no upper bound", ">= 1.38.0", "", "no upper bound"},
		{"patched differs", "< 1.39.2", "1.39.3", "differs from patched version"},
		{"two lower bounds", ">= 1.0.0, >= 1.1.0, < 2.0.0", "", "more than one lower bound"},
		{"two upper bounds", "< 1.0.0, < 2.0.0", "", "more than one upper bound"},
		{"garbage", "all versions", "", "cannot parse constraint"},
		{"empty", "", "", "cannot parse constraint"},
		{"bad patched", "< 1.39.2", "v1.39.2", "invalid patched version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRange(tc.rangeText, tc.patched)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
