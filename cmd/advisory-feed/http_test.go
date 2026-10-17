package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"shorter than the limit", "abc", 5, "abc"},
		{"exactly the limit", "abcde", 5, "abcde"},
		{"ascii over the limit", "abcdef", 3, "abc..."},
		{"multi-byte rune at the cut", "aaéz", 3, "aaé..."},
		{"199 ascii bytes then é", strings.Repeat("a", 199) + "éz", 200, strings.Repeat("a", 199) + "é..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.in, tc.n)
			if !utf8.ValidString(got) {
				t.Fatalf("truncate split a rune: %q", got)
			}
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestFetchBodyLimit(t *testing.T) {
	var size int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("x"), size))
	}))
	defer srv.Close()

	size = maxFeedBytes
	_, _, body, err := fetch(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil || len(body) != maxFeedBytes {
		t.Fatalf("a body of exactly the limit must be returned whole: len=%d err=%v", len(body), err)
	}

	size = maxFeedBytes + 1
	_, _, _, err = fetch(context.Background(), srv.Client(), srv.URL, nil)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("want a size error for one byte over the limit, got %v", err)
	}
}
