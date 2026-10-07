package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// servedFeed serves f at its feed path and 404 for everything else.
func servedFeed(t *testing.T, f *Feed) *httptest.Server {
	t.Helper()
	body, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+feedPath(f.Product) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

func testCDN(srv *httptest.Server) *CDN {
	return &CDN{BaseURL: srv.URL, HTTP: srv.Client()}
}

func sampleFeed(ids ...string) *Feed {
	f := &Feed{FeedVersion: feedVersion, Product: "telegraf", FeedTimestamp: testTimestamp, Notice: feedNotice, Advisories: []Entry{}}
	for _, id := range ids {
		f.Advisories = append(f.Advisories, Entry{ID: id, Published: "2026-01-01T00:00:00Z", Affected: []Range{{Fixed: "1.0.0"}}, CWEs: []CWE{}})
	}
	return f
}

func TestFetchNotFound(t *testing.T) {
	srv := servedFeed(t, sampleFeed())
	defer srv.Close()
	got, err := testCDN(srv).Fetch(context.Background(), "other-product")
	if err != nil || got != nil {
		t.Fatalf("want nil feed without error, got %v err=%v", got, err)
	}
}

func TestFetchFound(t *testing.T) {
	srv := servedFeed(t, sampleFeed("GHSA-aaaa-aaaa-aaaa"))
	defer srv.Close()
	cdn := &CDN{BaseURL: srv.URL + "/", HTTP: srv.Client()} // trailing slash tolerated
	got, err := cdn.Fetch(context.Background(), "telegraf")
	if err != nil || got == nil {
		t.Fatalf("got %v err=%v", got, err)
	}
	if len(got.Advisories) != 1 || got.Advisories[0].ID != "GHSA-aaaa-aaaa-aaaa" {
		t.Errorf("got %+v", got)
	}
}

func TestFetchOtherStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := testCDN(srv).Fetch(context.Background(), "telegraf")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("want HTTP 403 error, got %v", err)
	}
}

func TestUnchanged(t *testing.T) {
	const now = "2026-09-24T00:00:00Z"
	stamped := func(f *Feed) []byte {
		t.Helper()
		f.FeedTimestamp = now
		data, err := Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	served := sampleFeed("GHSA-aaaa-aaaa-aaaa")

	if same, _ := Unchanged(stamped(sampleFeed("GHSA-aaaa-aaaa-aaaa")), served, now); !same {
		t.Error("a feed that differs only in feedTimestamp must count as unchanged")
	}
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb")), served, now); same {
		t.Error("a feed with a new advisory must count as changed")
	}
	edited := sampleFeed("GHSA-aaaa-aaaa-aaaa")
	edited.Advisories[0].Summary = "edited"
	if same, _ := Unchanged(stamped(edited), served, now); same {
		t.Error("an edited entry must count as changed")
	}
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-aaaa-aaaa-aaaa")), nil, now); same {
		t.Error("no served feed must count as changed")
	}
	unnoticed := sampleFeed("GHSA-aaaa-aaaa-aaaa")
	unnoticed.Notice = ""
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-aaaa-aaaa-aaaa")), unnoticed, now); same {
		t.Error("a served feed without the notice must count as changed")
	}
}

func TestCheckShrink(t *testing.T) {
	served := sampleFeed("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb")
	if err := CheckShrink(sampleFeed("GHSA-aaaa-aaaa-aaaa"), served); err == nil || !strings.Contains(err.Error(), "shrink") {
		t.Errorf("want a shrink error, got %v", err)
	}
	if err := CheckShrink(sampleFeed("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"), served); err != nil {
		t.Errorf("same size must pass: %v", err)
	}
	if err := CheckShrink(sampleFeed(), nil); err != nil {
		t.Errorf("no served feed must pass: %v", err)
	}
}
