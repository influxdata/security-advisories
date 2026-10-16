package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// servedRaw serves each body at its product's feed path and 404 for
// everything else.
func servedRaw(bodies map[string][]byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for product, body := range bodies {
			if r.URL.Path == "/"+feedPath(product) {
				w.Header().Set("Content-Type", "application/json")
				w.Write(body)
				return
			}
		}
		http.NotFound(w, r)
	}))
}

// servedFeed serves f at its feed path and 404 for everything else.
func servedFeed(t *testing.T, f *Feed) *httptest.Server {
	t.Helper()
	body, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return servedRaw(map[string][]byte{f.Product: body})
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
	got, body, err := testCDN(srv).Fetch(context.Background(), "other-product")
	if err != nil || got != nil || body != nil {
		t.Fatalf("want nil feed and body without error, got %v body=%q err=%v", got, body, err)
	}
}

func TestFetchFound(t *testing.T) {
	want := sampleFeed("GHSA-cccc-cccc-cccc")
	srv := servedFeed(t, want)
	defer srv.Close()
	cdn := &CDN{BaseURL: srv.URL + "/", HTTP: srv.Client()} // trailing slash tolerated
	got, body, err := cdn.Fetch(context.Background(), "telegraf")
	if err != nil || got == nil {
		t.Fatalf("got %v err=%v", got, err)
	}
	if len(got.Advisories) != 1 || got.Advisories[0].ID != "GHSA-cccc-cccc-cccc" {
		t.Errorf("got %+v", got)
	}
	wantBody, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, wantBody) {
		t.Errorf("body must be the exact bytes served:\n%s", body)
	}
}

func TestFetchOtherStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	_, _, err := testCDN(srv).Fetch(context.Background(), "telegraf")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("want HTTP 403 error, got %v", err)
	}
}

func TestUnchanged(t *testing.T) {
	const now = "2026-09-24T00:00:00Z"
	marshal := func(f *Feed) []byte {
		t.Helper()
		data, err := Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	stamped := func(f *Feed) []byte {
		f.FeedTimestamp = now
		return marshal(f)
	}
	// sampleFeed stamps testTimestamp, which is earlier than now.
	served := marshal(sampleFeed("GHSA-cccc-cccc-cccc"))

	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), served, now); !same {
		t.Error("a feed that differs only in feedTimestamp must count as unchanged")
	}
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-ffff-ffff-ffff")), served, now); same {
		t.Error("a feed with a new advisory must count as changed")
	}
	edited := sampleFeed("GHSA-cccc-cccc-cccc")
	edited.Advisories[0].Summary = "edited"
	if same, _ := Unchanged(stamped(edited), served, now); same {
		t.Error("an edited entry must count as changed")
	}
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), nil, now); same {
		t.Error("no served feed must count as changed")
	}
	unnoticed := sampleFeed("GHSA-cccc-cccc-cccc")
	unnoticed.Notice = ""
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), marshal(unnoticed), now); same {
		t.Error("a served feed without the notice must count as changed")
	}
	// A served feed in a stale shape carries keys the current Feed struct
	// does not declare. It must be rewritten, so it must count as changed.
	extraTop := bytes.Replace(served, []byte(`"notice":`), []byte(`"legacy": true, "notice":`), 1)
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), extraTop, now); same {
		t.Error("a served feed with an unknown top-level key must count as changed")
	}
	extraEntry := bytes.Replace(served, []byte(`"cwes":`), []byte(`"legacy": true, "cwes":`), 1)
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), extraEntry, now); same {
		t.Error("a served feed with an unknown key inside an advisory must count as changed")
	}
	unstamped := bytes.Replace(served, []byte(`"feedTimestamp": "`+testTimestamp+`",`), nil, 1)
	if !bytes.Contains(unstamped, []byte(`"product"`)) || bytes.Contains(unstamped, []byte("feedTimestamp")) {
		t.Fatalf("test setup failed to remove feedTimestamp:\n%s", unstamped)
	}
	if same, _ := Unchanged(stamped(sampleFeed("GHSA-cccc-cccc-cccc")), unstamped, now); same {
		t.Error("a served feed with no feedTimestamp must count as changed")
	}
}

func TestCheckShrink(t *testing.T) {
	served := sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-ffff-ffff-ffff")
	err := CheckShrink(sampleFeed("GHSA-cccc-cccc-cccc"), served)
	if err == nil || !strings.Contains(err.Error(), "shrink") || !strings.Contains(err.Error(), "GHSA-ffff-ffff-ffff") {
		t.Errorf("want a shrink error naming the missing advisory, got %v", err)
	}
	// Same count, but one served advisory replaced by a new one: history
	// would silently vanish, so this must fail too.
	err = CheckShrink(sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-gggg-gggg-gggg"), served)
	if err == nil || !strings.Contains(err.Error(), "GHSA-ffff-ffff-ffff") {
		t.Errorf("a feed that swaps a served advisory for a new one must fail naming the missing id, got %v", err)
	}
	if err := CheckShrink(sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-ffff-ffff-ffff"), served); err != nil {
		t.Errorf("same size must pass: %v", err)
	}
	if err := CheckShrink(sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-ffff-ffff-ffff", "GHSA-gggg-gggg-gggg"), served); err != nil {
		t.Errorf("a grown feed must pass, this is the normal publish: %v", err)
	}
	if err := CheckShrink(sampleFeed(), nil); err != nil {
		t.Errorf("no served feed must pass: %v", err)
	}
}
