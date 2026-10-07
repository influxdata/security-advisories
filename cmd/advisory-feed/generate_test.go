package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureAPI serves a recorded GitHub response for any advisories request.
func fixtureAPI(t *testing.T, name string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "github", name))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

// fixedNow returns the instant every golden file is stamped with.
func fixedNow() time.Time {
	now, err := time.Parse(time.RFC3339, testTimestamp)
	if err != nil {
		panic(err)
	}
	return now
}

func testOptions(t *testing.T) Options {
	return Options{OutDir: t.TempDir(), Now: fixedNow}
}

func TestGenerateWritesChangedFeedsOnly(t *testing.T) {
	api := fixtureAPI(t, "telegraf-1.40.0.json")
	defer api.Close()

	// The CDN already serves an up-to-date empty Controller feed and nothing
	// for Telegraf, so only Telegraf should be written.
	controller := &Feed{FeedVersion: feedVersion, Product: "telegraf-controller", FeedTimestamp: "2026-01-01T00:00:00Z", Notice: feedNotice, Advisories: []Entry{}}
	cdn := servedFeed(t, controller)
	defer cdn.Close()

	opts := testOptions(t)
	res, err := Generate(context.Background(), testClient(api), testCDN(cdn), testRegistry, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Join(res.Written, ",") != "telegraf" || strings.Join(res.Unchanged, ",") != "telegraf-controller" {
		t.Fatalf("written=%v unchanged=%v", res.Written, res.Unchanged)
	}
	got, err := os.ReadFile(filepath.Join(opts.OutDir, "v1", "telegraf.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("telegraf-1.40.0", "telegraf.json"), got)
	if _, err := os.Stat(filepath.Join(opts.OutDir, "v1", "telegraf-controller.json")); !os.IsNotExist(err) {
		t.Error("unchanged feed must not be written")
	}
}

func TestGenerateDryRunWritesEverything(t *testing.T) {
	api := fixtureAPI(t, "two-products.json")
	defer api.Close()

	opts := testOptions(t)
	res, err := Generate(context.Background(), testClient(api), nil, testRegistry, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Written) != 2 || len(res.Unchanged) != 0 {
		t.Fatalf("written=%v unchanged=%v", res.Written, res.Unchanged)
	}
	for _, p := range testRegistry.Products {
		if _, err := os.Stat(filepath.Join(opts.OutDir, "v1", p+".json")); err != nil {
			t.Errorf("%s not written: %v", p, err)
		}
	}
}

func TestGenerateShrinkGuard(t *testing.T) {
	api := fixtureAPI(t, "telegraf-1.40.0.json") // one telegraf advisory
	defer api.Close()
	cdn := servedFeed(t, sampleFeed("GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb")) // two already served
	defer cdn.Close()

	_, err := Generate(context.Background(), testClient(api), testCDN(cdn), testRegistry, testOptions(t))
	if err == nil || !strings.Contains(err.Error(), "shrink") {
		t.Fatalf("want a shrink error, got %v", err)
	}
	opts := testOptions(t)
	opts.AllowShrink = true
	res, err := Generate(context.Background(), testClient(api), testCDN(cdn), testRegistry, opts)
	if err != nil {
		t.Fatalf("allow-shrink must override: %v", err)
	}
	if strings.Join(res.Written, ",") != "telegraf,telegraf-controller" {
		t.Errorf("written = %v", res.Written)
	}
}

func TestGenerateFailsClosedOnBadAdvisory(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ghsa_id":"GHSA-zzzz-zzzz-zzzz","state":"published","summary":"x","severity":"low","html_url":"https://e/x","published_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"","name":"typo"},"vulnerable_version_range":"< 1.0.0"}]}]`))
	}))
	defer api.Close()
	opts := testOptions(t)
	_, err := Generate(context.Background(), testClient(api), nil, testRegistry, opts)
	if err == nil || !strings.Contains(err.Error(), "unknown package") {
		t.Fatalf("want unknown package error, got %v", err)
	}
	if entries, _ := os.ReadDir(opts.OutDir); len(entries) != 0 {
		t.Error("nothing may be written when validation fails")
	}
}

func TestRunRequiresFeedBaseURLUnlessDryRun(t *testing.T) {
	registry := writeTemp(t, "products.json", `{"products": ["telegraf"]}`)
	var out bytes.Buffer
	err := run([]string{"generate", "--products", registry}, &out)
	if err == nil || !strings.Contains(err.Error(), "--feed-base-url") {
		t.Fatalf("want a --feed-base-url error, got %v", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"frobnicate"}, &out); err == nil {
		t.Fatal("want a usage error")
	}
}

func TestRunDryRunEndToEnd(t *testing.T) {
	api := fixtureAPI(t, "two-products.json")
	defer api.Close()
	registry := writeTemp(t, "products.json", `{"products": ["telegraf", "telegraf-controller"]}`)
	var out bytes.Buffer
	err := run([]string{"generate", "--dry-run", "--api", api.URL, "--repo", "o/r", "--products", registry, "--out", t.TempDir()}, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "written   telegraf\n") || !strings.Contains(out.String(), "changed=true") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}
