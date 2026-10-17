package main

import (
	"bytes"
	"context"
	"fmt"
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
	cdn := servedFeed(t, sampleFeed("GHSA-cccc-cccc-cccc", "GHSA-ffff-ffff-ffff")) // two already served
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
		w.Write([]byte(`[{"ghsa_id":"GHSA-xxxx-xxxx-xxxx","state":"published","summary":"x","severity":"low","html_url":"https://e/x","published_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","vulnerabilities":[{"package":{"ecosystem":"","name":"typo"},"vulnerable_version_range":"< 1.0.0"}]}]`))
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

// goldenServed returns the golden feeds under testdata/golden/<dir> as a
// CDN would serve them, restamped with an earlier feedTimestamp so that a
// run proves only feedTimestamp may differ.
func goldenServed(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	bodies := make(map[string][]byte, len(testRegistry.Products))
	for _, p := range testRegistry.Products {
		body, err := os.ReadFile(filepath.Join("testdata", "golden", dir, p+".json"))
		if err != nil {
			t.Fatal(err)
		}
		bodies[p] = bytes.Replace(body, []byte(testTimestamp), []byte("2026-01-01T00:00:00Z"), 1)
	}
	return bodies
}

// TestGenerateWritesNothingWhenALaterProductFails: by the time the second
// product fails, the first has already been judged ready to write. Nothing
// may reach the output directory, not even the v1 directory.
func TestGenerateWritesNothingWhenALaterProductFails(t *testing.T) {
	api := fixtureAPI(t, "telegraf-1.40.0.json") // telegraf: 1 advisory, telegraf-controller: none
	defer api.Close()

	controller := sampleFeed("GHSA-cccc-cccc-cccc")
	controller.Product = "telegraf-controller"
	cases := []struct {
		name    string
		cdn     *httptest.Server
		wantErr string
	}{
		{"cdn error on the second product", httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/"+feedPath("telegraf") {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "nope", http.StatusInternalServerError)
		})), "HTTP 500"},
		{"shrink on the second product", servedFeed(t, controller), "shrink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.cdn.Close()
			opts := testOptions(t)
			_, err := Generate(context.Background(), testClient(api), testCDN(tc.cdn), testRegistry, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if entries, _ := os.ReadDir(opts.OutDir); len(entries) != 0 {
				t.Errorf("nothing may be written when a later product fails, found %v", entries)
			}
		})
	}
}

// TestGenerateAllUnchanged: when the CDN already serves every feed, nothing
// is written and no output directory is created. Downstream jobs skip on
// this result.
func TestGenerateAllUnchanged(t *testing.T) {
	api := fixtureAPI(t, "telegraf-1.40.0.json")
	defer api.Close()
	cdn := servedRaw(goldenServed(t, "telegraf-1.40.0"))
	defer cdn.Close()

	opts := testOptions(t)
	res, err := Generate(context.Background(), testClient(api), testCDN(cdn), testRegistry, opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Written) != 0 || strings.Join(res.Unchanged, ",") != "telegraf,telegraf-controller" {
		t.Fatalf("written=%v unchanged=%v", res.Written, res.Unchanged)
	}
	if entries, _ := os.ReadDir(opts.OutDir); len(entries) != 0 {
		t.Errorf("no output may be created when nothing changed, found %v", entries)
	}
}

func TestRunReportsChangedFalseWhenAllUnchanged(t *testing.T) {
	api := fixtureAPI(t, "telegraf-1.40.0.json")
	defer api.Close()
	cdn := servedRaw(goldenServed(t, "telegraf-1.40.0"))
	defer cdn.Close()
	registry := writeTemp(t, "products.json", `{"products": ["telegraf", "telegraf-controller"]}`)
	outDir := t.TempDir()

	var out bytes.Buffer
	err := run([]string{"generate", "--api", api.URL, "--repo", "o/r", "--feed-base-url", cdn.URL, "--products", registry, "--out", outDir}, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{"unchanged telegraf\n", "unchanged telegraf-controller\n", "changed=false\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "written") {
		t.Errorf("nothing was written, output must not say so:\n%s", out.String())
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Errorf("no output may be created when nothing changed, found %v", entries)
	}
}

// TestGenerateRejectsOversizeFeed: two API pages, each under the response
// cap, together build one product feed over the feed cap.
func TestGenerateRejectsOversizeFeed(t *testing.T) {
	big := strings.Repeat("x", maxFeedBytes/2+1024)
	advisory := func(id string) string {
		return fmt.Sprintf(`[{"ghsa_id":%q,"state":"published","summary":"big","severity":"low","html_url":"https://e/x","published_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","description":%q,"vulnerabilities":[{"package":{"ecosystem":"","name":"telegraf"},"vulnerable_version_range":"< 1.0.0"}]}]`, id, big)
	}
	page1, page2 := advisory("GHSA-cccc-cccc-cccc"), advisory("GHSA-ffff-ffff-ffff")
	if len(page1) > maxFeedBytes {
		t.Fatalf("test setup: a page must fit under the response cap, got %d bytes", len(page1))
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, page2)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/security-advisories?per_page=100&page=2>; rel="next"`, srv.URL))
		fmt.Fprint(w, page1)
	}))
	defer srv.Close()

	opts := testOptions(t)
	_, err := Generate(context.Background(), testClient(srv), nil, testRegistry, opts)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("want a feed size error, got %v", err)
	}
	if entries, _ := os.ReadDir(opts.OutDir); len(entries) != 0 {
		t.Errorf("nothing may be written when a feed is over the limit, found %v", entries)
	}
}
