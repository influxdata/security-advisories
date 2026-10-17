package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files from the current output")

// testTimestamp is the feedTimestamp every golden file carries.
const testTimestamp = "2026-09-23T15:00:00Z"

var testRegistry = Registry{Products: []string{"telegraf", "telegraf-controller"}}

func loadRaw(t *testing.T, name string) []RawAdvisory {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "github", name))
	if err != nil {
		t.Fatal(err)
	}
	var raw []RawAdvisory
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return raw
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create it): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// checkGoldenFeeds stamps every feed with testTimestamp and compares it to
// testdata/golden/<dir>/<product>.json.
func checkGoldenFeeds(t *testing.T, dir string, feeds map[string]*Feed) {
	t.Helper()
	for _, f := range feeds {
		f.FeedTimestamp = testTimestamp
		got, err := Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, filepath.Join(dir, f.Product+".json"), got)
	}
}

func TestBuildFeedsTelegraf140(t *testing.T) {
	feeds, err := BuildFeeds(loadRaw(t, "telegraf-1.40.0.json"), testRegistry)
	if err != nil {
		t.Fatalf("BuildFeeds: %v", err)
	}
	if len(feeds) != 2 {
		t.Fatalf("want a feed per registered product, got %d", len(feeds))
	}
	tg := feeds["telegraf"]
	if len(tg.Advisories) != 1 {
		t.Fatalf("telegraf advisories = %d, want 1", len(tg.Advisories))
	}
	e := tg.Advisories[0]
	if e.ID != "GHSA-wf3f-qrcr-xvx5" || e.CVE != nil || e.Severity != "medium" {
		t.Errorf("unexpected entry header: %+v", e)
	}
	if e.CVSS == nil || e.CVSS.Score != 5.9 || !strings.HasPrefix(e.CVSS.Vector, "CVSS:3.1/") {
		t.Errorf("cvss = %+v", e.CVSS)
	}
	if len(e.Affected) != 1 || e.Affected[0].Introduced == nil || *e.Affected[0].Introduced != "1.32.0" || e.Affected[0].Fixed != "1.40.0" {
		t.Errorf("affected = %+v", e.Affected)
	}
	if len(e.CWEs) != 3 || e.CWEs[0].ID != "CWE-22" {
		t.Errorf("cwes = %+v", e.CWEs)
	}
	if !strings.Contains(e.Description, "## References") {
		t.Error("description must keep the References section")
	}
	if tc := feeds["telegraf-controller"]; len(tc.Advisories) != 0 {
		t.Errorf("telegraf-controller should have an empty feed, got %d", len(tc.Advisories))
	}
	checkGoldenFeeds(t, "telegraf-1.40.0", feeds)
}

func TestBuildFeedsTwoProducts(t *testing.T) {
	feeds, err := BuildFeeds(loadRaw(t, "two-products.json"), testRegistry)
	if err != nil {
		t.Fatalf("BuildFeeds: %v", err)
	}
	tg, tc := feeds["telegraf"], feeds["telegraf-controller"]
	if len(tg.Advisories) != 2 {
		t.Fatalf("telegraf advisories = %d, want 2 (published + withdrawn, draft skipped)", len(tg.Advisories))
	}
	if tg.Advisories[0].ID != "GHSA-cccc-ffff-gggg" || tg.Advisories[1].ID != "GHSA-hhhh-jjjj-mmmm" {
		t.Errorf("order must be newest first: %s, %s", tg.Advisories[0].ID, tg.Advisories[1].ID)
	}
	if tg.Advisories[1].Withdrawn == nil {
		t.Error("withdrawn advisory must carry its withdrawn timestamp")
	}
	if tg.Advisories[0].CVSS != nil {
		t.Error("cvss must be null when no vector was entered")
	}
	if tg.Advisories[0].CVE == nil || *tg.Advisories[0].CVE != "CVE-2026-31402" {
		t.Error("cve must be carried")
	}
	if len(tg.Advisories[0].Affected) != 1 || tg.Advisories[0].Affected[0].Fixed != "1.38.1" {
		t.Errorf("telegraf copy must carry only telegraf ranges: %+v", tg.Advisories[0].Affected)
	}
	if len(tc.Advisories) != 1 || tc.Advisories[0].Affected[0].Introduced != nil || tc.Advisories[0].Affected[0].Fixed != "1.2.0" {
		t.Errorf("telegraf-controller feed = %+v", tc.Advisories)
	}
	checkGoldenFeeds(t, "two-products", feeds)
}

func TestMarshalShape(t *testing.T) {
	got, err := Marshal(&Feed{FeedVersion: feedVersion, Product: "telegraf", FeedTimestamp: testTimestamp, Notice: feedNotice, Advisories: []Entry{}})
	if err != nil {
		t.Fatal(err)
	}
	// feedNotice is plain ASCII with no quotes or backslashes, so its JSON
	// encoding is the text itself.
	want := "{\n  \"feedVersion\": 1,\n  \"product\": \"telegraf\",\n  \"feedTimestamp\": \"" + testTimestamp + "\",\n  \"notice\": \"" + feedNotice + "\",\n  \"advisories\": []\n}\n"
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestBuildFeedsCarriesNotice checks that every feed, including an empty
// one, carries the notice and that the notice points readers at the stable
// sources: the advisories page and the GitHub REST API.
func TestBuildFeedsCarriesNotice(t *testing.T) {
	feeds, err := BuildFeeds(loadRaw(t, "telegraf-1.40.0.json"), testRegistry)
	if err != nil {
		t.Fatalf("BuildFeeds: %v", err)
	}
	for _, f := range feeds {
		if f.Notice != feedNotice {
			t.Errorf("feed for %s has notice %q, want feedNotice", f.Product, f.Notice)
		}
	}
	for _, url := range []string{
		"https://github.com/influxdata/security-advisories/security/advisories",
		"https://api.github.com/repos/influxdata/security-advisories/security-advisories",
	} {
		if !strings.Contains(feedNotice, url) {
			t.Errorf("notice must point to %s", url)
		}
	}
	if strings.HasSuffix(feedNotice, ".") {
		t.Error("notice must not end in a period: it follows a URL, and a trailing period gets swallowed into the link")
	}
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	f := &Feed{FeedVersion: feedVersion, Product: "p", Advisories: []Entry{{ID: "GHSA-cccc-cccc-cccc", Description: "a <b> & c", Affected: []Range{}, CWEs: []CWE{}}}}
	got, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"a <b> & c"`)) {
		t.Errorf("angle brackets and ampersands must not be escaped:\n%s", got)
	}
}

// validAdvisory is a minimal published Telegraf advisory that passes every
// validation rule. Tests mutate one field at a time.
func validAdvisory(id string) RawAdvisory {
	return RawAdvisory{
		GHSAID: id, HTMLURL: "https://example.test/" + id, Summary: "ok",
		Severity: "low", State: "published", PublishedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
		Vulnerabilities: []RawVulnerability{{Package: RawPackage{Name: "telegraf"}, VulnerableVersionRange: "< 1.0.0"}},
	}
}

// ghsaID returns a distinct id in the GHSA alphabet for n, for tests that
// need many advisories.
func ghsaID(n int) string {
	const alphabet = "23456789cfghjmpqrvwx"
	b := []byte("GHSA-cccc-cccc-2222")
	for i := len(b) - 1; n > 0; i-- {
		b[i] = alphabet[n%len(alphabet)]
		n /= len(alphabet)
	}
	return string(b)
}

func TestBuildFeedsRejects(t *testing.T) {
	base := func() RawAdvisory { return validAdvisory("GHSA-cccc-cccc-cccc") }
	cases := []struct {
		name    string
		mutate  func(a *RawAdvisory)
		wantErr string
	}{
		{"unknown package", func(a *RawAdvisory) { a.Vulnerabilities[0].Package.Name = "telegaf" }, "unknown package"},
		{"foreign ecosystem", func(a *RawAdvisory) { a.Vulnerabilities[0].Package.Ecosystem = "npm" }, "ecosystem"},
		{"no affected products", func(a *RawAdvisory) { a.Vulnerabilities = nil }, "no affected products"},
		{"bad range", func(a *RawAdvisory) { a.Vulnerabilities[0].VulnerableVersionRange = "<= 1.0.0" }, "only >= and <"},
		{"bad severity", func(a *RawAdvisory) { a.Severity = "moderate" }, "severity"},
		{"empty summary", func(a *RawAdvisory) { a.Summary = "" }, "empty summary"},
		{"long summary", func(a *RawAdvisory) { a.Summary = strings.Repeat("x", 1001) }, "summary longer than 1000"},
		{"long id", func(a *RawAdvisory) { a.GHSAID = strings.Repeat("G", 129) }, "ghsa_id longer than 128"},
		{"missing id", func(a *RawAdvisory) { a.GHSAID = "" }, "missing ghsa_id"},
		{"missing url", func(a *RawAdvisory) { a.HTMLURL = "" }, "missing html_url"},
		{"missing published_at", func(a *RawAdvisory) { a.PublishedAt = "" }, "published_at"},
		{"missing updated_at", func(a *RawAdvisory) { a.UpdatedAt = "" }, "updated_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base()
			tc.mutate(&a)
			_, err := BuildFeeds([]RawAdvisory{a}, testRegistry)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if !strings.Contains(err.Error(), a.GHSAID) {
				t.Errorf("error must name the advisory: %v", err)
			}
		})
	}
}

func TestBuildFeedsSkipsDrafts(t *testing.T) {
	draft := RawAdvisory{GHSAID: "GHSA-2222-3333-4444", State: "draft"}
	feeds, err := BuildFeeds([]RawAdvisory{draft}, testRegistry)
	if err != nil {
		t.Fatalf("a draft must be skipped, not validated: %v", err)
	}
	if len(feeds["telegraf"].Advisories) != 0 {
		t.Error("draft leaked into the feed")
	}
}

// TestBuildFeedsKeepsEveryRowForAProduct covers the authoring guide's form
// for a fix that ships on more than one release line: one Affected
// products row per line, all naming the same package. Every row must reach
// the feed, in row order.
func TestBuildFeedsKeepsEveryRowForAProduct(t *testing.T) {
	a := validAdvisory("GHSA-cccc-cccc-cccc")
	a.Vulnerabilities = []RawVulnerability{
		{Package: RawPackage{Name: "telegraf"}, VulnerableVersionRange: ">= 1.30.0, < 1.38.1", PatchedVersions: "1.38.1"},
		{Package: RawPackage{Name: "telegraf"}, VulnerableVersionRange: ">= 1.39.0, < 1.39.2", PatchedVersions: "1.39.2"},
	}
	feeds, err := BuildFeeds([]RawAdvisory{a}, testRegistry)
	if err != nil {
		t.Fatalf("BuildFeeds: %v", err)
	}
	tg := feeds["telegraf"].Advisories
	if len(tg) != 1 {
		t.Fatalf("telegraf advisories = %d, want 1 entry carrying both ranges", len(tg))
	}
	ptr := func(s string) *string { return &s }
	want := []Range{{Introduced: ptr("1.30.0"), Fixed: "1.38.1"}, {Introduced: ptr("1.39.0"), Fixed: "1.39.2"}}
	if !reflect.DeepEqual(tg[0].Affected, want) {
		t.Errorf("affected = %s, want both rows in row order", describeRanges(tg[0].Affected))
	}
}

func describeRanges(rs []Range) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		intro := "null"
		if r.Introduced != nil {
			intro = *r.Introduced
		}
		parts = append(parts, intro+".."+r.Fixed)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// TestBuildFeedsSortsNewestFirstThenByID checks the order the schema
// promises: newest published first, with id breaking ties so that the
// output is deterministic.
func TestBuildFeedsSortsNewestFirstThenByID(t *testing.T) {
	mk := func(id, published string) RawAdvisory {
		a := validAdvisory(id)
		a.PublishedAt = published
		return a
	}
	feeds, err := BuildFeeds([]RawAdvisory{
		mk("GHSA-pppp-pppp-pppp", "2026-01-01T00:00:00Z"),
		mk("GHSA-xxxx-xxxx-xxxx", "2026-02-01T00:00:00Z"),
		mk("GHSA-cccc-cccc-cccc", "2026-01-01T00:00:00Z"),
	}, testRegistry)
	if err != nil {
		t.Fatalf("BuildFeeds: %v", err)
	}
	var got []string
	for _, e := range feeds["telegraf"].Advisories {
		got = append(got, e.ID)
	}
	const want = "GHSA-xxxx-xxxx-xxxx,GHSA-cccc-cccc-cccc,GHSA-pppp-pppp-pppp"
	if strings.Join(got, ",") != want {
		t.Errorf("order = %s\nwant    %s", strings.Join(got, ","), want)
	}
}

func TestBuildFeedsCapsAdvisoriesPerProduct(t *testing.T) {
	raw := make([]RawAdvisory, 0, maxAdvisories+1)
	for i := 0; i < maxAdvisories; i++ {
		raw = append(raw, validAdvisory(ghsaID(i)))
	}
	if _, err := BuildFeeds(raw, testRegistry); err != nil {
		t.Fatalf("exactly the limit must pass: %v", err)
	}
	raw = append(raw, validAdvisory(ghsaID(maxAdvisories)))
	_, err := BuildFeeds(raw, testRegistry)
	if err == nil || !strings.Contains(err.Error(), "more than the limit") {
		t.Fatalf("want a limit error for one advisory over, got %v", err)
	}
}
