package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	feedVersion      = 1
	feedDir          = "v1" // path segment below the feed root, on the CDN and on disk
	maxIDLength      = 128
	maxSummaryLength = 1000
	maxAdvisories    = 5000
	maxFeedBytes     = 10 * 1024 * 1024
)

// feedNotice tells anyone who opens a feed file what it is for and where
// the supported source of advisories lives. It must not end in a period:
// the text ends with a URL, and a trailing period gets swallowed into the
// link by most renderers.
const feedNotice = "Generated for use by InfluxData products. The format of this file is not a supported API and may change without notice. Published InfluxData security advisories are at https://github.com/influxdata/security-advisories/security/advisories and are available through the GitHub REST API at https://api.github.com/repos/influxdata/security-advisories/security-advisories"

var severityLevels = []string{"critical", "high", "medium", "low"}

// Feed is one product's feed file.
type Feed struct {
	FeedVersion   int     `json:"feedVersion"`
	Product       string  `json:"product"`
	FeedTimestamp string  `json:"feedTimestamp"`
	Notice        string  `json:"notice"`
	Advisories    []Entry `json:"advisories"`
}

// Entry is one advisory as it appears in a product's feed. Every field is
// always present; absent values are null, an empty array, or an empty
// object.
type Entry struct {
	ID          string              `json:"id"`
	CVE         *string             `json:"cve"`
	URL         string              `json:"url"`
	Summary     string              `json:"summary"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
	CVSS        *CVSS               `json:"cvss"`
	Published   string              `json:"published"`
	Updated     string              `json:"updated"`
	Withdrawn   *string             `json:"withdrawn"`
	Affected    []Range             `json:"affected"`
	CWEs        []CWE               `json:"cwes"`
	Annotations map[string][]string `json:"annotations"` // annotation block entries by key, for this product only
}

// CVSS is a CVSS 3.x vector and GitHub's computed base score.
type CVSS struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
}

// CWE is one Common Weakness Enumeration entry.
type CWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// feedPath is a product's feed path below the feed root, with forward
// slashes.
func feedPath(product string) string {
	return path.Join(feedDir, product+".json")
}

// BuildFeeds validates every published or withdrawn advisory, flattens it
// into an Entry, and groups entries by product. Every registered product
// gets a feed, empty if nothing names it. Any validation problem fails the
// whole build so that nothing is published from a bad run. Warnings, one
// per unrecognized HTML comment that was stripped, are returned for the
// caller to report; they never fail the build.
func BuildFeeds(raw []RawAdvisory, reg Registry) (map[string]*Feed, []string, error) {
	feeds := make(map[string]*Feed, len(reg.Products))
	for _, p := range reg.Products {
		feeds[p] = &Feed{FeedVersion: feedVersion, Product: p, Notice: feedNotice, Advisories: []Entry{}}
	}
	var warnings []string
	for _, a := range raw {
		if a.State != "published" && a.State != "withdrawn" {
			continue
		}
		entries, ws, err := convert(a, reg)
		if err != nil {
			return nil, nil, fmt.Errorf("advisory %s: %w", a.GHSAID, err)
		}
		for _, w := range ws {
			warnings = append(warnings, fmt.Sprintf("advisory %s: %s", a.GHSAID, w))
		}
		for product, e := range entries {
			feeds[product].Advisories = append(feeds[product].Advisories, e)
		}
	}
	for _, f := range feeds {
		slices.SortFunc(f.Advisories, func(a, b Entry) int {
			if c := strings.Compare(b.Published, a.Published); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		if len(f.Advisories) > maxAdvisories {
			return nil, nil, fmt.Errorf("product %s has %d advisories, more than the limit of %d", f.Product, len(f.Advisories), maxAdvisories)
		}
	}
	return feeds, warnings, nil
}

// convert validates one advisory, extracts and strips its annotation
// blocks, and flattens it into one Entry per product it names, each
// carrying that product's ranges and annotations. Warnings, one per
// unrecognized HTML comment, come back without the advisory id; the caller
// adds it, as it does for errors.
func convert(a RawAdvisory, reg Registry) (map[string]Entry, []string, error) {
	switch {
	case a.GHSAID == "":
		return nil, nil, fmt.Errorf("missing ghsa_id")
	case len(a.GHSAID) > maxIDLength:
		return nil, nil, fmt.Errorf("ghsa_id longer than %d characters", maxIDLength)
	case a.Summary == "":
		return nil, nil, fmt.Errorf("empty summary")
	case utf8.RuneCountInString(a.Summary) > maxSummaryLength:
		return nil, nil, fmt.Errorf("summary longer than %d characters", maxSummaryLength)
	case !slices.Contains(severityLevels, a.Severity):
		return nil, nil, fmt.Errorf("severity %q is not one of %s", a.Severity, strings.Join(severityLevels, ", "))
	case a.HTMLURL == "":
		return nil, nil, fmt.Errorf("missing html_url")
	case a.PublishedAt == "" || a.UpdatedAt == "":
		return nil, nil, fmt.Errorf("missing published_at or updated_at")
	case len(a.Vulnerabilities) == 0:
		return nil, nil, fmt.Errorf("no affected products, cannot assign to a product")
	}
	ranges := make(map[string][]Range)
	for i, v := range a.Vulnerabilities {
		r, err := convertRow(v, reg)
		if err != nil {
			return nil, nil, fmt.Errorf("affected product %d: %w", i+1, err)
		}
		ranges[v.Package.Name] = append(ranges[v.Package.Name], r)
	}
	ex, err := extractAnnotations(a.Description, slices.Sorted(maps.Keys(ranges)), reg)
	if err != nil {
		return nil, nil, err
	}
	base := Entry{
		ID:          a.GHSAID,
		CVE:         a.CVEID,
		URL:         a.HTMLURL,
		Summary:     a.Summary,
		Description: ex.Description,
		Severity:    a.Severity,
		Published:   a.PublishedAt,
		Updated:     a.UpdatedAt,
		Withdrawn:   a.WithdrawnAt,
		CWEs:        []CWE{},
	}
	if v3 := a.CVSSSeverities.CVSSV3; v3 != nil && v3.VectorString != "" {
		base.CVSS = &CVSS{Vector: v3.VectorString, Score: v3.Score}
	}
	for _, c := range a.CWEs {
		base.CWEs = append(base.CWEs, CWE{ID: c.CWEID, Name: c.Name})
	}
	entries := make(map[string]Entry, len(ranges))
	for product, rs := range ranges {
		e := base
		e.Affected = rs
		e.Annotations = reg.annotationsFor(product, ex.Blocks)
		entries[product] = e
	}
	return entries, ex.Warnings, nil
}

// convertRow validates one "Affected products" row and parses its range.
func convertRow(v RawVulnerability, reg Registry) (Range, error) {
	if !slices.Contains(reg.Products, v.Package.Name) {
		return Range{}, fmt.Errorf("names unknown package %q", v.Package.Name)
	}
	if v.Package.Ecosystem != "" && v.Package.Ecosystem != "other" {
		return Range{}, fmt.Errorf("has ecosystem %q, expected Other", v.Package.Ecosystem)
	}
	return ParseRange(v.VulnerableVersionRange, v.PatchedVersions)
}

// Marshal serializes a feed deterministically: fixed field order,
// two-space indentation, no HTML escaping, trailing newline.
func Marshal(f *Feed) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("encode feed for %s: %w", f.Product, err)
	}
	return buf.Bytes(), nil
}
