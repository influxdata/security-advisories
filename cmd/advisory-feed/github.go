package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// RawAdvisory is the subset of GitHub's repository security advisory
// object that the generator reads. Field names follow the API.
type RawAdvisory struct {
	GHSAID          string             `json:"ghsa_id"`
	CVEID           *string            `json:"cve_id"`
	HTMLURL         string             `json:"html_url"`
	Summary         string             `json:"summary"`
	Description     string             `json:"description"`
	Severity        string             `json:"severity"`
	State           string             `json:"state"`
	PublishedAt     string             `json:"published_at"`
	UpdatedAt       string             `json:"updated_at"`
	WithdrawnAt     *string            `json:"withdrawn_at"`
	Vulnerabilities []RawVulnerability `json:"vulnerabilities"`
	CVSSSeverities  RawCVSSSeverities  `json:"cvss_severities"`
	CWEs            []RawCWE           `json:"cwes"`
}

// RawVulnerability is one "Affected products" row of the advisory form.
type RawVulnerability struct {
	Package                RawPackage `json:"package"`
	VulnerableVersionRange string     `json:"vulnerable_version_range"`
	PatchedVersions        string     `json:"patched_versions"`
}

// RawPackage identifies the product. GitHub returns an empty ecosystem
// for advisories authored with ecosystem "Other".
type RawPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// RawCVSSSeverities carries the CVSS v3 vector and score when one was
// entered; both are null otherwise.
type RawCVSSSeverities struct {
	CVSSV3 *RawCVSS `json:"cvss_v3"`
}

// RawCVSS is a vector string and GitHub's computed base score. Both decode
// to their zero value when the advisory has no vector.
type RawCVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// RawCWE is one weakness from the form's Weaknesses field.
type RawCWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// Client lists repository security advisories through the GitHub REST API.
type Client struct {
	BaseURL string       // API root, normally https://api.github.com
	Repo    string       // owner/name
	Token   string       // optional bearer token; raises the rate limit
	HTTP    *http.Client // injected so tests can point at httptest servers
}

// maxPages bounds pagination. At 100 advisories per page it allows 10,000
// advisories, double the per-product limit, and bounds memory at maxPages
// times the per-response cap in fetch.
const maxPages = 100

var nextLinkPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// ListAdvisories fetches every advisory the API returns for the
// repository, following Link-header pagination. It does not filter by
// state; callers decide which states to keep.
func (c *Client) ListAdvisories(ctx context.Context) ([]RawAdvisory, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API base URL %q: %w", c.BaseURL, err)
	}
	header := http.Header{}
	header.Set("Accept", "application/vnd.github+json")
	header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		header.Set("Authorization", "Bearer "+c.Token)
	}
	next := joinURL(c.BaseURL, "repos/"+c.Repo+"/security-advisories?per_page=100")
	var all []RawAdvisory
	for pages := 0; next != ""; pages++ {
		if pages == maxPages {
			return nil, fmt.Errorf("GET %s: more than %d pages of advisories; raise maxPages if the repository really has that many", next, maxPages)
		}
		status, hdr, body, err := fetch(ctx, c.HTTP, next, header)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("GET %s: HTTP %d: %s", next, status, truncate(strings.TrimSpace(string(body)), 200))
		}
		var page []RawAdvisory
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse %s: %w", next, err)
		}
		all = append(all, page...)
		next = nextLink(hdr.Get("Link"))
		if next != "" {
			if err := checkOrigin(base, next); err != nil {
				return nil, err
			}
		}
	}
	return all, nil
}

// checkOrigin rejects a pagination URL whose scheme or host differs from
// the configured API's, so the bearer token is never sent anywhere else.
func checkOrigin(base *url.URL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse pagination link %q: %w", raw, err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return fmt.Errorf("pagination link %s is not on %s://%s", raw, base.Scheme, base.Host)
	}
	return nil
}

// nextLink extracts the rel="next" URL from a Link header, or "".
func nextLink(header string) string {
	m := nextLinkPattern.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	return m[1]
}
