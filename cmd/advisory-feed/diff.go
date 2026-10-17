package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
)

// CDN reads the feeds currently served to consumers.
type CDN struct {
	BaseURL string       // public base URL the feed root lives under
	HTTP    *http.Client // injected so tests can point at httptest servers
}

// Fetch returns the served feed for product, parsed and as the exact bytes
// served, or nil for both when the CDN has none, which is the state before
// the first publish. Any other non-200 status is an error, so the caller
// never publishes on top of a state it cannot see.
func (c *CDN) Fetch(ctx context.Context, product string) (*Feed, []byte, error) {
	url := joinURL(c.BaseURL, feedPath(product))
	status, _, body, err := fetch(ctx, c.HTTP, url, nil)
	if err != nil {
		return nil, nil, err
	}
	switch status {
	case http.StatusNotFound:
		return nil, nil, nil
	case http.StatusOK:
	default:
		return nil, nil, fmt.Errorf("GET %s: HTTP %d", url, status)
	}
	var f Feed
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, nil, fmt.Errorf("parse served feed %s: %w", url, err)
	}
	return &f, body, nil
}

// Unchanged reports whether data, a feed serialized with timestamp, has the
// same content as served, the bytes the CDN returned. Only feedTimestamp
// may differ. The two are compared as generic JSON rather than through the
// Feed struct, so a served file whose shape differs from the current one,
// for example by carrying a key the struct no longer declares, counts as
// changed and is rewritten. A missing served feed is never unchanged.
func Unchanged(data, served []byte, timestamp string) (bool, error) {
	if served == nil {
		return false, nil
	}
	var next, prev map[string]any
	if err := json.Unmarshal(data, &next); err != nil {
		return false, fmt.Errorf("parse generated feed: %w", err)
	}
	if err := json.Unmarshal(served, &prev); err != nil {
		return false, fmt.Errorf("parse served feed: %w", err)
	}
	if _, ok := prev["feedTimestamp"]; ok {
		prev["feedTimestamp"] = timestamp
	}
	return reflect.DeepEqual(next, prev), nil
}

// CheckShrink fails when any advisory that served carries is missing from
// next. Advisories are never deleted, only withdrawn, so a served advisory
// the API no longer returns means the API returned incomplete data. The
// check is by id rather than by count so that a feed which swaps one
// advisory for another cannot silently drop history.
func CheckShrink(next, served *Feed) error {
	if served == nil {
		return nil
	}
	have := make(map[string]bool, len(next.Advisories))
	for _, e := range next.Advisories {
		have[e.ID] = true
	}
	var missing []string
	for _, e := range served.Advisories {
		if !have[e.ID] {
			missing = append(missing, e.ID)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("feed for %s would shrink: served advisories missing from the new feed: %s; the API may have returned incomplete data", next.Product, strings.Join(missing, ", "))
	}
	return nil
}
