package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CDN reads the feeds currently served to consumers.
type CDN struct {
	BaseURL string       // public base URL the feed root lives under
	HTTP    *http.Client // injected so tests can point at httptest servers
}

// Fetch returns the served feed for product, or nil when the CDN has none,
// which is the state before the first publish. Any other non-200 status is
// an error, so the caller never publishes on top of a state it cannot see.
func (c *CDN) Fetch(ctx context.Context, product string) (*Feed, error) {
	url := joinURL(c.BaseURL, feedPath(product))
	status, _, body, err := fetch(ctx, c.HTTP, url, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusNotFound:
		return nil, nil
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("GET %s: HTTP %d", url, status)
	}
	var f Feed
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parse served feed %s: %w", url, err)
	}
	return &f, nil
}

// Unchanged reports whether data, a feed serialized with timestamp, has the
// same content as served. Only feedTimestamp may differ. A missing served
// feed is never unchanged.
func Unchanged(data []byte, served *Feed, timestamp string) (bool, error) {
	if served == nil {
		return false, nil
	}
	c := *served
	c.FeedTimestamp = timestamp
	b, err := Marshal(&c)
	if err != nil {
		return false, err
	}
	return bytes.Equal(data, b), nil
}

// CheckShrink fails when next has fewer advisories than served. Advisories
// are never deleted, so a smaller feed means the API returned incomplete
// data.
func CheckShrink(next, served *Feed) error {
	if served != nil && len(next.Advisories) < len(served.Advisories) {
		return fmt.Errorf("feed for %s would shrink from %d advisories to %d; the API may have returned incomplete data", next.Product, len(served.Advisories), len(next.Advisories))
	}
	return nil
}
