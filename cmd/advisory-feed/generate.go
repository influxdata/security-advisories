package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Options controls one generate run.
type Options struct {
	OutDir      string           // feeds are written under OutDir/v1/
	AllowShrink bool             // override the shrink guard for this run
	Now         func() time.Time // injected clock for feedTimestamp
}

// Result lists which products were written and which were left alone.
type Result struct {
	Written   []string
	Unchanged []string
}

// Generate fetches advisories, builds every product's feed, and writes the
// ones whose content differs from what cdn serves. A nil cdn is a dry run:
// every feed is written and nothing is fetched. Nothing is written if any
// step fails.
func Generate(ctx context.Context, client *Client, cdn *CDN, reg Registry, opts Options) (Result, error) {
	raw, err := client.ListAdvisories(ctx)
	if err != nil {
		return Result{}, err
	}
	feeds, err := BuildFeeds(raw, reg)
	if err != nil {
		return Result{}, err
	}
	now := opts.Now().UTC().Format(time.RFC3339)

	// Decide first, write second, so a CDN error mid-way leaves no partial output.
	type pending struct {
		product string
		data    []byte
	}
	var toWrite []pending
	var res Result
	for _, p := range reg.Products {
		f := feeds[p]
		f.FeedTimestamp = now
		data, err := Marshal(f)
		if err != nil {
			return Result{}, err
		}
		if len(data) > maxFeedBytes {
			return Result{}, fmt.Errorf("feed for %s is %d bytes, over the %d byte limit", p, len(data), maxFeedBytes)
		}
		if cdn != nil {
			served, err := cdn.Fetch(ctx, p)
			if err != nil {
				return Result{}, err
			}
			if err := CheckShrink(f, served); err != nil && !opts.AllowShrink {
				return Result{}, err
			}
			same, err := Unchanged(data, served, now)
			if err != nil {
				return Result{}, err
			}
			if same {
				res.Unchanged = append(res.Unchanged, p)
				continue
			}
		}
		toWrite = append(toWrite, pending{p, data})
	}

	if len(toWrite) == 0 {
		return res, nil
	}
	if err := os.MkdirAll(filepath.Join(opts.OutDir, feedDir), 0o755); err != nil {
		return Result{}, err
	}
	for _, w := range toWrite {
		if err := os.WriteFile(filepath.Join(opts.OutDir, filepath.FromSlash(feedPath(w.product))), w.data, 0o644); err != nil {
			return Result{}, err
		}
		res.Written = append(res.Written, w.product)
	}
	return res, nil
}
