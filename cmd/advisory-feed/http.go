package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// fetch performs a GET and returns the status, response headers, and body.
// The body is capped at maxFeedBytes, which bounds a served feed and is far
// larger than a page of advisories. Transport errors and oversize bodies
// are errors; non-200 statuses are returned for the caller to interpret.
func fetch(ctx context.Context, httpc *http.Client, url string, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) > maxFeedBytes {
		return 0, nil, nil, fmt.Errorf("read %s: response larger than %d bytes", url, maxFeedBytes)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// joinURL appends a path to a base URL, tolerating a trailing slash on base.
func joinURL(base, p string) string {
	return strings.TrimRight(base, "/") + "/" + p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
