// Command advisory-feed builds per-product security advisory feeds from the
// advisories published in the influxdata/security-advisories repository.
//
// Usage:
//
//	advisory-feed generate --feed-base-url URL [--out dist] [--products products.json] [--allow-shrink]
//	advisory-feed generate --dry-run [--out dist] [--products products.json]
//
// GITHUB_TOKEN, when set, raises the GitHub API rate limit.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "generate" {
		return fmt.Errorf("usage: advisory-feed generate [flags]")
	}
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stdout)
	out := fs.String("out", "dist", "output directory; feeds are written under <out>/v1/")
	products := fs.String("products", "products.json", "path to the product registry")
	repo := fs.String("repo", "influxdata/security-advisories", "GitHub repository to read advisories from")
	api := fs.String("api", "https://api.github.com", "GitHub API base URL")
	feedBaseURL := fs.String("feed-base-url", "", "public base URL of the served feeds; required unless --dry-run")
	dryRun := fs.Bool("dry-run", false, "write every feed without comparing to the served feeds")
	allowShrink := fs.Bool("allow-shrink", false, "write a feed even if it has fewer advisories than the served one")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	reg, err := LoadRegistry(*products)
	if err != nil {
		return err
	}
	httpc := &http.Client{Timeout: 30 * time.Second}
	var cdn *CDN
	if !*dryRun {
		if *feedBaseURL == "" {
			return fmt.Errorf("--feed-base-url is required unless --dry-run is given")
		}
		cdn = &CDN{BaseURL: *feedBaseURL, HTTP: httpc}
	}
	client := &Client{BaseURL: *api, Repo: *repo, Token: os.Getenv("GITHUB_TOKEN"), HTTP: httpc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res, err := Generate(ctx, client, cdn, reg, Options{OutDir: *out, AllowShrink: *allowShrink, Now: time.Now})
	if err != nil {
		return err
	}
	for _, p := range res.Written {
		fmt.Fprintf(stdout, "written   %s\n", p)
	}
	for _, p := range res.Unchanged {
		fmt.Fprintf(stdout, "unchanged %s\n", p)
	}
	fmt.Fprintf(stdout, "changed=%t\n", len(res.Written) > 0)
	return nil
}
