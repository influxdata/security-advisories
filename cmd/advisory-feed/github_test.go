package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testClient points a Client at an httptest server.
func testClient(srv *httptest.Server) *Client {
	return &Client{BaseURL: srv.URL, Repo: "o/r", HTTP: srv.Client()}
}

func TestListAdvisoriesFollowsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization = %q, want Bearer token", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Errorf("X-GitHub-Api-Version = %q", got)
		}
		if r.URL.Path != "/repos/o/r/security-advisories" {
			t.Errorf("path = %q", r.URL.Path)
		}
		switch r.URL.Query().Get("page") {
		case "":
			if r.URL.Query().Get("per_page") != "100" {
				t.Errorf("per_page = %q, want 100", r.URL.Query().Get("per_page"))
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/security-advisories?per_page=100&page=2>; rel="next", <%s/x?page=2>; rel="last"`, srv.URL, srv.URL))
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-aaaa-aaaa-aaaa","state":"published"}]`)
		case "2":
			fmt.Fprint(w, `[{"ghsa_id":"GHSA-bbbb-bbbb-bbbb","state":"withdrawn","withdrawn_at":"2026-01-01T00:00:00Z"}]`)
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer srv.Close()

	c := testClient(srv)
	c.Token = "token"
	got, err := c.ListAdvisories(context.Background())
	if err != nil {
		t.Fatalf("ListAdvisories: %v", err)
	}
	if len(got) != 2 || got[0].GHSAID != "GHSA-aaaa-aaaa-aaaa" || got[1].GHSAID != "GHSA-bbbb-bbbb-bbbb" {
		t.Fatalf("got %+v", got)
	}
	if got[1].WithdrawnAt == nil || *got[1].WithdrawnAt != "2026-01-01T00:00:00Z" {
		t.Errorf("withdrawn_at not decoded: %+v", got[1])
	}
}

func TestListAdvisoriesNoTokenHeaderWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("Authorization header must be absent without a token")
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	if _, err := testClient(srv).ListAdvisories(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestListAdvisoriesFailsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := testClient(srv).ListAdvisories(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
}

func TestListAdvisoriesFailsOnBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"not":"an array"}`)
	}))
	defer srv.Close()
	if _, err := testClient(srv).ListAdvisories(context.Background()); err == nil {
		t.Fatal("want a parse error")
	}
}
