// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAHandler(t *testing.T) {
	files := fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><title>Kiln</title>")},
		"assets/app-abc123.js": {Data: []byte("console.log(1)")},
		"favicon.svg":          {Data: []byte("<svg/>")},
	}
	d := testDeps(t, nil)
	d.Options.WebFS = files
	h, _, err := NewHandler(d)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, method, target string
		status               int
		bodyHas, csp, cache  string
	}{
		{"root is the app shell", "GET", "/", 200, "<title>Kiln", "script-src 'self'", "no-cache"},
		{"client route falls back to shell", "GET", "/orgs/acme/projects", 200, "<title>Kiln", "frame-ancestors 'none'", "no-cache"},
		{"hashed asset cached immutably", "GET", "/assets/app-abc123.js", 200, "console.log", "", "immutable"},
		{"missing asset is 404", "GET", "/assets/missing.js", 404, "urn:kiln:problem:not-found", "", ""},
		{"unknown api path is a problem, not the shell", "GET", "/api/v1/nope", 404, "urn:kiln:problem", "", ""},
		{"POST to the app is rejected", "POST", "/orgs", 405, "method-not-allowed", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(h, tt.method, tt.target, "", nil)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.bodyHas) {
				t.Fatalf("= %d %q", rec.Code, rec.Body)
			}
			if tt.csp != "" {
				csp := rec.Header().Get("Content-Security-Policy")
				if !strings.Contains(csp, tt.csp) || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
					t.Fatalf("CSP = %q", csp)
				}
			}
			if tt.cache != "" && !strings.Contains(rec.Header().Get("Cache-Control"), tt.cache) {
				t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
	if rec := do(h, http.MethodGet, "/", "", nil); !strings.Contains(rec.Header().Get("Content-Security-Policy"), "upgrade-insecure-requests") {
		t.Fatal("https deployments should upgrade insecure requests")
	}
}

// Traversal attempts are cleaned or rejected by net/http before the handler
// and, if they arrive, only ever resolve to indexed files inside the root.
func TestSPAHandler_TraversalNeverEscapesRoot(t *testing.T) {
	d := testDeps(t, nil)
	d.Options.WebFS = fstest.MapFS{"index.html": {Data: []byte("<title>Kiln</title>")}}
	h, _, err := NewHandler(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/../../etc/passwd", "/assets/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/..%5c..%5cwindows%5cwin.ini"} {
		rec := do(h, http.MethodGet, target, "", nil)
		if rec.Code == http.StatusOK && !strings.Contains(rec.Body.String(), "<title>Kiln") {
			t.Fatalf("%s served unexpected content: %q", target, rec.Body)
		}
		if rec.Code == http.StatusTemporaryRedirect || rec.Code == http.StatusMovedPermanently {
			if loc := rec.Header().Get("Location"); strings.Contains(loc, "..") || strings.HasPrefix(loc, "//") {
				t.Fatalf("%s redirected outside the root: %q", target, loc)
			}
		}
	}
}

func TestSPAHandler_RequiresIndex(t *testing.T) {
	d := testDeps(t, nil)
	d.Options.WebFS = fstest.MapFS{"app.js": {Data: []byte("x")}}
	if _, _, err := NewHandler(d); err == nil {
		t.Fatal("web dir without index.html accepted")
	}
}
