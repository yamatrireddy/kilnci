// SPDX-License-Identifier: Apache-2.0

// Package githubtest is a fake GitHub API for tests: it serves the few
// endpoints Kiln's App client uses and records posted commit statuses.
package githubtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/vcs/github"
)

// Repo is a repository the fake knows.
type Repo struct {
	ID      int64
	Private bool
	// Installations that can see the repository (empty: every one).
	Installations []int64
}

// Fake is a fake GitHub. Configure it before making calls; the maps are
// guarded for concurrent test access through the methods.
type Fake struct {
	mu sync.Mutex
	// Installations that exist (nil: every positive ID exists).
	Installations map[int64]bool
	// Repos by "owner/name" (nil: any "owner/name" exists, public, with an ID
	// derived from the name).
	Repos map[string]Repo
	// Files by "<repoID>@<sha>" (nil: every commit has DefaultFile).
	Files       map[string]string
	DefaultFile string
	// Branches by name -> SHA (nil: only "main").
	Branches map[string]string
	statuses []map[string]string
}

// SetFile adds a pipeline file at repoID@sha.
func (f *Fake) SetFile(key, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Files == nil {
		f.Files = map[string]string{}
	}
	f.Files[key] = body
}

// Statuses returns the commit statuses posted so far.
func (f *Fake) Statuses() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.statuses...)
}

func nameID(name string) int64 {
	var h int64 = 1469598103934665603
	for _, c := range name {
		h = (h ^ int64(c)) * 1099511628211
	}
	if h < 0 {
		h = -h
	}
	return h%1_000_000_000 + 1
}

func (f *Fake) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_fake_" + r.PathValue("id"), "expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		var id int64
		_ = json.Unmarshal([]byte(r.PathValue("id")), &id)
		f.mu.Lock()
		ok := id > 0 && (f.Installations == nil || f.Installations[id])
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "account": map[string]string{"login": "acme"}})
	})
	mux.HandleFunc("GET /repos/{owner}/{name}", func(w http.ResponseWriter, r *http.Request) {
		full := r.PathValue("owner") + "/" + r.PathValue("name")
		f.mu.Lock()
		repo, ok := Repo{ID: nameID(full)}, f.Repos == nil
		if f.Repos != nil {
			repo, ok = f.Repos[full]
		}
		f.mu.Unlock()
		if ok && len(repo.Installations) > 0 {
			ok = false
			for _, inst := range repo.Installations {
				if r.Header.Get("Authorization") == "token ghs_fake_"+itoa(inst) {
					ok = true
				}
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": repo.ID, "full_name": full,
			"clone_url": "https://github.com/" + full + ".git", "default_branch": "main", "private": repo.Private})
	})
	mux.HandleFunc("GET /repositories/{repo}/contents/.kiln/pipeline.yaml", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, ok := f.DefaultFile, f.Files == nil && f.DefaultFile != ""
		if f.Files != nil {
			body, ok = f.Files[r.PathValue("repo")+"@"+r.URL.Query().Get("ref")]
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("GET /repositories/{repo}/git/ref/heads/{branch...}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		sha, ok := f.Branches[r.PathValue("branch")]
		if f.Branches == nil && r.PathValue("branch") == "main" {
			sha, ok = "cccccccccccccccccccccccccccccccccccccccc", true
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": sha, "type": "commit"}})
	})
	mux.HandleFunc("POST /repositories/{repo}/statuses/{sha}", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["sha"] = r.PathValue("sha")
		body["repo"] = r.PathValue("repo")
		f.mu.Lock()
		f.statuses = append(f.statuses, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{}")
	})
	return mux
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Client starts the fake and returns an App client talking to it.
func (f *Fake) Client(t *testing.T) *github.Client {
	t.Helper()
	srv := httptest.NewTLSServer(f.handler())
	t.Cleanup(srv.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, err := github.New(github.Options{AppID: 9, APIURL: srv.URL, HTTP: srv.Client(),
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
