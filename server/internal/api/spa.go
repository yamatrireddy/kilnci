// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// webCSP is the Content Security Policy for the web app's documents: no
// inline scripts or styles, no eval, no framing, and API calls same-origin
// only (security-standards §10). The UI's styles are compiled at build time
// into a static stylesheet (ADR-0004) so no 'unsafe-inline' is needed.
const webCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

// spaHandler serves the built single-page app. Real files are served as-is
// (hashed assets are cached immutably); any other GET path returns index.html
// so client-side routes work. It never serves /api/ paths. The files are
// static and contain no data, so they are reachable without a principal
// (ADR-0003); every data request still goes through the API router.
//
// The build directory is indexed once at startup and only indexed paths are
// ever opened, so request input never reaches the filesystem.
type spaHandler struct {
	files fs.FS
	index map[string]string // request path -> file name to serve
	errs  errorWriter
	csp   string
}

func newSPAHandler(files fs.FS, errs errorWriter, https bool) (http.Handler, error) {
	index := map[string]string{}
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			index[p] = p
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("index web app files: %w", err)
	}
	if _, ok := index["index.html"]; !ok {
		return nil, errors.New("web app directory has no index.html")
	}
	csp := webCSP
	if https {
		csp += "; upgrade-insecure-requests"
	}
	return &spaHandler{files: files, index: index, errs: errs, csp: csp}, nil
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stateFrom(r).route = "spa"
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(r.Context(), w, problemKind{ProblemMethodNotAllowed, "Method not allowed", http.StatusMethodNotAllowed}, nil)
		return
	}
	requested := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if file, ok := h.index[requested]; ok {
		h.serveFile(w, r, file)
		return
	}
	if requested != "" && path.Ext(requested) != "" {
		// A missing asset is a 404, not the app shell.
		h.errs.write(w, r, domain.ErrNotFound)
		return
	}
	h.serveFile(w, r, "index.html")
}

func (h *spaHandler) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	hdr := w.Header()
	if strings.HasPrefix(name, "assets/") {
		// Vite emits content-hashed file names under assets/.
		hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		hdr.Set("Cache-Control", "no-cache")
	}
	if path.Ext(name) == ".html" {
		hdr.Set("Content-Security-Policy", h.csp)
	}
	http.ServeFileFS(w, r, h.files, name)
}
