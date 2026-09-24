// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/yamatrireddy/kilnci/server/internal/auth/authz"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/reqmeta"
)

// Authenticator resolves the principal for a request.
type Authenticator interface {
	// Authenticate returns (nil, nil) when the request carries no credentials,
	// and an error (domain.ErrUnauthenticated, or domain.ErrForbidden for a
	// failed CSRF check) when credentials are present but unacceptable.
	Authenticate(r *http.Request) (*authz.Principal, error)
}

// publicRoutes may be served without a principal (CLAUDE.md invariant 9).
var publicRoutes = []string{
	"GET /healthz",
	"GET /readyz",
}

// publicPrefixes may be served without a principal; handlers under them must
// verify a signature before parsing input. Reserved for webhook ingest.
var publicPrefixes = []string{
	"POST /api/v1/webhooks/",
}

// preAuthRoutes are the OIDC login flow endpoints (ADR-0003).
var preAuthRoutes = []string{
	"GET /api/v1/auth/login",
	"GET /api/v1/auth/callback",
	"POST /api/v1/auth/token",
}

type route struct {
	method  string
	pattern string
	perm    authz.Action
	handler http.Handler
}

// RouteInfo describes a registered route, for spec-conformance tests.
type RouteInfo struct {
	Method     string
	Pattern    string
	Permission authz.Action
}

// Router is a deny-by-default HTTP router. Every route declares the permission
// it requires; routes without a principal are only possible on the allowlists
// above; Build fails if any rule is broken, so a misconfigured route stops the
// server from starting rather than being exposed.
type Router struct {
	routes map[string]map[string]route // pattern -> method -> route
	authn  Authenticator
	errs   errorWriter
	regErr []error
	// validate checks the request against the OpenAPI spec after
	// authentication and before the handler. Nil only in unit tests.
	validate func(*http.Request) error
	// limits applies the authentication-failure budget and per-principal
	// limits. Nil only in unit tests.
	limits *limiters
}

func newRouter(authn Authenticator, errs errorWriter) *Router {
	return &Router{routes: make(map[string]map[string]route), authn: authn, errs: errs}
}

// Handle registers h for method and pattern (a net/http path pattern without
// a method, e.g. "/api/v1/orgs/{orgSlug}"), requiring perm.
func (rt *Router) Handle(method, pattern string, perm authz.Action, h http.HandlerFunc) {
	key := method + " " + pattern
	switch {
	case perm == "":
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: no permission declared", key))
	case !authz.Known(perm):
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: unknown permission %q", key, perm))
	case perm == authz.PermissionPublic && !isAllowedPublic(key):
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: public access is only allowed for %v and %v", key, publicRoutes, publicPrefixes))
	case perm == authz.PermissionPreAuth && !slices.Contains(preAuthRoutes, key):
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: pre-auth access is only allowed for %v", key, preAuthRoutes))
	case h == nil:
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: nil handler", key))
	}
	byMethod := rt.routes[pattern]
	if byMethod == nil {
		byMethod = make(map[string]route)
		rt.routes[pattern] = byMethod
	}
	if _, dup := byMethod[method]; dup {
		rt.regErr = append(rt.regErr, fmt.Errorf("%s: registered twice", key))
	}
	byMethod[method] = route{method: method, pattern: pattern, perm: perm, handler: h}
}

func isAllowedPublic(key string) bool {
	if slices.Contains(publicRoutes, key) {
		return true
	}
	for _, p := range publicPrefixes {
		if strings.HasPrefix(key, p) && len(key) > len(p) {
			return true
		}
	}
	return false
}

// Routes lists registered routes, sorted.
func (rt *Router) Routes() []RouteInfo {
	var out []RouteInfo
	for _, byMethod := range rt.routes {
		for _, r := range byMethod {
			out = append(out, RouteInfo{Method: r.method, Pattern: r.pattern, Permission: r.perm})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Pattern+" "+out[i].Method < out[j].Pattern+" "+out[j].Method
	})
	return out
}

// build validates all registrations and returns the dispatching handler.
func (rt *Router) build() (http.Handler, error) {
	if len(rt.regErr) > 0 {
		return nil, fmt.Errorf("invalid routes: %w", errors.Join(rt.regErr...))
	}
	mux := http.NewServeMux()
	for pattern, byMethod := range rt.routes {
		mux.Handle(pattern, rt.dispatch(byMethod))
	}
	// Anything unmatched is a problem+json 404, never a default text page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rt.errs.write(w, r, domain.ErrNotFound)
	})
	return mux, nil
}

func (rt *Router) dispatch(byMethod map[string]route) http.Handler {
	allow := make([]string, 0, len(byMethod))
	for m := range byMethod {
		allow = append(allow, m)
	}
	sort.Strings(allow)
	allowHeader := strings.Join(allow, ", ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateFrom(r).route = r.Pattern
		rte, ok := byMethod[r.Method]
		if !ok {
			w.Header().Set("Allow", allowHeader)
			writeProblem(r.Context(), w, problemKind{ProblemMethodNotAllowed, "Method not allowed", http.StatusMethodNotAllowed}, nil)
			return
		}
		if rte.perm == authz.PermissionPublic || rte.perm == authz.PermissionPreAuth {
			rt.serve(w, r, rte)
			return
		}
		if rt.authn == nil {
			rt.errs.write(w, r, domain.ErrUnauthenticated)
			return
		}
		ip := reqmeta.From(r.Context()).RateKey
		if rt.limits != nil && !rt.limits.failures.Peek(ip) {
			// Too many failed authentications from this address: refuse
			// before even looking at the credential (credential stuffing).
			tooMany(w, r, rt.errs)
			return
		}
		p, err := rt.authn.Authenticate(r)
		if err != nil {
			if rt.limits != nil && (errors.Is(err, domain.ErrUnauthenticated) || errors.Is(err, domain.ErrForbidden)) {
				rt.limits.failures.Allow(ip)
			}
			rt.errs.write(w, r, err)
			return
		}
		if p == nil {
			rt.errs.write(w, r, domain.ErrUnauthenticated)
			return
		}
		if rt.limits != nil && !rt.limits.perPrincipal.Allow(p.UserID) {
			tooMany(w, r, rt.errs)
			return
		}
		if !p.AllowsAction(rte.perm) {
			// The credential's scopes exclude this action. Resource-level
			// checks happen again in the service layer.
			rt.errs.write(w, r, domain.ErrForbidden)
			return
		}
		rt.serve(w, r.WithContext(authz.WithPrincipal(r.Context(), p)), rte)
	})
}

func (rt *Router) serve(w http.ResponseWriter, r *http.Request, rte route) {
	if rt.validate != nil {
		if err := rt.validate(r); err != nil {
			rt.errs.write(w, r, err)
			return
		}
	}
	rte.handler.ServeHTTP(w, r)
}
