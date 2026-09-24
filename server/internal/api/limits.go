// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
	"github.com/yamatrireddy/kilnci/server/internal/platform/ratelimit"
	"github.com/yamatrireddy/kilnci/server/internal/platform/reqmeta"
)

// RateLimits configures request rate limits (security-standards §12).
// Values are events per minute; zero values get safe defaults.
type RateLimits struct {
	PerIP             float64 // all /api/ requests per client IP
	AuthPerIP         float64 // /api/v1/auth/* requests per client IP
	AuthFailuresPerIP float64 // failed authentications per client IP
	PerPrincipal      float64 // authenticated requests per user
	Now               func() time.Time
}

type limiters struct {
	perIP        *ratelimit.Keyed
	authPerIP    *ratelimit.Keyed
	failures     *ratelimit.Keyed
	perPrincipal *ratelimit.Keyed
}

const maxTrackedKeys = 100_000

func newLimiters(c RateLimits) *limiters {
	def := func(v, d float64) float64 {
		if v <= 0 {
			return d
		}
		return v
	}
	perIP := def(c.PerIP, 600)
	auth := def(c.AuthPerIP, 30)
	fail := def(c.AuthFailuresPerIP, 20)
	pp := def(c.PerPrincipal, 1200)
	return &limiters{
		perIP:        ratelimit.New(perIP, int(perIP/5)+1, maxTrackedKeys, c.Now),
		authPerIP:    ratelimit.New(auth, int(auth/3)+1, maxTrackedKeys, c.Now),
		failures:     ratelimit.New(fail, int(fail), maxTrackedKeys, c.Now),
		perPrincipal: ratelimit.New(pp, int(pp/5)+1, maxTrackedKeys, c.Now),
	}
}

// rateLimit applies per-IP limits to API routes. Health probes are exempt so
// orchestrators are never throttled.
func rateLimit(l *limiters, errs errorWriter) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}
			ip := reqmeta.From(r.Context()).RateKey
			if !l.perIP.Allow(ip) || (strings.HasPrefix(r.URL.Path, "/api/v1/auth/") && !l.authPerIP.Allow(ip)) {
				tooMany(w, r, errs)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func tooMany(w http.ResponseWriter, r *http.Request, errs errorWriter) {
	w.Header().Set("Retry-After", "60")
	errs.write(w, r, domain.ErrRateLimited)
}

// requestMeta records the client IP and user agent for rate limiting and audit.
func requestMeta(ips clientIPResolver) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr := ips.resolve(r)
			ctx := reqmeta.With(r.Context(), reqmeta.Meta{
				ClientIP: addr.String(), UserAgent: r.UserAgent(), RateKey: ratelimit.NetworkKey(addr),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
