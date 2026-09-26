// SPDX-License-Identifier: Apache-2.0

//go:build integration

package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	wh "github.com/yamatrireddy/kilnci/server/internal/webhooks/github"
)

func webhook(event, body, sig string) []reqOpt {
	return []reqOpt{
		withHeader(wh.EventHeader, event),
		withHeader(wh.DeliveryHeader, fmt.Sprintf("d-%d", time.Now().UnixNano())),
		withHeader(wh.SignatureHeader, sig),
	}
}

// TestGitHubWebhook_SignatureAndLimits: ingest is public but verified before
// the body is parsed (ADR-0008 §3), and accepts bodies up to 5 MiB.
func TestGitHubWebhook_SignatureAndLimits(t *testing.T) {
	e := newEnv(t)
	secret := []byte(testWebhookSecret)
	const path = "/api/v1/webhooks/github"

	ping := `{"zen":"Design for failure.","hook_id":1}`
	e.mustStatus(e.do(anonymous, http.MethodPost, path, ping, webhook("ping", ping, wh.Sign(secret, []byte(ping)))...), http.StatusAccepted)

	// Wrong or missing signatures: 401, even for garbage that is not JSON.
	notJSON := "{not json"
	rec := e.do(anonymous, http.MethodPost, path, notJSON, webhook("push", notJSON, "sha256=deadbeef")...)
	e.mustStatus(rec, http.StatusUnauthorized)
	rec = e.do(anonymous, http.MethodPost, path, ping, webhook("push", ping, wh.Sign([]byte("wrong-secret-0123456789"), []byte(ping)))...)
	e.mustStatus(rec, http.StatusUnauthorized)

	// Unsupported events are acknowledged and ignored.
	e.mustStatus(e.do(anonymous, http.MethodPost, path, ping, webhook("workflow_run", ping, wh.Sign(secret, []byte(ping)))...), http.StatusAccepted)

	// Larger than the 1 MiB API limit but within the 5 MiB webhook limit.
	big := `{"pad":"` + strings.Repeat("x", 2<<20) + `"}`
	e.mustStatus(e.do(anonymous, http.MethodPost, path, big, webhook("ping", big, wh.Sign(secret, []byte(big)))...), http.StatusAccepted)
	huge := `{"pad":"` + strings.Repeat("x", 6<<20) + `"}`
	e.mustStatus(e.do(anonymous, http.MethodPost, path, huge, webhook("ping", huge, wh.Sign(secret, []byte(huge)))...), http.StatusRequestEntityTooLarge)
	// The general API limit still applies elsewhere.
	e.mustStatus(e.do(anonymous, http.MethodPost, "/api/v1/auth/token", big), http.StatusRequestEntityTooLarge)
}
