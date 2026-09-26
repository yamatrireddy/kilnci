// SPDX-License-Identifier: Apache-2.0

package github

import (
	"errors"
	"strings"
	"testing"
)

var secret = []byte("test-webhook-secret-not-real")

func TestVerify(t *testing.T) {
	body := []byte(`{"zen":"Keep it logically awesome."}`)
	good := Sign(secret, body)
	if err := Verify(secret, body, good); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		secret []byte
		body   []byte
		header string
	}{
		"tampered body":  {secret, append([]byte(" "), body...), good},
		"wrong secret":   {[]byte("other"), body, good},
		"empty secret":   {nil, body, Sign(nil, body)},
		"sha1 header":    {secret, body, "sha1=" + strings.TrimPrefix(good, "sha256=")},
		"no prefix":      {secret, body, strings.TrimPrefix(good, "sha256=")},
		"not hex":        {secret, body, "sha256=zz"},
		"short":          {secret, body, "sha256=abcd"},
		"missing header": {secret, body, ""},
	}
	for name, c := range cases {
		if err := Verify(c.secret, c.body, c.header); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPullRequest_IsForkFailsClosed(t *testing.T) {
	var same, fork, deleted PullRequest
	if err := Decode([]byte(`{"pull_request":{"head":{"repo":{"id":5}},"base":{"repo":{"id":5}}}}`), &same); err != nil {
		t.Fatal(err)
	}
	_ = Decode([]byte(`{"pull_request":{"head":{"repo":{"id":6}},"base":{"repo":{"id":5}}}}`), &fork)
	_ = Decode([]byte(`{"pull_request":{"head":{"repo":null},"base":{"repo":{"id":5}}}}`), &deleted)
	if same.IsFork() || !fork.IsFork() || !deleted.IsFork() {
		t.Fatalf("IsFork: same=%v fork=%v deleted=%v", same.IsFork(), fork.IsFork(), deleted.IsFork())
	}
	// Name-based spoofing: same full_name, different ID.
	var spoof PullRequest
	_ = Decode([]byte(`{"pull_request":{"head":{"repo":{"id":7,"full_name":"acme/app"}},"base":{"repo":{"id":5,"full_name":"acme/app"}}}}`), &spoof)
	if !spoof.IsFork() {
		t.Fatal("same name, different repository ID must be a fork")
	}
}

func TestDecodeAndHelpers(t *testing.T) {
	var p Push
	if err := Decode([]byte("{not json"), &p); err == nil || strings.Contains(err.Error(), "not json") {
		t.Fatalf("decode error = %v", err)
	}
	if !Supported("push") || Supported("workflow_run") {
		t.Fatal("Supported")
	}
	for _, ok := range []string{"72d3162e-cc78-11e3-81ab-4c9367dc0958"} {
		if !ValidDeliveryID(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "a b", "x/../y", strings.Repeat("a", 101)} {
		if ValidDeliveryID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("body"), "sha256=00")
	f.Fuzz(func(t *testing.T, body []byte, header string) {
		if Verify(secret, body, header) == nil && header != Sign(secret, body) {
			// Only the exact signature (case-insensitive hex) may verify.
			if !strings.EqualFold(header, Sign(secret, body)) {
				t.Fatalf("unexpected verification: %q", header)
			}
		}
	})
}
