// SPDX-License-Identifier: Apache-2.0

package reqmeta

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWithFrom_SanitizesUserAgent(t *testing.T) {
	ctx := With(context.Background(), Meta{ClientIP: "203.0.113.1", UserAgent: "evil\r\nX-Injected: 1\x1b[31m" + strings.Repeat("a", 500)})
	m := From(ctx)
	if m.ClientIP != "203.0.113.1" {
		t.Fatalf("ClientIP = %q", m.ClientIP)
	}
	if strings.ContainsAny(m.UserAgent, "\r\n\x1b") || len(m.UserAgent) > maxUserAgent {
		t.Fatalf("UserAgent not sanitized: %q", m.UserAgent)
	}
	for _, ua := range []string{strings.Repeat("a", 255) + "é", strings.Repeat("日", 200), "rtl\u202eexe.txt", "bad\xff\xfeutf8"} {
		got := From(With(context.Background(), Meta{UserAgent: ua})).UserAgent
		if !utf8.ValidString(got) || len(got) > maxUserAgent || strings.ContainsRune(got, 0x202e) {
			t.Fatalf("sanitize(%q) = %q: invalid UTF-8 or too long", ua, got)
		}
	}
	if (From(context.Background()) != Meta{}) {
		t.Fatal("empty context should yield zero Meta")
	}
}
