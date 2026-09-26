// SPDX-License-Identifier: Apache-2.0

package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
)

const secret = "hunter2-SECRET-value/+="

func mask(t *testing.T, values []string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	w := New(&out, values)
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestMask_AllEncodings(t *testing.T) {
	encodings := map[string]string{
		"raw":          secret,
		"base64":       base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64url":    base64.URLEncoding.EncodeToString([]byte(secret)),
		"hex":          hex.EncodeToString([]byte(secret)),
		"query":        url.QueryEscape(secret),
		"path":         url.PathEscape(secret),
		"embedded b64": base64.StdEncoding.EncodeToString([]byte("user:" + secret + "@host")),
		"offset2 b64":  base64.StdEncoding.EncodeToString([]byte("ab" + secret)),
	}
	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			got := mask(t, []string{secret}, "before ", enc, " after\n")
			if strings.Contains(got, enc) && name != "embedded b64" && name != "offset2 b64" {
				t.Fatalf("%s not masked: %q", name, got)
			}
			for _, v := range Variants(secret) {
				if len(v) >= 8 && strings.Contains(got, v) {
					t.Fatalf("variant %q leaked in %q", v, got)
				}
			}
			if !strings.HasPrefix(got, "before ") || !strings.HasSuffix(got, " after\n") || !strings.Contains(got, Replacement) {
				t.Fatalf("output mangled: %q", got)
			}
		})
	}
}

func TestMask_SplitAcrossWrites(t *testing.T) {
	for split := 1; split < len(secret); split++ {
		got := mask(t, []string{secret}, "x"+secret[:split], secret[split:]+"y")
		if got != "x"+Replacement+"y" {
			t.Fatalf("split %d: %q", split, got)
		}
	}
	// One byte at a time.
	in := "a " + secret + " b " + secret
	chunks := make([]string, len(in))
	for i := range in {
		chunks[i] = in[i : i+1]
	}
	if got := mask(t, []string{secret}, chunks...); got != "a *** b ***" {
		t.Fatalf("bytewise = %q", got)
	}
}

func TestMask_MultiLineValues(t *testing.T) {
	key := "-----BEGIN KEY-----\nMIIEpAIBAAKCAQEAxyz\nabcdEFGH1234\n-----END KEY-----"
	got := mask(t, []string{key}, "line: abcdEFGH1234\n", "other: MIIEpAIBAAKCAQEAxyz\n")
	if strings.Contains(got, "abcdEFGH1234") || strings.Contains(got, "MIIEpAIBAAKCAQEAxyz") {
		t.Fatalf("multi-line pieces leaked: %q", got)
	}
}

func TestMask_OverlappingValuesNeverPartiallyLeak(t *testing.T) {
	got := mask(t, []string{"abcdef", "defghijk"}, "xxabcdefghijkyy")
	if got != "xx***yy" {
		t.Fatalf("overlap = %q", got)
	}
}

func TestMask_ShortAndEmptyValuesIgnored(t *testing.T) {
	if got := mask(t, []string{"", "ab"}, "ab cd"); got != "ab cd" {
		t.Fatalf("short values masked: %q", got)
	}
	if got := mask(t, nil, "plain"); got != "plain" {
		t.Fatalf("no values = %q", got)
	}
}

func TestMask_WriteAfterClose(t *testing.T) {
	w := New(&bytes.Buffer{}, []string{secret})
	_ = w.Close()
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("sink down") }

func TestMask_PropagatesSinkErrors(t *testing.T) {
	w := New(failWriter{}, []string{secret})
	if _, err := w.Write(bytes.Repeat([]byte("x"), 100)); err == nil {
		t.Fatal("sink error swallowed")
	}
}

// FuzzMask: however output is chunked, no variant of the value (8+ chars)
// ever appears in the masked stream.
func FuzzMask(f *testing.F) {
	f.Add([]byte("prefix"), []byte("suffix"), "s3cr3t-token-value", uint8(3))
	f.Add([]byte{}, []byte("\x00\xff"), "multi\nline\nsecret", uint8(1))
	f.Fuzz(func(t *testing.T, pre, post []byte, value string, chunk uint8) {
		if len(value) < 8 || len(value) > 256 {
			return
		}
		size := int(chunk%16) + 1
		stream := append(append(append([]byte{}, pre...), value...), post...)
		stream = append(stream, []byte(base64.StdEncoding.EncodeToString([]byte(value)))...)
		var out bytes.Buffer
		w := New(&out, []string{value})
		for i := 0; i < len(stream); i += size {
			end := min(i+size, len(stream))
			if _, err := w.Write(stream[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.Bytes(), []byte(value)) {
			t.Fatalf("value leaked: %q", out.Bytes())
		}
		if b := base64.StdEncoding.EncodeToString([]byte(value)); len(b) >= 8 && bytes.Contains(out.Bytes(), []byte(b[:len(b)-4])) {
			t.Fatalf("base64 leaked: %q", out.Bytes())
		}
	})
}
