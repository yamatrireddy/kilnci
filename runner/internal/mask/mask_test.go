// SPDX-License-Identifier: Apache-2.0

package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// wrap splits s into lines of width characters, as `base64 -w<width>` does.
func wrap(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteByte('\n')
		s = s[width:]
	}
	b.WriteString(s)
	b.WriteByte('\n')
	return b.String()
}

// assertNoBase64Leak fails if any 8-character run of any aligned base64
// encoding of value survives in got, ignoring line breaks.
func assertNoBase64Leak(t *testing.T, got, value string) {
	t.Helper()
	flat := strings.NewReplacer("\n", "", "\r", "").Replace(got)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for _, s := range alignedBase64(enc, []byte(value)) {
			for i := 0; i+8 <= len(s); i++ {
				if strings.Contains(flat, s[i:i+8]) {
					t.Fatalf("base64 run %q leaked in %q", s[i:i+8], got)
				}
			}
		}
	}
}

func TestMask_LineWrappedBase64(t *testing.T) {
	// Values are assembled at runtime so no credential-shaped literal is
	// committed (gitleaks scans the tree).
	long := "tok-" + strings.Repeat("Qx7vR2mZ", 9) // 76 bytes, > 57
	user := "ci-bot"
	pass := strings.Repeat("Lk3", 22) + "-end" // 70 bytes
	b64 := base64.StdEncoding.EncodeToString
	tests := []struct {
		name   string
		value  string
		stream string
		keep   []string // surrounding text that must survive
	}{
		{
			name:   "echo value | base64 (wrapped at 76)",
			value:  long,
			stream: "$ echo \"$S\" | base64\n" + wrap(b64([]byte(long+"\n")), 76) + "done\n",
			keep:   []string{"$ echo \"$S\" | base64\n", "done\n"},
		},
		{
			name:   "basic credential wrapped at 76",
			value:  pass,
			stream: wrap(b64([]byte(user+":"+pass)), 76),
		},
		{
			name:   "basic credential wrapped at 64 (openssl)",
			value:  pass,
			stream: wrap(b64([]byte(user+":"+pass)), 64),
		},
		{
			name:   "authorization header",
			value:  pass,
			stream: "Authorization: Basic " + b64([]byte(user+":"+pass)) + "\n",
			keep:   []string{"Authorization: Basic "},
		},
		{
			name:   "value after a prefix wrapped at 76",
			value:  long,
			stream: wrap(b64([]byte("prefix-data-of-odd-length:"+long+":suffix")), 76),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.stream, "\n") {
				t.Fatal("test stream must contain a line break")
			}
			got := mask(t, []string{tt.value}, tt.stream)
			assertNoBase64Leak(t, got, tt.value)
			if !strings.Contains(got, Replacement) {
				t.Fatalf("nothing masked: %q", got)
			}
			for _, k := range tt.keep {
				if !strings.Contains(got, k) {
					t.Fatalf("context %q lost: %q", k, got)
				}
			}
		})
	}
}

func TestMask_HexAndJSONForms(t *testing.T) {
	quoted := `pa"ss\wo` + "rd-<&>-\u00e9\t1"
	marshal := func(v string) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	noHTML := func(v string) string {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(b.String(), "\n")
	}
	tests := []struct {
		name   string
		value  string
		stream string
		want   string
	}{
		{"lower hex", secret, "h=" + hex.EncodeToString([]byte(secret)) + "\n", "h=***\n"},
		{"upper hex (%X)", secret, "h=" + strings.ToUpper(hex.EncodeToString([]byte(secret))) + "\n", "h=***\n"},
		{"json.Marshal", quoted, `{"token":` + marshal(quoted) + "}\n", `{"token":"***"}` + "\n"},
		{"json without HTML escaping", quoted, `{"token":` + noHTML(quoted) + "}\n", `{"token":"***"}` + "\n"},
		{"raw value with quote", quoted, "v=" + quoted + "\n", "v=***\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mask(t, []string{tt.value}, tt.stream); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMask_ShorterPrefixPatternWaitsForLongerMatch(t *testing.T) {
	values := []string{"hunter2-SUFFIXSECRET", "hunter2"}
	tests := []struct {
		name   string
		chunks []string
		want   string
	}{
		{"longer value split after the shorter one", []string{"pw=hunter2", "-SUFFIXSECRET"}, "pw=***"},
		{"longer value split later", []string{"pw=hunter2-SUF", "FIXSECRET\n"}, "pw=***\n"},
		{"only the shorter value", []string{"pw=hunter2", " ok"}, "pw=*** ok"},
		{"longer value padded past the hold", []string{"pw=hunter2", "-SUFFIXSECRET" + strings.Repeat(".", 100)}, "pw=***" + strings.Repeat(".", 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mask(t, values, tt.chunks...); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// splitMix is a tiny deterministic PRNG for test splits (math/rand is
// banned by lint policy, and tests must be deterministic).
type splitMix uint64

func (s *splitMix) next() uint64 {
	*s += 0x9e3779b97f4a7c15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// overlapping is a set of values whose variants overlap and prefix each
// other, including a credential and its base64 form.
func overlapping() []string {
	cred := "ci-bot:" + strings.Repeat("Pq8", 7)
	return []string{
		"hunter2-SUFFIXSECRET", "hunter2", "SECRET-tail-9",
		"abcdef", "defghijk",
		cred, base64.StdEncoding.EncodeToString([]byte(cred)),
	}
}

func overlappingStream() []byte {
	v := overlapping()
	var b bytes.Buffer
	b.WriteString("pw=hunter2-SUFFIXSECRET-tail-9 and hunter2 alone; xxabcdefghijkyy\n")
	b.WriteString("Authorization: Basic " + v[6] + "\n")
	b.WriteString(wrap(base64.StdEncoding.EncodeToString([]byte("x:"+v[0]+v[5]+v[2])), 76))
	b.WriteString(hex.EncodeToString([]byte(v[0])) + " " + url.QueryEscape(v[5]) + " hunter2hunter2\n")
	return b.Bytes()
}

func maskChunks(t testing.TB, values []string, in []byte, cuts []int) string {
	t.Helper()
	var out bytes.Buffer
	w := New(&out, values)
	prev := 0
	for _, c := range append(cuts, len(in)) {
		if _, err := w.Write(in[prev:c]); err != nil {
			t.Fatal(err)
		}
		prev = c
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// TestMask_OutputIndependentOfWriteBoundaries: masking the same input gives
// identical output however it is split into writes.
func TestMask_OutputIndependentOfWriteBoundaries(t *testing.T) {
	values, in := overlapping(), overlappingStream()
	want := maskChunks(t, values, in, nil)
	if strings.Contains(want, "hunter2") || strings.Contains(want, "SUFFIX") {
		t.Fatalf("one-shot output leaks: %q", want)
	}
	for k := 0; k <= len(in); k++ {
		if got := maskChunks(t, values, in, []int{k}); got != want {
			t.Fatalf("split at %d:\n got %q\nwant %q", k, got, want)
		}
	}
	rng := splitMix(1)
	for round := range 300 {
		cuts := randomCuts(&rng, len(in), 1+round%20)
		if got := maskChunks(t, values, in, cuts); got != want {
			t.Fatalf("cuts %v:\n got %q\nwant %q", cuts, got, want)
		}
	}
}

// randomCuts returns up to n sorted cut positions in [0, size].
func randomCuts(rng *splitMix, size, n int) []int {
	cuts := make([]int, 0, n)
	for range n {
		cuts = append(cuts, int(rng.next()>>33)%(size+1)) // 31 bits: fits any int
	}
	for i := 1; i < len(cuts); i++ { // insertion sort; n is small
		for j := i; j > 0 && cuts[j] < cuts[j-1]; j-- {
			cuts[j], cuts[j-1] = cuts[j-1], cuts[j]
		}
	}
	return cuts
}

// FuzzMask_SplitInvariant: for overlapping values, output never depends on
// write boundaries.
func FuzzMask_SplitInvariant(f *testing.F) {
	f.Add(overlappingStream(), uint64(7), uint8(5))
	f.Add([]byte("pw=hunter2-SUFFIXSECRET"), uint64(1), uint8(1))
	f.Fuzz(func(t *testing.T, in []byte, seed uint64, n uint8) {
		if len(in) > 4096 {
			return
		}
		values := overlapping()
		want := maskChunks(t, values, in, nil)
		rng := splitMix(seed)
		cuts := randomCuts(&rng, len(in), int(n%32))
		if got := maskChunks(t, values, in, cuts); got != want {
			t.Fatalf("cuts %v:\n got %q\nwant %q", cuts, got, want)
		}
	})
}
