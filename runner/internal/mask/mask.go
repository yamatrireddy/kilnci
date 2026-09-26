// SPDX-License-Identifier: Apache-2.0

// Package mask removes sensitive values from a job's output stream before
// any byte leaves the runner (invariant 4, threat T-27).
//
// For every value it masks the raw bytes, standard and URL-safe base64 (at
// all three byte alignments, so a value embedded in larger encoded data is
// still caught), lower- and upper-case hex, URL query and path escaping, the
// JSON string escaping, and each line of a multi-line value.
//
// Base64 is often line-wrapped (coreutils base64 wraps at 76 columns, PEM and
// openssl at 64), and the wrap phase depends on whatever precedes the value
// in the encoded stream. So besides each whole aligned encoding, every
// wrapWindow-character substring of it is masked, as are its prefixes and
// suffixes down to the minimum length. Each line of a wrapped encoding is
// then masked whatever the wrap width (>= wrapWindow) or phase; at most
// minLen-1 characters at a line edge can remain visible.
//
// Matches split across Write calls are caught by holding back the last
// len(longest variant)-1 bytes until more data or Close arrives. A match is
// only decided once every longer pattern that could start at the same
// position has been fully seen, so the output does not depend on how the
// input was split into writes.
//
// Masking is a safety net, not a security boundary: code that is given a
// secret can always exfiltrate it. The primary control is not giving
// secrets to untrusted code.
package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Replacement is written in place of every masked value.
const Replacement = "***"

// minLen is the shortest variant masked; shorter strings would mask
// ordinary output and reveal little.
const minLen = 4

// wrapWindow is the length of the base64 substrings masked to catch
// line-wrapped encodings. It must not exceed the narrowest wrap width we
// want to cover (64, as PEM and openssl use) and is long enough (96 bits of
// the value) that it does not match unrelated output.
const wrapWindow = 16

// Size limits (security review). Masking cost grows with the values: the
// held-back window grows with the longest encoded variant, and the
// wrapped-base64 windows with each value's length.
const (
	// MaxValueBytes is the largest value Check accepts.
	MaxValueBytes = 64 << 10
	// MaxTotalBytes is the most Check accepts across all values.
	MaxTotalBytes = 256 << 10
	// maxWrapValueBytes is the largest value whose line-wrapped base64 is
	// masked; longer values are still masked in every other form.
	maxWrapValueBytes = 4 << 10
)

// ErrTooLarge means the values to mask exceed MaxValueBytes or
// MaxTotalBytes.
var ErrTooLarge = errors.New("mask: values too large to mask")

// Check reports whether values are within the size limits. Callers must
// not run a job whose values fail Check: masking them would use unbounded
// memory and delay output, so the job fails closed instead.
func Check(values []string) error {
	total := 0
	for _, v := range values {
		if len(v) > MaxValueBytes {
			return fmt.Errorf("%w: a value is %d bytes (limit %d)", ErrTooLarge, len(v), MaxValueBytes)
		}
		total += len(v)
	}
	if total > MaxTotalBytes {
		return fmt.Errorf("%w: values total %d bytes (limit %d)", ErrTooLarge, total, MaxTotalBytes)
	}
	return nil
}

// Writer masks values in everything written to it and forwards the result
// to the underlying writer. It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	byFirst [256][][]byte       // exact patterns by first byte, longest first
	windows map[string]struct{} // wrapWindow-long base64 substrings
	winHead []uint64            // prefilter bitset over the first 4 bytes of windows
	hold    int                 // bytes held back for matches split across writes
	buf     []byte              // input not yet emitted, unmasked
	carry   int                 // leading bytes of buf covered by an already-decided match
	masking bool                // the last byte emitted was part of a masked run
	closed  bool
}

// New returns a Writer that masks values (and their encodings) written to w.
// Callers check values with Check first. Line-wrapped base64 is masked only
// for values of at most 4 KiB.
func New(w io.Writer, values []string) *Writer {
	exact := map[string]bool{}
	windows := map[string]struct{}{}
	for _, v := range values {
		for _, variant := range Variants(v) {
			if len(variant) >= minLen {
				exact[variant] = true
			}
		}
		if len(v) > maxWrapValueBytes {
			continue
		}
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			for _, s := range alignedBase64(enc, []byte(v)) {
				addWrapPieces(s, exact, windows)
			}
		}
	}
	patterns := make([][]byte, 0, len(exact))
	maxLen := 0
	if len(windows) > 0 {
		maxLen = wrapWindow
	}
	for p := range exact {
		patterns = append(patterns, []byte(p))
		maxLen = max(maxLen, len(p))
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i]) != len(patterns[j]) {
			return len(patterns[i]) > len(patterns[j])
		}
		return bytes.Compare(patterns[i], patterns[j]) < 0
	})
	hold := 0
	if maxLen > 0 {
		hold = maxLen - 1
	}
	m := &Writer{w: w, windows: windows, hold: hold}
	for _, p := range patterns {
		m.byFirst[p[0]] = append(m.byFirst[p[0]], p)
	}
	if len(windows) > 0 {
		m.winHead = make([]uint64, 1<<headBits/64)
		for win := range windows {
			h := headHash([]byte(win[:4]))
			m.winHead[h/64] |= 1 << (h % 64)
		}
	}
	return m
}

// Variants returns the encodings of v that are masked as whole strings.
// Line-wrapped base64 is handled separately (see the package comment).
func Variants(v string) []string {
	if v == "" {
		return nil
	}
	h := hex.EncodeToString([]byte(v))
	out := []string{v, h, strings.ToUpper(h), url.QueryEscape(v), url.PathEscape(v)}
	for _, escapeHTML := range []bool{true, false} {
		if j := jsonEscaped(v, escapeHTML); j != v {
			out = append(out, j)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		out = append(out, alignedBase64(enc, []byte(v))...)
	}
	if strings.ContainsAny(v, "\r\n") {
		for line := range strings.FieldsFuncSeq(v, func(r rune) bool { return r == '\n' || r == '\r' }) {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

// jsonEscaped returns v as it appears inside a JSON string literal: as
// encoding/json writes it (escapeHTML) or as most other encoders (jq,
// JSON.stringify) do.
func jsonEscaped(v string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(v); err != nil {
		return v // unreachable: a string always encodes
	}
	s := strings.TrimSuffix(b.String(), "\n")
	return s[1 : len(s)-1] // drop the quotes
}

// alignedBase64 returns the base64 characters determined only by v's bytes
// when v starts at each of the three possible offsets within a 3-byte group.
func alignedBase64(enc *base64.Encoding, v []byte) []string {
	raw := enc.WithPadding(base64.NoPadding)
	var out []string
	for k := range 3 {
		in := append(make([]byte, k), v...)
		s := raw.EncodeToString(in)
		start := (8*k + 5) / 6        // first char whose 6 bits are all from v
		end := (8 * (k + len(v))) / 6 // chars before end are fully determined
		if end > len(s) {
			end = len(s)
		}
		if start < end {
			out = append(out, s[start:end])
		}
	}
	return out
}

// addWrapPieces records the patterns that mask every line of s when s is
// line-wrapped at any width >= wrapWindow and in any phase: all
// wrapWindow-long substrings (full lines and long edge pieces) and the
// shorter prefixes and suffixes (the value's pieces on its first and last
// line).
func addWrapPieces(s string, exact map[string]bool, windows map[string]struct{}) {
	for i := 0; i+wrapWindow <= len(s); i++ {
		windows[s[i:i+wrapWindow]] = struct{}{}
	}
	for n := minLen; n < min(len(s), wrapWindow); n++ {
		exact[s[:n]] = true
		exact[s[len(s)-n:]] = true
	}
}

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("mask: writer closed")

// Write masks p (together with held-back bytes) and forwards everything that
// can no longer be part of an undecided match.
func (m *Writer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrClosed
	}
	m.buf = append(m.buf, p...)
	if err := m.emit(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes the held-back bytes (masked) and closes the writer. It does
// not close the underlying writer.
func (m *Writer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	err := m.emit(true)
	m.buf = nil
	return err
}

// emit masks and writes the decided prefix of buf. The match at start
// position i is decided once i+hold < len(buf): every pattern that could
// start there then fits in buf, so the longest one is known and a shorter
// pattern that is a prefix of a longer one cannot be replaced early. With
// final set, everything is decided. Overlapping or adjacent matches merge
// into one replacement, also across calls, so masking one value never leaves
// part of an overlapping value visible and output does not depend on how the
// input was split into writes.
func (m *Writer) emit(final bool) error {
	limit := len(m.buf)
	if !final {
		limit -= m.hold
	}
	if limit <= 0 {
		return nil
	}
	covered := make([]bool, limit)
	end := m.carry // end of the furthest decided match, relative to buf
	for i := range min(m.carry, limit) {
		covered[i] = true
	}
	for i := range limit {
		n := m.matchAt(i)
		for j := i; j < min(i+n, limit); j++ {
			covered[j] = true
		}
		end = max(end, i+n)
	}
	out := make([]byte, 0, limit)
	masking := m.masking
	for i := range limit {
		if covered[i] {
			if !masking {
				out = append(out, Replacement...)
				masking = true
			}
			continue
		}
		masking = false
		out = append(out, m.buf[i])
	}
	if len(out) > 0 {
		if _, err := m.w.Write(out); err != nil {
			return err //nolint:wrapcheck // pass through the sink's error
		}
	}
	m.masking = masking
	m.carry = max(0, end-limit)
	m.buf = append(m.buf[:0], m.buf[limit:]...)
	return nil
}

// matchAt returns the length of the longest pattern matching buf at i, or 0.
func (m *Writer) matchAt(i int) int {
	b := m.buf[i:]
	n := 0
	for _, p := range m.byFirst[b[0]] {
		if bytes.HasPrefix(b, p) {
			n = len(p) // patterns are longest first
			break
		}
	}
	if n < wrapWindow && len(b) >= wrapWindow && m.winHead != nil {
		// The bitset rejects most positions before the map lookup hashes.
		if h := headHash(b); m.winHead[h/64]&(1<<(h%64)) != 0 {
			if _, ok := m.windows[string(b[:wrapWindow])]; ok {
				n = wrapWindow
			}
		}
	}
	return n
}

// headBits sizes the windows prefilter (2^headBits bits, 128 KiB), so it
// stays sparse even for values of several KiB.
const headBits = 20

// headHash maps the first four bytes of b to a prefilter bit index.
func headHash(b []byte) uint32 {
	x := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	return (x * 0x9e3779b1) >> (32 - headBits)
}
