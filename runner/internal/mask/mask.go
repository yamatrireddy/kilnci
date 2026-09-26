// SPDX-License-Identifier: Apache-2.0

// Package mask removes sensitive values from a job's output stream before
// any byte leaves the runner (invariant 4, threat T-27).
//
// For every value it masks the raw bytes, standard and URL-safe base64 (at
// all three byte alignments, so a value embedded in larger encoded data is
// still caught), hex, URL query escaping, and each line of a multi-line
// value. Matches split across Write calls are caught by holding back the
// last len(longest variant)-1 bytes until more data or Close arrives.
//
// Masking is a safety net, not a security boundary: code that is given a
// secret can always exfiltrate it. The primary control is not giving
// secrets to untrusted code.
package mask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

// Writer masks values in everything written to it and forwards the result
// to the underlying writer. It is safe for concurrent use.
type Writer struct {
	mu       sync.Mutex
	w        io.Writer
	patterns [][]byte // longest first
	byFirst  map[byte][][]byte
	hold     int // bytes held back for matches split across writes
	buf      []byte
	closed   bool
}

// New returns a Writer that masks values (and their encodings) written to w.
func New(w io.Writer, values []string) *Writer {
	set := map[string]bool{}
	for _, v := range values {
		for _, variant := range Variants(v) {
			if len(variant) >= minLen {
				set[variant] = true
			}
		}
	}
	patterns := make([][]byte, 0, len(set))
	maxLen := 0
	for p := range set {
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
	byFirst := map[byte][][]byte{}
	for _, p := range patterns {
		byFirst[p[0]] = append(byFirst[p[0]], p)
	}
	return &Writer{w: w, patterns: patterns, byFirst: byFirst, hold: hold}
}

// Variants returns the encodings of v that are masked.
func Variants(v string) []string {
	if v == "" {
		return nil
	}
	out := []string{v, hex.EncodeToString([]byte(v)), url.QueryEscape(v), url.PathEscape(v)}
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

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("mask: writer closed")

// Write masks p (together with held-back bytes) and forwards everything that
// can no longer be part of a match.
func (m *Writer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, ErrClosed
	}
	m.buf = append(m.buf, p...)
	m.buf = m.replace(m.buf)
	if len(m.buf) > m.hold {
		n := len(m.buf) - m.hold
		if _, err := m.w.Write(m.buf[:n]); err != nil {
			return 0, err //nolint:wrapcheck // pass through the sink's error
		}
		m.buf = append(m.buf[:0], m.buf[n:]...)
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
	if len(m.buf) == 0 {
		return nil
	}
	out := m.replace(m.buf)
	m.buf = nil
	_, err := m.w.Write(out)
	return err //nolint:wrapcheck // pass through the sink's error
}

// replace masks every occurrence of every pattern in b. Overlapping or
// adjacent matches are merged into one replacement, so masking one value can
// never leave part of another (overlapping) value visible.
func (m *Writer) replace(b []byte) []byte {
	if len(m.patterns) == 0 || len(b) == 0 {
		return b
	}
	// end[i] > i marks that a match covers b[i:end[i]].
	covered := make([]bool, len(b))
	any := false
	for i := range b {
		for _, p := range m.byFirst[b[i]] {
			if bytes.HasPrefix(b[i:], p) {
				for j := i; j < i+len(p); j++ {
					covered[j] = true
				}
				any = true
				break // patterns are longest first
			}
		}
	}
	if !any {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if !covered[i] {
			out = append(out, b[i])
			i++
			continue
		}
		out = append(out, Replacement...)
		for i < len(b) && covered[i] {
			i++
		}
	}
	return out
}
