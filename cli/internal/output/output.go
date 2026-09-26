// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/yamatrireddy/kilnci/cli/internal/client"
)

// Format selects how results are written.
type Format string

// Supported formats.
const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case FormatText, FormatJSON:
		return f, nil
	default:
		return "", fmt.Errorf("unknown format %q (want text or json)", Clean(s))
	}
}

// Write renders the lint result for file in format f.
func Write(w io.Writer, f Format, file string, r client.LintResult) error {
	if f == FormatJSON {
		return writeJSON(w, file, r)
	}
	return writeText(w, file, r)
}

// writeText prints one problem per line in the file:line: path: message
// shape editors and CI annotators recognize.
func writeText(w io.Writer, file string, r client.LintResult) error {
	file = Clean(file)
	var b strings.Builder
	if r.Valid {
		fmt.Fprintf(&b, "%s: pipeline is valid\n", file)
	}
	for _, p := range r.Problems {
		b.WriteString(file)
		if p.Line > 0 {
			fmt.Fprintf(&b, ":%d", p.Line)
		}
		b.WriteString(": ")
		if p.Path != "" {
			b.WriteString(Clean(p.Path))
			b.WriteString(": ")
		}
		b.WriteString(Clean(p.Message))
		b.WriteByte('\n')
	}
	if n := len(r.Problems); n > 0 {
		fmt.Fprintf(&b, "%d problem%s found\n", n, plural(n))
	}
	_, err := io.WriteString(w, b.String())
	return err //nolint:wrapcheck // io pass-through
}

func writeJSON(w io.Writer, file string, r client.LintResult) error {
	problems := r.Problems
	if problems == nil {
		problems = []client.LintProblem{}
	}
	data, err := json.MarshalIndent(struct {
		File     string               `json:"file"`
		Valid    bool                 `json:"valid"`
		Problems []client.LintProblem `json:"problems"`
	}{file, r.Valid, problems}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	_, err = io.WriteString(w, escapeJSON(string(data))+"\n")
	return err //nolint:wrapcheck // io pass-through
}

// escapeJSON rewrites the runes Clean neutralizes as \uXXXX escapes.
// encoding/json escapes only C0 controls, so DEL, C1 controls, and Unicode
// format characters would otherwise reach a terminal raw. Outside strings,
// JSON is plain ASCII, so every such rune is inside a string, where the
// escape is lossless for machine consumers.
func escapeJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		// A raw newline is indentation: encoding/json escapes those in strings.
		if r == '\n' || !unsafeRune(r) {
			b.WriteRune(r)
			continue
		}
		if r > 0xffff {
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// Clean makes untrusted text safe to print to a terminal: control
// characters (C0, DEL, C1, which covers ANSI escape sequences) and line or
// paragraph separators become '?', and Unicode format characters are
// removed. Format characters include bidirectional overrides and isolates
// (Trojan Source, CVE-2021-42574) and zero-width characters, which could
// reorder or disguise what the reader sees.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case !unsafeRune(r):
			return r
		case unicode.Is(unicode.Cf, r):
			return -1
		default:
			return '?'
		}
	}, s)
}

// unsafeRune reports whether r must not reach a terminal raw.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
