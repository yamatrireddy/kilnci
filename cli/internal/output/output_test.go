// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yamatrireddy/kilnci/cli/internal/client"
)

func TestWrite_Text(t *testing.T) {
	tests := []struct {
		name string
		res  client.LintResult
		want string
	}{
		{name: "valid", res: client.LintResult{Valid: true},
			want: ".kiln/pipeline.yaml: pipeline is valid\n"},
		{name: "one problem", res: client.LintResult{Problems: []client.LintProblem{
			{Path: "jobs.build.image", Line: 4, Message: "is required"}}},
			want: ".kiln/pipeline.yaml:4: jobs.build.image: is required\n1 problem found\n"},
		{name: "no line or path", res: client.LintResult{Problems: []client.LintProblem{
			{Message: "document exceeds 256 KiB"}, {Path: "version", Line: 1, Message: "must be 1"}}},
			want: ".kiln/pipeline.yaml: document exceeds 256 KiB\n.kiln/pipeline.yaml:1: version: must be 1\n2 problems found\n"},
		{name: "hostile text is neutralized", res: client.LintResult{Problems: []client.LintProblem{
			{Path: "jobs.\x1b]8;;https://evil\x07x", Line: 2, Message: "bad\u202eevil\nnext"}}},
			want: ".kiln/pipeline.yaml:2: jobs.?]8;;https://evil?x: badevil?next\n1 problem found\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := Write(&b, FormatText, ".kiln/pipeline.yaml", tt.res); err != nil {
				t.Fatal(err)
			}
			if b.String() != tt.want {
				t.Fatalf("got\n%q\nwant\n%q", b.String(), tt.want)
			}
		})
	}
}

func TestWrite_JSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, FormatJSON, "p.yaml", client.LintResult{Valid: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"problems": []`) {
		t.Fatalf("valid result must have an empty problems array: %s", b.String())
	}
	b.Reset()
	in := client.LintResult{Problems: []client.LintProblem{{Path: "a", Line: 1, Message: "x\x1b[31m"}}}
	if err := Write(&b, FormatJSON, "p.yaml", in); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(b.String(), 0x1b) {
		t.Fatalf("raw escape in JSON output: %q", b.String())
	}
	b.Reset()
	hostile := client.LintProblem{Path: "p\u200b", Line: 1, Message: "x\u009b31m\u202ey\x7f\U000e0041\u2028"}
	if err := Write(&b, FormatJSON, "p.yaml", client.LintResult{Problems: []client.LintProblem{hostile}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range b.String() {
		if r != '\n' && unsafeRune(r) {
			t.Fatalf("raw %U in JSON output: %q", r, b.String())
		}
	}
	var hostileOut struct{ Problems []client.LintProblem }
	if err := json.Unmarshal(b.Bytes(), &hostileOut); err != nil || hostileOut.Problems[0] != hostile {
		t.Fatalf("escaping is not lossless: %+v %v", hostileOut, err)
	}
	b.Reset()
	if err := Write(&b, FormatJSON, "p.yaml", in); err != nil {
		t.Fatal(err)
	}
	var out struct {
		File     string               `json:"file"`
		Valid    bool                 `json:"valid"`
		Problems []client.LintProblem `json:"problems"`
	}
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.File != "p.yaml" || out.Valid || len(out.Problems) != 1 || out.Problems[0] != in.Problems[0] {
		t.Fatalf("round trip %+v", out)
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "json"} {
		if f, err := ParseFormat(s); err != nil || string(f) != s {
			t.Fatalf("ParseFormat(%q) = %q, %v", s, f, err)
		}
	}
	if _, err := ParseFormat("xml\x1b"); err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("err = %q", err)
	}
}

func TestClean(t *testing.T) {
	tests := map[string]string{
		"plain ascii":           "plain ascii",
		"tab\there":             "tab?here",
		"del\x7f":               "del?",
		"c1\u009b31m":           "c1?31m",
		"ünïcode ok":            "ünïcode ok",
		"a\u2066b\u2069c\u200f": "abc",
		"zero\u200bwidth\ufeff": "zerowidth",
		"tag\U000e0041":         "tag",
		"soft\u00adhyphen":      "softhyphen",
		"line\u2028para\u2029":  "line?para?",
	}
	for in, want := range tests {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}
