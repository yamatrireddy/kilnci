// SPDX-License-Identifier: Apache-2.0

package ids

import (
	"strings"
	"testing"
	"time"
)

func TestGenerator_New_IsValidAndUnique(t *testing.T) {
	g := NewGenerator(nil)
	seen := make(map[string]bool)
	for range 1000 {
		id := g.New()
		if !Valid(id) {
			t.Fatalf("generated invalid id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestGenerator_New_SortsByTime(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	g := NewGenerator(func() time.Time { return now })
	a := g.New()
	now = now.Add(time.Millisecond)
	b := g.New()
	if a[:10] >= b[:10] {
		t.Fatalf("timestamp prefix not increasing: %q >= %q", a, b)
	}
}

func TestEncode_KnownValue(t *testing.T) {
	var b [16]byte
	if got := encode(b); got != strings.Repeat("0", 26) {
		t.Fatalf("zero = %q", got)
	}
	for i := range b {
		b[i] = 0xff
	}
	if got := encode(b); got != "7"+strings.Repeat("Z", 25) {
		t.Fatalf("max = %q", got)
	}
}

func TestValid(t *testing.T) {
	tests := map[string]bool{
		"01ARZ3NDEKTSV4RRFFQ69G5FAV":   true,
		"01arz3ndektsv4rrffq69g5fav":   false, // lowercase rejected: IDs are canonical
		"01ARZ3NDEKTSV4RRFFQ69G5FA":    false,
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX":  false,
		"81ARZ3NDEKTSV4RRFFQ69G5FAV":   false, // overflows 128 bits
		"01ARZ3NDEKTSV4RRFFQ69G5FAI":   false, // I is not in the alphabet
		"01ARZ3NDEKTSV4RRFFQ69G5F/../": false,
		"":                             false,
	}
	for in, want := range tests {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%q) = %v, want %v", in, got, want)
		}
	}
}
