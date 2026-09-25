// SPDX-License-Identifier: Apache-2.0

package dag

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPlan_OrdersDependenciesFirstDeterministically(t *testing.T) {
	nodes := []Node{
		{ID: "deploy", Needs: []string{"test", "build"}},
		{ID: "lint"},
		{ID: "build", Needs: []string{"lint"}},
		{ID: "test", Needs: []string{"build"}},
		{ID: "docs"},
	}
	for range 5 {
		got, err := Plan(nodes)
		if err != nil {
			t.Fatal(err)
		}
		// lint (index 1) and docs (4) start ready; lint is taken first, then
		// build becomes ready and sorts before docs, and so on.
		want := []string{"lint", "build", "test", "deploy", "docs"}
		if !slices.Equal(got, want) {
			t.Fatalf("Plan = %v, want %v", got, want)
		}
	}
}

func TestPlan_RejectsInvalidGraphs(t *testing.T) {
	cases := []struct {
		name  string
		nodes []Node
		msg   string
	}{
		{"duplicate", []Node{{ID: "a"}, {ID: "a"}}, "more than once"},
		{"self", []Node{{ID: "a", Needs: []string{"a"}}}, "needs itself"},
		{"unknown", []Node{{ID: "a", Needs: []string{"ghost"}}}, "unknown job"},
		{"repeated dep", []Node{{ID: "a"}, {ID: "b", Needs: []string{"a", "a"}}}, "more than once"},
		{"cycle", []Node{{ID: "a", Needs: []string{"c"}}, {ID: "b", Needs: []string{"a"}}, {ID: "c", Needs: []string{"b"}}, {ID: "d"}}, "cycle (a, b, c)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Plan(c.nodes)
			var ge *GraphError
			if !errors.As(err, &ge) || !errors.Is(err, ErrInvalidGraph) {
				t.Fatalf("Plan err = %v, want GraphError", err)
			}
			if !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("error %q does not mention %q", err, c.msg)
			}
		})
	}
}

func TestPlan_LargeChainIsLinear(t *testing.T) {
	const n = 2000
	nodes := make([]Node, n)
	for i := range nodes {
		nodes[i].ID = "j" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		if i > 0 {
			nodes[i].Needs = []string{nodes[i-1].ID}
		}
	}
	got, err := Plan(nodes)
	if err != nil || len(got) != n || got[n-1] != nodes[n-1].ID {
		t.Fatalf("Plan chain: len=%d err=%v", len(got), err)
	}
}

func TestAdvance(t *testing.T) {
	nodes := []Node{
		{ID: "lint"},
		{ID: "build"},
		{ID: "test", Needs: []string{"build"}},
		{ID: "deploy", Needs: []string{"test", "lint"}},
		{ID: "notify", Needs: []string{"deploy"}},
	}
	cases := []struct {
		name     string
		outcomes map[string]Outcome
		ready    []string
		skip     []string
	}{
		{"start", map[string]Outcome{}, []string{"lint", "build"}, nil},
		{"partial", map[string]Outcome{"lint": Succeeded, "build": Active}, nil, nil},
		{"build done", map[string]Outcome{"lint": Active, "build": Succeeded}, []string{"test"}, nil},
		{"all deps done", map[string]Outcome{"lint": Succeeded, "build": Succeeded, "test": Succeeded}, []string{"deploy"}, nil},
		{"failure cascades", map[string]Outcome{"lint": Succeeded, "build": Blocked}, nil, []string{"test", "deploy", "notify"}},
		{"one of two deps failed", map[string]Outcome{"lint": Blocked, "build": Active}, nil, []string{"deploy", "notify"}},
		{"finished", map[string]Outcome{"lint": Succeeded, "build": Succeeded, "test": Succeeded, "deploy": Succeeded, "notify": Active}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ready, skip := Advance(nodes, c.outcomes)
			if !slices.Equal(ready, c.ready) || !slices.Equal(skip, c.skip) {
				t.Fatalf("Advance = ready %v skip %v, want ready %v skip %v", ready, skip, c.ready, c.skip)
			}
		})
	}
}

func TestAdvance_InvalidGraphDoesNothing(t *testing.T) {
	ready, skip := Advance([]Node{{ID: "a", Needs: []string{"a"}}}, nil)
	if ready != nil || skip != nil {
		t.Fatalf("Advance on invalid graph = %v %v", ready, skip)
	}
}
