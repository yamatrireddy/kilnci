// SPDX-License-Identifier: Apache-2.0

// Package dag plans a run's job graph: it validates dependencies (unknown
// references, self-references, cycles), produces a deterministic topological
// order, and decides which jobs become runnable or must be skipped as their
// dependencies finish. It is pure: no I/O and no knowledge of storage.
package dag

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Node is one job and the IDs of the jobs it needs.
type Node struct {
	ID    string
	Needs []string
}

// ErrInvalidGraph wraps every planning failure.
var ErrInvalidGraph = errors.New("invalid job graph")

// GraphError describes why a graph is invalid. Node is the job the problem
// was found on; Message is safe to show to the pipeline author.
type GraphError struct {
	Node    string
	Message string
}

// Error implements error.
func (e *GraphError) Error() string { return fmt.Sprintf("job %s: %s", e.Node, e.Message) }

// Unwrap makes errors.Is(err, ErrInvalidGraph) true.
func (e *GraphError) Unwrap() error { return ErrInvalidGraph }

// Plan validates nodes and returns their IDs in topological order. Ties are
// broken by input order, so the same pipeline always plans the same way.
// It reports the first problem found as a *GraphError.
func Plan(nodes []Node) ([]string, error) {
	index := make(map[string]int, len(nodes))
	for i, n := range nodes {
		if _, dup := index[n.ID]; dup {
			return nil, &GraphError{Node: n.ID, Message: "is defined more than once"}
		}
		index[n.ID] = i
	}
	indegree := make([]int, len(nodes))
	dependents := make([][]int, len(nodes))
	for i, n := range nodes {
		seen := make(map[string]bool, len(n.Needs))
		for _, dep := range n.Needs {
			if dep == n.ID {
				return nil, &GraphError{Node: n.ID, Message: "needs itself"}
			}
			if seen[dep] {
				return nil, &GraphError{Node: n.ID, Message: "lists a dependency more than once"}
			}
			seen[dep] = true
			j, ok := index[dep]
			if !ok {
				return nil, &GraphError{Node: n.ID, Message: "needs an unknown job"}
			}
			indegree[i]++
			dependents[j] = append(dependents[j], i)
		}
	}

	// Kahn's algorithm, always taking the lowest input index that is ready.
	order := make([]string, 0, len(nodes))
	var ready []int
	for i := range nodes {
		if indegree[i] == 0 {
			ready = append(ready, i)
		}
	}
	for len(ready) > 0 {
		slices.Sort(ready)
		i := ready[0]
		ready = ready[1:]
		order = append(order, nodes[i].ID)
		for _, d := range dependents[i] {
			indegree[d]--
			if indegree[d] == 0 {
				ready = append(ready, d)
			}
		}
	}
	if len(order) != len(nodes) {
		var cyclic []string
		for i, n := range nodes {
			if indegree[i] > 0 {
				cyclic = append(cyclic, n.ID)
			}
		}
		return nil, &GraphError{Node: cyclic[0], Message: "is part of a dependency cycle (" + strings.Join(cyclic, ", ") + ")"}
	}
	return order, nil
}

// Outcome is what the planner needs to know about a job's progress.
type Outcome int

// Outcomes.
const (
	// Waiting: not started, or not yet decided.
	Waiting Outcome = iota
	// Active: queued or running.
	Active
	// Succeeded: finished successfully; dependents may start.
	Succeeded
	// Blocked: failed, canceled, or skipped; dependents must be skipped.
	Blocked
)

// Advance returns the waiting jobs whose dependencies have all succeeded
// (ready to queue) and the waiting jobs with at least one blocked dependency
// (to skip). Skipping cascades: a job whose dependency is about to be skipped
// is skipped in the same call. Results follow input order. Nodes must have
// been validated by Plan.
func Advance(nodes []Node, outcomes map[string]Outcome) (ready, skip []string) {
	state := make(map[string]Outcome, len(nodes))
	for _, n := range nodes {
		state[n.ID] = outcomes[n.ID]
	}
	order, err := Plan(nodes)
	if err != nil {
		return nil, nil
	}
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	skipped := map[string]bool{}
	readySet := map[string]bool{}
	for _, id := range order { // dependencies are always decided first
		if state[id] != Waiting {
			continue
		}
		allDone, blocked := true, false
		for _, dep := range byID[id].Needs {
			switch state[dep] {
			case Blocked:
				blocked = true
			case Succeeded:
			default:
				allDone = false
			}
		}
		switch {
		case blocked:
			state[id] = Blocked
			skipped[id] = true
		case allDone:
			readySet[id] = true
		}
	}
	for _, n := range nodes {
		if skipped[n.ID] {
			skip = append(skip, n.ID)
		}
		if readySet[n.ID] {
			ready = append(ready, n.ID)
		}
	}
	return ready, skip
}
