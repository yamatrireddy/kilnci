// SPDX-License-Identifier: Apache-2.0

// Package spec is the only parser for pipeline YAML (.kiln/pipeline.yaml),
// which is attacker-controlled input (threat T-07, T-24).
//
// Parse is a safe loader: it bounds document size, nesting depth, and node
// count before interpreting anything; rejects anchors, aliases, merge keys,
// explicit tags, duplicate keys, multiple documents, and unknown fields; and
// never echoes field values in errors. It decodes by walking the YAML node
// tree by hand rather than unmarshaling into structs, so every accepted field
// is explicit. The contract is docs/specs/pipeline.md; fixtures live in
// testdata/ (valid/ and invalid/), and FuzzParse runs on a schedule in CI.
package spec
