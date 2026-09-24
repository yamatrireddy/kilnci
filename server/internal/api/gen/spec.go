// SPDX-License-Identifier: Apache-2.0

package gen

import (
	_ "embed"
	"fmt"

	"github.com/getkin/kin-openapi/openapi3"
)

// specYAML is a copy of docs/api/openapi.yaml made by `make generate`; CI
// fails if it drifts from the source.
//
//go:embed openapi.yaml
var specYAML []byte

// Spec parses and validates the embedded OpenAPI document. The document is
// Kiln's own, compiled into the binary; it is never loaded from user input.
func Spec() (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	spec, err := loader.LoadFromData(specYAML)
	if err != nil {
		return nil, fmt.Errorf("parse embedded OpenAPI spec: %w", err)
	}
	if err := spec.Validate(loader.Context); err != nil {
		return nil, fmt.Errorf("validate embedded OpenAPI spec: %w", err)
	}
	return spec, nil
}
