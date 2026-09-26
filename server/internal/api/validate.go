// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"

	"github.com/yamatrireddy/kilnci/server/internal/api/gen"
	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// specValidator checks every request against docs/api/openapi.yaml before it
// reaches a handler (security-standards §5). Services validate business rules
// again; this layer rejects anything the contract does not allow, including
// unknown JSON fields (additionalProperties: false).
type specValidator struct {
	router routers.Router
}

func loadSpec() (*openapi3.T, error) {
	spec, err := gen.Spec()
	if err != nil {
		return nil, fmt.Errorf("load embedded OpenAPI spec: %w", err)
	}
	return spec, nil
}

func newSpecValidator(spec *openapi3.T) (*specValidator, error) {
	r, err := legacy.NewRouter(spec)
	if err != nil {
		return nil, fmt.Errorf("build OpenAPI router: %w", err)
	}
	return &specValidator{router: r}, nil
}

var validationOptions = &openapi3filter.Options{
	// Authentication is enforced by the Router, not by the spec validator.
	AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
	MultiError:         true,
}

// webhookValidationOptions skip the body: webhook signatures must be
// verified before the body is parsed at all (SS §11, ADR-0008 §3).
var webhookValidationOptions = &openapi3filter.Options{
	AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
	MultiError:         true,
	ExcludeRequestBody: true,
}

// validate returns nil, a *domain.ValidationError naming the invalid fields
// (never echoing their values), or an internal error if the route is missing
// from the spec (a conformance bug, caught by TestRoutesMatchSpec).
func (v *specValidator) validate(r *http.Request) error {
	route, params, err := v.router.FindRoute(r)
	if err != nil {
		return fmt.Errorf("route %s %s missing from OpenAPI spec: %w", r.Method, stateFrom(r).routeName(), err)
	}
	opts := validationOptions
	if strings.HasPrefix(r.URL.Path, webhookPrefix) {
		opts = webhookValidationOptions
	}
	in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route, Options: opts}
	err = openapi3filter.ValidateRequest(r.Context(), in)
	if err == nil {
		return nil
	}
	var maxBytes *http.MaxBytesError
	if errors.As(err, &maxBytes) {
		return fmt.Errorf("validate request: %w", err)
	}
	return toValidationError(err)
}

func toValidationError(err error) *domain.ValidationError {
	ve := &domain.ValidationError{}
	var multi openapi3.MultiError
	errs := []error{err}
	if errors.As(err, &multi) {
		errs = multi
	}
	for _, e := range errs {
		var reqErr *openapi3filter.RequestError
		switch {
		case errors.As(e, &reqErr) && reqErr.Parameter != nil:
			ve.Add(reqErr.Parameter.Name, "invalid "+reqErr.Parameter.In+" parameter")
		case errors.As(e, &reqErr) && reqErr.RequestBody != nil:
			ve.Add("body", "does not match the request schema")
		default:
			ve.Add("request", "does not match the API specification")
		}
	}
	return ve
}
