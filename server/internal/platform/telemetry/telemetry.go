// SPDX-License-Identifier: Apache-2.0

// Package telemetry configures OpenTelemetry tracing for the server.
//
// W3C trace context propagation is always enabled. Spans are exported over
// OTLP/HTTP only when an endpoint is configured; the exporter uses
// platform/httpclient like every other outbound call.
package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Options configures Setup.
type Options struct {
	ServiceVersion string
	// OTLPEndpoint is host:port of an OTLP/HTTP collector; empty disables export.
	OTLPEndpoint string
	Insecure     bool
	// HTTPClient is the client used to reach the collector.
	HTTPClient *http.Client
}

// Setup installs the global propagator and tracer provider. The returned
// function flushes and stops export; call it during shutdown.
func Setup(ctx context.Context, opts Options) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if opts.OTLPEndpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	eopts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(opts.OTLPEndpoint), otlptracehttp.WithHTTPClient(opts.HTTPClient)}
	if opts.Insecure {
		eopts = append(eopts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, eopts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}
	res := resource.NewSchemaless(
		semconv.ServiceName("kiln-server"),
		semconv.ServiceVersion(opts.ServiceVersion),
	)
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
