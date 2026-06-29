// Package tracing initialises the OpenTelemetry SDK and exposes a per-package
// tracer helper used across the OIDC critical path.
//
// Usage:
//
//	shutdown, err := tracing.Init(cfg.Telemetry)
//	defer shutdown(ctx)
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config mirrors TelemetryConfig from the application config.
type Config struct {
	Enabled      bool    `mapstructure:"enabled"`
	OTLPEndpoint string  `mapstructure:"otlp_endpoint"` // e.g. "http://otel-collector:4318"
	ServiceName  string  `mapstructure:"service_name"`
	SampleRate   float64 `mapstructure:"sample_rate"` // 0.0–1.0; default 1.0
}

// Tracer returns a named tracer scoped to the given instrumentation library.
// If the global provider has not been initialised (e.g. in tests), this returns
// a no-op tracer automatically.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// Init configures the global OTEL TracerProvider with an OTLP/HTTP exporter.
// It is safe to call before config is fully loaded — if cfg.Enabled is false,
// a no-op provider is installed and a no-op shutdown is returned.
func Init(cfg Config) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "clavex"
	}
	sampleRate := cfg.SampleRate
	if sampleRate <= 0 {
		sampleRate = 1.0
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: build resource: %w", err)
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint),
	}

	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("tracing: create OTLP exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))),
	)

	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}
