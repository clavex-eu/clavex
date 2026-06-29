package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/clavex-eu/clavex/internal/metrics"
	"github.com/labstack/echo/v4"
)

// PrometheusMiddleware records HTTP request latency into the
// clavex_http_request_duration_seconds histogram.
// It skips the /metrics endpoint itself to avoid self-observation noise.
func PrometheusMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Path() == "/metrics" {
				return next(c)
			}
			start := time.Now()
			err := next(c)
			duration := time.Since(start).Seconds()

			code := c.Response().Status
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					code = he.Code
				} else {
					code = http.StatusInternalServerError
				}
			}

			route := c.Path()
			if route == "" {
				route = "unknown"
			}

			metrics.HTTPRequestDuration.WithLabelValues(
				c.Request().Method,
				route,
				strconv.Itoa(code),
			).Observe(duration)

			return err
		}
	}
}
