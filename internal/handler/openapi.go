package handler

import (
	"embed"
	"net/http"

	"github.com/labstack/echo/v4"
)

//go:embed spec/openapi.json
var openapiFS embed.FS

// OpenAPI serves the embedded OpenAPI 3.1 specification.
// GET /api/v1/openapi.json
func OpenAPI(c echo.Context) error {
	data, err := openapiFS.ReadFile("spec/openapi.json")
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSONBlob(http.StatusOK, data)
}
