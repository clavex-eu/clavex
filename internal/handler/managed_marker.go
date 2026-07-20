package handler

import (
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
)

// managedMarkerFromRequest extracts the declarative-management marker from the
// inbound request headers. The Kubernetes operator sets X-Clavex-Managed-By
// (and optionally X-Clavex-Managed-Ref) on every create/update; a UI /
// clavexctl / direct-API request sends neither, yielding an inactive marker
// that ApplyManagedMarker leaves untouched. X-Clavex-Managed-Release: true
// disowns the resource (clears the marker) without changing its config.
func managedMarkerFromRequest(c echo.Context) repository.ManagedMarkerInput {
	h := c.Request().Header
	return repository.ManagedMarkerInput{
		By:      strings.TrimSpace(h.Get(repository.HeaderManagedBy)),
		Ref:     strings.TrimSpace(h.Get(repository.HeaderManagedRef)),
		Release: strings.EqualFold(strings.TrimSpace(h.Get(repository.HeaderManagedRelease)), "true"),
	}
}

// reflectManagedMarker mirrors an applied marker onto the in-memory model so
// the JSON response matches the persisted state without a re-read. An inactive
// marker leaves the model untouched (an ordinary edit keeps whatever marker the
// resource already carried).
func reflectManagedMarker(mm *models.ManagedMarker, m repository.ManagedMarkerInput) {
	switch {
	case m.Release:
		mm.ManagedBy = nil
		mm.ManagedRef = nil
	case m.By != "":
		by := m.By
		mm.ManagedBy = &by
		if ref := m.Ref; ref != "" {
			mm.ManagedRef = &ref
		} else {
			mm.ManagedRef = nil
		}
	}
}
