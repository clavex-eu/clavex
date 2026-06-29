package handler

import (
	"net/http"
	"strconv"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// MDSHandler exposes admin-only endpoints for browsing the FIDO MDS3 catalog
// and inspecting the last sync status.
//
// Routes (all require org-scoped authentication):
//   GET  /api/v1/organizations/:org_id/mds/entries          — paginated catalog
//   GET  /api/v1/organizations/:org_id/mds/entries/:aaguid  — single entry
//   GET  /api/v1/organizations/:org_id/mds/sync             — last sync status
//   POST /api/v1/organizations/:org_id/mds/sync             — trigger refresh
type MDSHandler struct {
	repo     *repository.MDSRepository
	pool     *pgxpool.Pool
	endpoint string // empty → use default https://mds3.fidoalliance.org
}

// NewMDSHandler creates the handler backed by the given pool.
func NewMDSHandler(pool *pgxpool.Pool) *MDSHandler {
	return &MDSHandler{
		repo: repository.NewMDSRepository(pool),
		pool: pool,
	}
}

// WithEndpoint overrides the MDS3 download endpoint (useful for testing).
func (h *MDSHandler) WithEndpoint(ep string) *MDSHandler {
	h.endpoint = ep
	return h
}

// ListEntries returns a paginated slice of the local MDS3 catalog.
// GET /api/v1/organizations/:org_id/mds/entries
//
// Query params:
//   q          – free-text search on description and aaguid
//   cert_level – minimum certification level filter ("L1", "L2", "L2+", …)
//   limit      – page size (default 50, max 200)
//   offset     – pagination offset (default 0)
//   exclude_revoked – "true" to hide revoked entries
func (h *MDSHandler) ListEntries(c echo.Context) error {
	ctx := c.Request().Context()

	filter := repository.MDSListFilter{
		Search: c.QueryParam("q"),
		Limit:  50,
		Offset: 0,
	}
	if lv := c.QueryParam("limit"); lv != "" {
		if n, err := strconv.Atoi(lv); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			filter.Limit = n
		}
	}
	if ov := c.QueryParam("offset"); ov != "" {
		if n, err := strconv.Atoi(ov); err == nil && n >= 0 {
			filter.Offset = n
		}
	}
	filter.MinCertLevel = c.QueryParam("cert_level")
	if c.QueryParam("exclude_revoked") == "true" {
		filter.ExcludeRevoked = true
	}
	if aaguids := c.QueryParams()["aaguid"]; len(aaguids) > 0 {
		filter.AAGUIDs = aaguids
	}

	entries, total, err := h.repo.ListEntries(ctx, filter)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  filter.Offset,
		"limit":   filter.Limit,
	})
}

// GetEntry returns a single MDS3 entry by AAGUID.
// GET /api/v1/organizations/:org_id/mds/entries/:aaguid
func (h *MDSHandler) GetEntry(c echo.Context) error {
	ctx := c.Request().Context()
	aaguid := c.Param("aaguid")
	if aaguid == "" {
		return echo.ErrBadRequest
	}
	entry, err := h.repo.GetByAAGUID(ctx, aaguid)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if entry == nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, entry)
}

// GetSyncStatus returns metadata about the last MDS3 sync.
// GET /api/v1/organizations/:org_id/mds/sync
func (h *MDSHandler) GetSyncStatus(c echo.Context) error {
	ctx := c.Request().Context()
	status, err := h.repo.GetSyncStatus(ctx)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, status)
}

// TriggerSync starts an out-of-band MDS3 refresh. The sync runs in the
// background; the response returns 202 immediately.
// POST /api/v1/organizations/:org_id/mds/sync
func (h *MDSHandler) TriggerSync(c echo.Context) error {
	// Verify the caller is an org admin of this org (org_id is validated by
	// the router middleware). We don't expose org_id data here — we just run
	// a global refresh since MDS3 is a single global feed.
	_ = uuid.MustParse(c.Param("org_id")) // validated by middleware, panic if missing

	go worker.RunMDS3SyncOnce(c.Request().Context(), h.pool, h.endpoint)

	return c.JSON(http.StatusAccepted, map[string]string{
		"message": "MDS3 refresh triggered",
	})
}
