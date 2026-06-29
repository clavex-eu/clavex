package handler

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/clavex-eu/clavex/internal/assets"
	"github.com/clavex-eu/clavex/internal/config"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const (
	maxAssetSizeBytes = 5 * 1024 * 1024 // 5 MB
)

var allowedAssetTypes = map[string]bool{
	"logo": true, "favicon": true, "background": true, "icon": true,
}

var allowedContentTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/svg+xml": true,
	"image/webp": true, "image/x-icon": true, "image/gif": true,
}

// OrgAssetHandler handles org binary asset uploads backed by S3-compatible storage
// or a local filesystem fallback.
type OrgAssetHandler struct {
	repo    *repository.OrgAssetRepository
	storage assets.Backend // nil when no storage backend is configured
}

func NewOrgAssetHandler(pool *pgxpool.Pool, cfg *config.Config) *OrgAssetHandler {
	h := &OrgAssetHandler{repo: repository.NewOrgAssetRepository(pool)}
	switch {
	case cfg.Storage.Endpoint != "":
		h.storage = assets.NewS3Client(assets.S3Config{
			Endpoint:      cfg.Storage.Endpoint,
			Bucket:        cfg.Storage.Bucket,
			Region:        cfg.Storage.Region,
			AccessKey:     cfg.Storage.AccessKey,
			SecretKey:     cfg.Storage.SecretKey,
			PublicBaseURL: cfg.Storage.PublicBaseURL,
		})
	case cfg.Storage.LocalDir != "":
		baseURL := cfg.Storage.LocalBaseURL
		if baseURL == "" {
			baseURL = cfg.HTTP.IssuerURLFromBase(cfg.Auth.IssuerBase, "") + "/_assets"
		}
		if lc, err := assets.NewLocalClient(cfg.Storage.LocalDir, baseURL); err == nil {
			h.storage = lc
		}
	}
	return h
}

// List returns all assets for an org.
// GET /api/v1/organizations/:org_id/assets
func (h *OrgAssetHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	list, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	if list == nil {
		list = []*models.OrgAsset{}
	}
	return c.JSON(http.StatusOK, list)
}

// Upload handles multipart/form-data upload of a single org asset.
// PUT /api/v1/organizations/:org_id/assets/:asset_type
//
// Form fields:
//
//	file  — the binary file (required)
func (h *OrgAssetHandler) Upload(c echo.Context) error {
	if h.storage == nil {
		return echo.NewHTTPError(http.StatusNotImplemented,
			"object storage not configured; set storage.endpoint (S3) or storage.local_dir (filesystem)")
	}

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	assetType := c.Param("asset_type")
	if !allowedAssetTypes[assetType] {
		return echo.NewHTTPError(http.StatusBadRequest, "asset_type must be one of: logo, favicon, background, icon")
	}

	if err := c.Request().ParseMultipartForm(maxAssetSizeBytes); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid multipart form")
	}

	fh, err := c.FormFile("file")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "file field is required")
	}
	if fh.Size > maxAssetSizeBytes {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "file exceeds 5 MB limit")
	}

	f, err := fh.Open()
	if err != nil {
		return echo.ErrInternalServerError
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxAssetSizeBytes))
	if err != nil {
		return echo.ErrInternalServerError
	}

	contentType := fh.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/png"
	}
	// Strip charset etc.
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	if !allowedContentTypes[contentType] {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType,
			"content type not allowed; use image/png, image/jpeg, image/svg+xml, image/webp, image/x-icon")
	}

	// Determine file extension.
	ext := path.Ext(fh.Filename)
	if ext == "" {
		ext = extensionForContentType(contentType)
	}
	s3Key := fmt.Sprintf("orgs/%s/%s%s", orgID.String(), assetType, ext)

	ctx := c.Request().Context()
	url, err := h.storage.PutObject(ctx, s3Key, contentType, data)
	if err != nil {
		c.Logger().Errorf("assets: s3 put: %v", err)
		return echo.NewHTTPError(http.StatusBadGateway, "storage upload failed")
	}

	asset, err := h.repo.Upsert(ctx, repository.UpsertAssetParams{
		OrgID:       orgID,
		AssetType:   assetType,
		S3Key:       s3Key,
		ContentType: contentType,
		SizeBytes:   int64(len(data)),
		URL:         url,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, asset)
}

// Delete removes an asset from storage and the DB.
// DELETE /api/v1/organizations/:org_id/assets/:asset_type
func (h *OrgAssetHandler) Delete(c echo.Context) error {
	if h.storage == nil {
		return echo.NewHTTPError(http.StatusNotImplemented,
			"object storage not configured; set storage.endpoint (S3) or storage.local_dir (filesystem)")
	}

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	assetType := c.Param("asset_type")
	if !allowedAssetTypes[assetType] {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid asset_type")
	}

	s3Key, err := h.repo.Delete(c.Request().Context(), orgID, assetType)
	if err != nil {
		return echo.ErrNotFound
	}
	// Best-effort deletion from storage backend.
	go func() {
		_ = h.storage.DeleteObject(c.Request().Context(), s3Key)
	}()
	return c.NoContent(http.StatusNoContent)
}

func extensionForContentType(ct string) string {
	switch ct {
	case "image/jpeg":
		return ".jpg"
	case "image/svg+xml":
		return ".svg"
	case "image/webp":
		return ".webp"
	case "image/x-icon":
		return ".ico"
	case "image/gif":
		return ".gif"
	default:
		return ".png"
	}
}
