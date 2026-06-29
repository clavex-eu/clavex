package handler

import (
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ServiceAccountHandler exposes CRUD operations for org service accounts.
type ServiceAccountHandler struct {
	repo *repository.ServiceAccountRepository
}

func NewServiceAccountHandler(pool *pgxpool.Pool) *ServiceAccountHandler {
	return &ServiceAccountHandler{repo: repository.NewServiceAccountRepository(pool)}
}

type saView struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	ClientID    string     `json:"client_id"`
	Scopes      []string   `json:"scopes"`
	IsActive    bool       `json:"is_active"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func saToView(sa *models.ServiceAccount) *saView {
	return &saView{
		ID: sa.ID, OrgID: sa.OrgID, Name: sa.Name, Description: sa.Description,
		ClientID: sa.ClientID, Scopes: sa.Scopes, IsActive: sa.IsActive,
		LastUsedAt: sa.LastUsedAt, CreatedAt: sa.CreatedAt, UpdatedAt: sa.UpdatedAt,
	}
}

func (h *ServiceAccountHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	list, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	views := make([]*saView, 0, len(list))
	for _, sa := range list {
		views = append(views, saToView(sa))
	}
	return c.JSON(http.StatusOK, views)
}

func (h *ServiceAccountHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Name        string   `json:"name"`
		Description *string  `json:"description"`
		Scopes      []string `json:"scopes"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	sa, plain, err := h.repo.Create(c.Request().Context(), repository.CreateServiceAccountParams{
		OrgID: orgID, Name: req.Name, Description: req.Description, Scopes: req.Scopes,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{
		"service_account": saToView(sa), "client_secret": plain,
		"secret_note": "Store this secret securely. It will not be shown again.",
	})
}

func (h *ServiceAccountHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	sa, err := h.repo.GetByID(c.Request().Context(), orgID, id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, saToView(sa))
}

func (h *ServiceAccountHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	var req struct {
		Name        string   `json:"name"`
		Description *string  `json:"description"`
		Scopes      []string `json:"scopes"`
		IsActive    *bool    `json:"is_active"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	sa, err := h.repo.Update(c.Request().Context(), orgID, id, repository.UpdateServiceAccountParams{
		Name: req.Name, Description: req.Description, Scopes: req.Scopes, IsActive: req.IsActive,
	})
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, saToView(sa))
}

func (h *ServiceAccountHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), orgID, id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *ServiceAccountHandler) RotateSecret(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	sa, plain, err := h.repo.RotateSecret(c.Request().Context(), orgID, id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"service_account": saToView(sa), "client_secret": plain,
		"secret_note": "Store this secret securely. It will not be shown again.",
	})
}
