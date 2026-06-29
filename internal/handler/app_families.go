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

// AppFamilyHandler manages application families (cross-app SSO groups).
type AppFamilyHandler struct {
	repo *repository.AppFamilyRepository
}

func NewAppFamilyHandler(pool *pgxpool.Pool) *AppFamilyHandler {
	return &AppFamilyHandler{repo: repository.NewAppFamilyRepository(pool)}
}

type appFamilyMemberView struct {
	FamilyID             uuid.UUID  `json:"family_id"`
	ClientID             string     `json:"client_id"`
	BackchannelLogoutURI *string    `json:"backchannel_logout_uri,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

type appFamilyView struct {
	ID          uuid.UUID              `json:"id"`
	OrgID       uuid.UUID              `json:"org_id"`
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Members     []appFamilyMemberView  `json:"members"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

func toFamilyView(f *models.AppFamily) *appFamilyView {
	v := &appFamilyView{
		ID: f.ID, OrgID: f.OrgID, Name: f.Name, Description: f.Description,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
	v.Members = make([]appFamilyMemberView, 0, len(f.Members))
	for _, m := range f.Members {
		v.Members = append(v.Members, appFamilyMemberView{
			FamilyID: m.FamilyID, ClientID: m.ClientID,
			BackchannelLogoutURI: m.BackchannelLogoutURI, CreatedAt: m.CreatedAt,
		})
	}
	return v
}

func (h *AppFamilyHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	list, err := h.repo.List(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	views := make([]*appFamilyView, 0, len(list))
	for _, f := range list {
		views = append(views, toFamilyView(f))
	}
	return c.JSON(http.StatusOK, views)
}

func (h *AppFamilyHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	f, err := h.repo.Create(c.Request().Context(), repository.CreateAppFamilyParams{
		OrgID: orgID, Name: req.Name, Description: req.Description,
	})
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, toFamilyView(f))
}

func (h *AppFamilyHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "family_id")
	if err != nil {
		return err
	}
	f, err := h.repo.GetByID(c.Request().Context(), orgID, id)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, toFamilyView(f))
}

func (h *AppFamilyHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "family_id")
	if err != nil {
		return err
	}
	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	f, err := h.repo.Update(c.Request().Context(), orgID, id, repository.UpdateAppFamilyParams{
		Name: req.Name, Description: req.Description,
	})
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(http.StatusOK, toFamilyView(f))
}

func (h *AppFamilyHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "family_id")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.Request().Context(), orgID, id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *AppFamilyHandler) AddMember(c echo.Context) error {
	_, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	familyID, err := uuidParam(c, "family_id")
	if err != nil {
		return err
	}
	var req struct {
		ClientID             string  `json:"client_id"`
		BackchannelLogoutURI *string `json:"backchannel_logout_uri"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	m, err := h.repo.AddMember(c.Request().Context(), familyID, req.ClientID, req.BackchannelLogoutURI)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusCreated, appFamilyMemberView{
		FamilyID: m.FamilyID, ClientID: m.ClientID,
		BackchannelLogoutURI: m.BackchannelLogoutURI, CreatedAt: m.CreatedAt,
	})
}

func (h *AppFamilyHandler) RemoveMember(c echo.Context) error {
	_, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	familyID, err := uuidParam(c, "family_id")
	if err != nil {
		return err
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_id is required")
	}
	if err := h.repo.RemoveMember(c.Request().Context(), familyID, clientID); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(http.StatusNoContent)
}
