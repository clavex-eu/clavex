package handler

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// LDAPHandler manages LDAP connection configurations per org.
type LDAPHandler struct {
	repo     *repository.LDAPRepository
	userRepo *repository.UserRepository
}

func NewLDAPHandler(pool *pgxpool.Pool) *LDAPHandler {
	return &LDAPHandler{
		repo:     repository.NewLDAPRepository(pool),
		userRepo: repository.NewUserRepository(pool),
	}
}

func NewLDAPHandlerWithEnc(pool *pgxpool.Pool, enc *crypto.Encryptor) *LDAPHandler {
	return &LDAPHandler{
		repo:     repository.NewLDAPRepositoryWithEnc(pool, enc),
		userRepo: repository.NewUserRepository(pool),
	}
}

type createLDAPRequest struct {
	Name       string  `json:"name"        validate:"required"`
	Host       string  `json:"host"        validate:"required"`
	Port       int     `json:"port"        validate:"required,min=1,max=65535"`
	UseTLS     bool    `json:"use_tls"`
	BindDN     *string `json:"bind_dn"`
	BindPass   *string `json:"bind_password"`
	BaseDN     string  `json:"base_dn"     validate:"required"`
	UserFilter string  `json:"user_filter"`
}

func (h *LDAPHandler) Create(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	var req createLDAPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	conn, err := h.repo.Create(c.Request().Context(), orgID, repository.CreateLDAPParams{
		Name:       req.Name,
		Host:       req.Host,
		Port:       req.Port,
		UseTLS:     req.UseTLS,
		BindDN:     req.BindDN,
		BindPass:   req.BindPass,
		BaseDN:     req.BaseDN,
		UserFilter: req.UserFilter,
	})
	if err != nil {
		return err
	}
	return c.JSON(201, conn)
}

func (h *LDAPHandler) List(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	p := models.PageParams{}
	if v := c.QueryParam("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			p.Limit = n
		}
	}
	if v := c.QueryParam("after"); v != "" {
		if uid, e := uuid.Parse(v); e == nil {
			p.After = &uid
		} else {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cursor")
		}
	}
	page, err := h.repo.ListByOrgPage(c.Request().Context(), orgID, p)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, page)
}

func (h *LDAPHandler) Get(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	conn, err := h.repo.GetForOrg(c.Request().Context(), id, orgID)
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(200, conn)
}

type updateLDAPRequest struct {
	Name       string  `json:"name"        validate:"required"`
	Host       string  `json:"host"        validate:"required"`
	Port       int     `json:"port"        validate:"required,min=1,max=65535"`
	UseTLS     bool    `json:"use_tls"`
	BindDN     *string `json:"bind_dn"`
	BindPass   *string `json:"bind_password"` // omit to leave password unchanged
	BaseDN     string  `json:"base_dn"     validate:"required"`
	UserFilter string  `json:"user_filter"`
	IsActive   bool    `json:"is_active"`
}

func (h *LDAPHandler) Update(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	var req updateLDAPRequest
	if err := bindAndValidate(c, &req); err != nil {
		return err
	}
	conn, err := h.repo.Update(c.Request().Context(), id, repository.UpdateLDAPParams{
		Name:       req.Name,
		Host:       req.Host,
		Port:       req.Port,
		UseTLS:     req.UseTLS,
		BindDN:     req.BindDN,
		BindPass:   req.BindPass,
		BaseDN:     req.BaseDN,
		UserFilter: req.UserFilter,
		IsActive:   req.IsActive,
	})
	if err != nil {
		return echo.ErrNotFound
	}
	return c.JSON(200, conn)
}

func (h *LDAPHandler) Delete(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return echo.ErrNotFound
	}
	return c.NoContent(204)
}

// TestConnection dials the LDAP server, optionally binds, and returns the result.
// POST /api/v1/organizations/:org_id/ldap/:id/test
func (h *LDAPHandler) TestConnection(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(c.Request().Context(), id, orgID); err != nil {
		return echo.ErrNotFound
	}
	conn, err := h.repo.GetByIDFull(c.Request().Context(), id)
	if err != nil {
		return echo.ErrNotFound
	}

	l, dialErr := dialLDAP(conn)
	if dialErr != nil {
		return c.JSON(200, map[string]any{
			"success": false,
			"error":   dialErr.Error(),
		})
	}
	defer l.Close()

	if conn.BindDN != nil && *conn.BindDN != "" && conn.BindPassword != nil {
		if bindErr := l.Bind(*conn.BindDN, *conn.BindPassword); bindErr != nil {
			return c.JSON(200, map[string]any{
				"success": false,
				"error":   "bind failed: " + bindErr.Error(),
			})
		}
	}

	return c.JSON(200, map[string]any{"success": true})
}

// Sync performs an immediate LDAP user sync: searches the directory and
// upserts matching users into the org's users table.
// POST /api/v1/organizations/:org_id/ldap/:id/sync
func (h *LDAPHandler) Sync(c echo.Context) error {
	ctx := c.Request().Context()
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	id, err := uuidParam(c, "id")
	if err != nil {
		return err
	}
	if _, err := h.repo.GetForOrg(ctx, id, orgID); err != nil {
		return echo.ErrNotFound
	}
	conn, err := h.repo.GetByIDFull(ctx, id)
	if err != nil {
		return echo.ErrNotFound
	}

	created, updated, syncErr := runLDAPSync(ctx, conn, h.userRepo)
	if syncErr != nil {
		return c.JSON(200, map[string]any{
			"success": false,
			"error":   syncErr.Error(),
			"created": created,
			"updated": updated,
		})
	}

	_ = h.repo.TouchLastSyncAt(ctx, id)
	return c.JSON(200, map[string]any{
		"success": true,
		"created": created,
		"updated": updated,
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// dialLDAP opens a plain or TLS connection to the LDAP server.
func dialLDAP(conn *models.LDAPConnection) (*ldap3.Conn, error) {
	addr := fmt.Sprintf("%s:%d", conn.Host, conn.Port)
	if conn.UseTLS {
		return ldap3.DialURL("ldaps://"+addr, ldap3.DialWithTLSConfig(&tls.Config{ServerName: conn.Host, MinVersion: tls.VersionTLS12}))
	}
	return ldap3.DialURL("ldap://" + addr)
}

// attrVal safely reads the first value of an LDAP entry attribute.
func attrVal(entry *ldap3.Entry, attr string) string {
	v := entry.GetAttributeValues(attr)
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// runLDAPSync performs the full dial → bind → search → upsert cycle.
func runLDAPSync(ctx context.Context, conn *models.LDAPConnection, users *repository.UserRepository) (created, updated int, err error) {
	l, err := dialLDAP(conn)
	if err != nil {
		return 0, 0, fmt.Errorf("dial: %w", err)
	}
	defer l.Close()

	if conn.BindDN != nil && *conn.BindDN != "" && conn.BindPassword != nil {
		if err := l.Bind(*conn.BindDN, *conn.BindPassword); err != nil {
			return 0, 0, fmt.Errorf("bind: %w", err)
		}
	}

	filter := conn.UserFilter
	if filter == "" {
		filter = "(objectClass=person)"
	}

	// Determine email and name attribute names from the UserAttrMap.
	// Defaults follow RFC 4524 / ActiveDirectory conventions.
	emailAttr := "mail"
	firstAttr := "givenName"
	lastAttr := "sn"
	if v, ok := conn.UserAttrMap["email"]; ok && v != "" {
		emailAttr = v
	}
	if v, ok := conn.UserAttrMap["first_name"]; ok && v != "" {
		firstAttr = v
	}
	if v, ok := conn.UserAttrMap["last_name"]; ok && v != "" {
		lastAttr = v
	}

	req := ldap3.NewSearchRequest(
		conn.BaseDN,
		ldap3.ScopeWholeSubtree,
		ldap3.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{emailAttr, firstAttr, lastAttr},
		nil,
	)

	sr, err := l.SearchWithPaging(req, 500)
	if err != nil {
		return 0, 0, fmt.Errorf("search: %w", err)
	}

	for _, entry := range sr.Entries {
		select {
		case <-ctx.Done():
			return created, updated, ctx.Err()
		default:
		}

		email := strings.ToLower(strings.TrimSpace(attrVal(entry, emailAttr)))
		if email == "" {
			continue
		}
		first := attrVal(entry, firstAttr)
		last := attrVal(entry, lastAttr)

		var fp, lp *string
		if first != "" {
			fp = &first
		}
		if last != "" {
			lp = &last
		}

		existing, getErr := users.GetByEmail(ctx, conn.OrgID, email)
		if getErr != nil {
			// User does not exist — create
			if _, createErr := users.Create(ctx, conn.OrgID, email, fp, lp); createErr == nil {
				created++
			}
		} else {
			// User exists — update name if changed
			needsUpdate := (fp != nil && (existing.FirstName == nil || *existing.FirstName != *fp)) ||
				(lp != nil && (existing.LastName == nil || *existing.LastName != *lp))
			if needsUpdate {
				if _, updateErr := users.Update(ctx, existing.ID, fp, lp, nil, nil); updateErr == nil {
					updated++
				}
			}
		}
	}

	return created, updated, nil
}
