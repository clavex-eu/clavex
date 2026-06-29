// Package scim implements a SCIM 2.0 server (RFC 7643 / RFC 7644).
// Endpoints are per-organization: /:org_slug/scim/v2/...
package scim

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/clavex-eu/clavex/internal/lifecycle"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/scimpush"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Handler is the SCIM 2.0 request handler.
type Handler struct {
	users      *repository.UserRepository
	groups     *repository.GroupRepository
	orgs       *repository.OrgRepository
	tokens     *SCIMTokenRepository
	// outboundPusher fans out SCIM 2.0 PUT/PATCH/DELETE to all active external
	// directories when a user is mutated via the inbound SCIM endpoint.
	// Nil when not configured (no push targets or pusher not wired).
	outboundPusher *scimpush.Pusher
	// jml triggers Joiner/Mover/Leaver rules after user lifecycle events.
	// Nil when not configured.
	jml *lifecycle.Engine
	// emitter records inbound SCIM operations in the structured audit log.
	// Nil when not configured.
	emitter *audit.Emitter
	// anomalyDetector counts deprovisionings per org and fires SSF+webhook
	// alerts when bulk-deprovisioning thresholds are exceeded (NIS2 §21).
	// Nil when not configured.
	anomalyDetector *AnomalyDetector
}

// New creates a SCIM handler.
func New(pool *pgxpool.Pool) *Handler {
	return &Handler{
		users:  repository.NewUserRepository(pool),
		groups: repository.NewGroupRepository(pool),
		orgs:   repository.NewOrgRepository(pool),
		tokens: NewSCIMTokenRepository(pool),
	}
}

// WithOutboundPusher attaches an outbound SCIM pusher so that changes arriving
// via the inbound SCIM endpoint are automatically propagated to all other
// configured external directories — turning Clavex into a bidirectional
// identity sync hub (Okta Workflows pattern).
func (h *Handler) WithOutboundPusher(p *scimpush.Pusher) *Handler {
	h.outboundPusher = p
	return h
}

// WithLifecycleEngine attaches the JML workflow engine so that lifecycle rules
// (Joiner/Mover/Leaver) are evaluated automatically on SCIM user events.
func (h *Handler) WithLifecycleEngine(e *lifecycle.Engine) *Handler {
	h.jml = e
	return h
}

// WithAuditEmitter attaches the audit emitter so that every inbound SCIM
// operation (create, update, deactivate, delete) is written to the structured
// audit log. Required for SOX / NIS2 identity chain-of-custody compliance.
func (h *Handler) WithAuditEmitter(e *audit.Emitter) *Handler {
	h.emitter = e
	return h
}

// WithAnomalyDetector attaches the SCIM anomaly detector. When set, every
// deprovisioning (PATCH active=false, DELETE) is counted against a per-org
// Redis sliding window; if the threshold is breached within the observation
// window the detector fires an SSF RISC account-disabled SET and a webhook
// event (NIS2 Article 21 — bulk-deprovisioning anomaly).
func (h *Handler) WithAnomalyDetector(d *AnomalyDetector) *Handler {
	h.anomalyDetector = d
	return h
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

// ResolveOrg is a middleware that loads the org from :org_slug and stores it as "scim_org".
func (h *Handler) ResolveOrg() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			slug := c.Param("org_slug")
			org, err := h.orgs.GetBySlug(c.Request().Context(), slug)
			if err != nil {
				return scimError(c, http.StatusNotFound, "Organization not found")
			}
			c.Set("scim_org", org)
			return next(c)
		}
	}
}

// RequireSCIMToken validates Bearer token for SCIM endpoints.
func (h *Handler) RequireSCIMToken() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			org, ok := c.Get("scim_org").(*models.Organization)
			if !ok || org == nil {
				return scimError(c, http.StatusUnauthorized, "Organization not found")
			}
			raw := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
			if raw == "" {
				return scimError(c, http.StatusUnauthorized, "Missing Bearer token")
			}
			hash := hashToken(raw)
			valid, err := h.tokens.Validate(c.Request().Context(), org.ID, hash)
			if err != nil || !valid {
				return scimError(c, http.StatusUnauthorized, "Invalid token")
			}
			// Update last_used_at asynchronously
			go h.tokens.TouchLastUsed(c.Request().Context(), hash) //nolint:errcheck
			return next(c)
		}
	}
}

// scimOrgID returns the org bound to the validated SCIM token.
func scimOrgID(c echo.Context) uuid.UUID {
	if org, ok := c.Get("scim_org").(*models.Organization); ok && org != nil {
		return org.ID
	}
	return uuid.Nil
}

// userInOrg loads a user only when it belongs to the SCIM token's org. On a
// cross-tenant or missing id it writes a 404 SCIM error and returns ok=false —
// SCIM tokens are scoped to one org, so they must never touch another tenant's
// users by their (global) UUID.
func (h *Handler) userInOrg(c echo.Context, id uuid.UUID) (*models.User, bool) {
	u, err := h.users.GetByID(c.Request().Context(), id)
	if err != nil || u == nil || u.OrgID != scimOrgID(c) {
		_ = scimError(c, http.StatusNotFound, "User not found")
		return nil, false
	}
	return u, true
}

// groupInOrg is the group equivalent of userInOrg.
func (h *Handler) groupInOrg(c echo.Context, id uuid.UUID) (*models.Group, bool) {
	g, err := h.groups.GetByID(c.Request().Context(), id)
	if err != nil || g == nil || g.OrgID != scimOrgID(c) {
		_ = scimError(c, http.StatusNotFound, "Group not found")
		return nil, false
	}
	return g, true
}

// memberInOrg reports whether the user belongs to the SCIM token's org, used to
// silently skip cross-org users when updating group membership.
func (h *Handler) memberInOrg(c echo.Context, id uuid.UUID) bool {
	u, err := h.users.GetByID(c.Request().Context(), id)
	return err == nil && u != nil && u.OrgID == scimOrgID(c)
}

// ─── ServiceProviderConfig ────────────────────────────────────────────────────

func (h *Handler) ServiceProviderConfig(c echo.Context) error {
	base := scimBase(c)
	return c.JSON(http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": base,
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]any{"supported": true},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "OAuth Bearer Token",
				"description":      "Authentication scheme using the Bearer Token standard",
				"specUri":          "https://www.rfc-editor.org/rfc/rfc6750",
				"documentationUri": base,
				"primary":          true,
			},
		},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     base + "/ServiceProviderConfig",
		},
	})
}

// ─── Schemas ──────────────────────────────────────────────────────────────────

func (h *Handler) Schemas(c echo.Context) error {
	base := scimBase(c)
	schemas := []map[string]any{
		userSchema(base),
		groupSchema(base),
	}
	return c.JSON(http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(schemas),
		"Resources":    schemas,
	})
}

func (h *Handler) Schema(c echo.Context) error {
	base := scimBase(c)
	id := c.Param("id")
	switch id {
	case scimUserSchema:
		return c.JSON(http.StatusOK, userSchema(base))
	case scimGroupSchema:
		return c.JSON(http.StatusOK, groupSchema(base))
	}
	return scimError(c, http.StatusNotFound, "Schema not found")
}

// ─── Users ────────────────────────────────────────────────────────────────────

func (h *Handler) ListUsers(c echo.Context) error {
	org := c.Get("scim_org").(*models.Organization)
	base := scimBase(c)
	startIndex, count := parsePagination(c)
	filter := c.QueryParam("filter")

	users, err := h.users.ListByOrg(c.Request().Context(), org.ID)
	if err != nil {
		return scimError(c, http.StatusInternalServerError, err.Error())
	}

	// Simple filter: userName eq "value" or externalId eq "value"
	if filter != "" {
		users = applyUserFilter(users, filter)
	}

	total := len(users)
	end := min(startIndex-1+count, total)
	start := startIndex - 1
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	page := users[start:end]

	resources := make([]map[string]any, len(page))
	for i, u := range page {
		resources[i] = userToSCIM(u, base)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    resources,
	})
}

func (h *Handler) GetUser(c echo.Context) error {
	base := scimBase(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid user id")
	}
	u, ok := h.userInOrg(c, id)
	if !ok {
		return nil
	}
	return c.JSON(http.StatusOK, userToSCIM(u, base))
}

// ── SCIM audit helpers ────────────────────────────────────────────────────────

// scimProviderFromUA detects the IdP/provisioning source from the User-Agent
// header sent by upstream SCIM clients (Azure AD, Okta, Google Workspace, etc.)
func scimProviderFromUA(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "microsoft") || strings.Contains(lower, "azure") || strings.Contains(lower, "aad"):
		return "azure_ad"
	case strings.Contains(lower, "okta"):
		return "okta"
	case strings.Contains(lower, "google"):
		return "google_workspace"
	case strings.Contains(lower, "onelogin"):
		return "onelogin"
	case strings.Contains(lower, "jumpcloud"):
		return "jumpcloud"
	case strings.Contains(lower, "pingidentity") || strings.Contains(lower, "ping"):
		return "ping_identity"
	case ua != "":
		return "other"
	default:
		return "unknown"
	}
}

// emitSCIM records a SCIM inbound audit event. No-op when emitter is nil.
func (h *Handler) emitSCIM(c echo.Context, orgID uuid.UUID, action string, user *models.User, extra map[string]interface{}) {
	if h.emitter == nil {
		return
	}
	ua := c.Request().Header.Get("User-Agent")
	ip := c.RealIP()
	meta := map[string]interface{}{
		"scim_provider": scimProviderFromUA(ua),
	}
	for k, v := range extra {
		meta[k] = v
	}
	rt := "user"
	rid := ""
	if user != nil {
		rid = user.ID.String()
	}
	h.emitter.Emit(c.Request().Context(), audit.EmitParams{
		OrgID:        orgID,
		Action:       action,
		ResourceType: &rt,
		ResourceID:   &rid,
		Status:       "success",
		IPAddress:    &ip,
		UserAgent:    &ua,
		Metadata:     meta,
	})
}

func (h *Handler) CreateUser(c echo.Context) error {
	org := c.Get("scim_org").(*models.Organization)
	base := scimBase(c)
	var body scimUserBody
	if err := c.Bind(&body); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid request body")
	}
	email := body.UserName
	if email == "" {
		for _, e := range body.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
	}
	if email == "" {
		return scimError(c, http.StatusBadRequest, "userName or primary email required")
	}
	var fn, ln *string
	if body.Name.GivenName != "" {
		fn = &body.Name.GivenName
	}
	if body.Name.FamilyName != "" {
		ln = &body.Name.FamilyName
	}
	u, err := h.users.Create(c.Request().Context(), org.ID, email, fn, ln)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return scimError(c, http.StatusConflict, "User already exists")
		}
		return scimError(c, http.StatusInternalServerError, err.Error())
	}
	if !body.Active {
		falseVal := false
		_, _ = h.users.Update(c.Request().Context(), u.ID, nil, nil, &falseVal, nil)
		u.IsActive = false
	}
	// Bidirectional sync: propagate new user to all other external directories.
	if h.outboundPusher != nil {
		go h.outboundPusher.Push(c.Request().Context(), org.ID, scimpush.EventUserCreated, u)
	}
	// JML: Joiner trigger
	if h.jml != nil {
		go h.jml.Apply(c.Request().Context(), models.TriggerJoiner, lifecycle.UserContext{User: u, OrgSlug: org.Slug})
	}
	h.emitSCIM(c, org.ID, "scim.user.create", u, map[string]interface{}{"email": u.Email, "active": u.IsActive})
	return c.JSON(http.StatusCreated, userToSCIM(u, base))
}

func (h *Handler) ReplaceUser(c echo.Context) error {
	base := scimBase(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid user id")
	}
	if _, ok := h.userInOrg(c, id); !ok {
		return nil
	}
	var body scimUserBody
	if err := c.Bind(&body); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid request body")
	}
	var fn, ln *string
	if body.Name.GivenName != "" {
		fn = &body.Name.GivenName
	}
	if body.Name.FamilyName != "" {
		ln = &body.Name.FamilyName
	}
	active := body.Active
	u, err := h.users.Update(c.Request().Context(), id, fn, ln, &active, nil)
	if err != nil {
		return scimError(c, http.StatusNotFound, "User not found")
	}
	// Bidirectional sync: propagate full-replace to all other external directories.
	if h.outboundPusher != nil {
		go h.outboundPusher.Push(c.Request().Context(), u.OrgID, scimpush.EventUserUpdated, u)
	}
	// JML: Leaver when deactivated, Mover otherwise.
	if h.jml != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), u.OrgID)
		slug := ""
		if org != nil {
			slug = org.Slug
		}
		trigger := models.TriggerMover
		if !u.IsActive {
			trigger = models.TriggerLeaver
		}
		go h.jml.Apply(c.Request().Context(), trigger, lifecycle.UserContext{User: u, OrgSlug: slug})
	}
	actionR := "scim.user.update"
	if !u.IsActive {
		actionR = "scim.user.deactivate"
	}
	h.emitSCIM(c, u.OrgID, actionR, u, map[string]interface{}{"email": u.Email, "active": u.IsActive})
	if !u.IsActive && h.anomalyDetector != nil {
		org := c.Get("scim_org").(*models.Organization)
		h.anomalyDetector.Record(c.Request().Context(), org)
	}
	return c.JSON(http.StatusOK, userToSCIM(u, base))
}

func (h *Handler) PatchUser(c echo.Context) error {
	base := scimBase(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid user id")
	}
	u, ok := h.userInOrg(c, id)
	if !ok {
		return nil
	}
	var patch scimPatchBody
	if err := c.Bind(&patch); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid patch body")
	}
	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
			switch strings.ToLower(op.Path) {
			case "active":
				active := parseBoolValue(op.Value)
				_, _ = h.users.Update(c.Request().Context(), id, nil, nil, &active, nil)
				u.IsActive = active
			case "name.givenname":
				s := fmt.Sprintf("%v", op.Value)
				u.FirstName = &s
				_, _ = h.users.Update(c.Request().Context(), id, u.FirstName, u.LastName, nil, nil)
			case "name.familyname":
				s := fmt.Sprintf("%v", op.Value)
				u.LastName = &s
				_, _ = h.users.Update(c.Request().Context(), id, u.FirstName, u.LastName, nil, nil)
			case "username":
				// email change not supported in-place
			}
		case "remove":
			// minimal support
		}
	}
	u2, _ := h.users.GetByID(c.Request().Context(), id)
	if u2 != nil {
		u = u2
	}
	// Bidirectional sync: propagate patch result to all other external directories.
	if h.outboundPusher != nil {
		go h.outboundPusher.Push(c.Request().Context(), u.OrgID, scimpush.EventUserUpdated, u)
	}
	// JML: Leaver when deactivated, Mover otherwise.
	if h.jml != nil {
		org2, _ := h.orgs.GetByID(c.Request().Context(), u.OrgID)
		slug2 := ""
		if org2 != nil {
			slug2 = org2.Slug
		}
		trigger2 := models.TriggerMover
		if !u.IsActive {
			trigger2 = models.TriggerLeaver
		}
		go h.jml.Apply(c.Request().Context(), trigger2, lifecycle.UserContext{User: u, OrgSlug: slug2})
	}
	actionP := "scim.user.update"
	if !u.IsActive {
		actionP = "scim.user.deactivate"
	}
	h.emitSCIM(c, u.OrgID, actionP, u, map[string]interface{}{"email": u.Email, "active": u.IsActive})
	if !u.IsActive && h.anomalyDetector != nil {
		org := c.Get("scim_org").(*models.Organization)
		h.anomalyDetector.Record(c.Request().Context(), org)
	}
	return c.JSON(http.StatusOK, userToSCIM(u, base))
}

func (h *Handler) DeleteUser(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid user id")
	}
	// Org guard: only delete a user that belongs to this SCIM token's org.
	u, ok := h.userInOrg(c, id)
	if !ok {
		return nil
	}
	var fetchErr error // user already fetched and org-checked above
	if err := h.users.Delete(c.Request().Context(), id); err != nil {
		return scimError(c, http.StatusNotFound, "User not found")
	}
	// Bidirectional sync: deactivate user in all other external directories.
	if h.outboundPusher != nil && fetchErr == nil && u != nil {
		go h.outboundPusher.Push(c.Request().Context(), u.OrgID, scimpush.EventUserDeactivated, u)
	}
	// JML: Leaver trigger on deletion.
	if h.jml != nil && fetchErr == nil && u != nil {
		org, _ := h.orgs.GetByID(c.Request().Context(), u.OrgID)
		slug := ""
		if org != nil {
			slug = org.Slug
		}
		go h.jml.Apply(c.Request().Context(), models.TriggerLeaver, lifecycle.UserContext{User: u, OrgSlug: slug})
	}
	if fetchErr == nil && u != nil {
		h.emitSCIM(c, u.OrgID, "scim.user.delete", u, map[string]interface{}{"email": u.Email})
		if h.anomalyDetector != nil {
			org := c.Get("scim_org").(*models.Organization)
			h.anomalyDetector.Record(c.Request().Context(), org)
		}
	}
	return c.NoContent(http.StatusNoContent)
}

// ─── Groups ───────────────────────────────────────────────────────────────────

func (h *Handler) ListGroups(c echo.Context) error {
	org := c.Get("scim_org").(*models.Organization)
	base := scimBase(c)
	startIndex, count := parsePagination(c)

	groups, err := h.groups.ListByOrg(c.Request().Context(), org.ID)
	if err != nil {
		return scimError(c, http.StatusInternalServerError, err.Error())
	}

	total := len(groups)
	end := min(startIndex-1+count, total)
	start := max(startIndex-1, 0)
	if start > total {
		start = total
	}

	resources := make([]map[string]any, 0)
	for _, g := range groups[start:end] {
		members, _ := h.groups.ListMembers(c.Request().Context(), g.ID)
		resources = append(resources, groupToSCIM(g, members, base))
	}

	return c.JSON(http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": total,
		"startIndex":   startIndex,
		"itemsPerPage": count,
		"Resources":    resources,
	})
}

func (h *Handler) GetGroup(c echo.Context) error {
	base := scimBase(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid group id")
	}
	g, ok := h.groupInOrg(c, id)
	if !ok {
		return nil
	}
	members, _ := h.groups.ListMembers(c.Request().Context(), id)
	return c.JSON(http.StatusOK, groupToSCIM(g, members, base))
}

func (h *Handler) CreateGroup(c echo.Context) error {
	org := c.Get("scim_org").(*models.Organization)
	base := scimBase(c)
	var body scimGroupBody
	if err := c.Bind(&body); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid request body")
	}
	if body.DisplayName == "" {
		return scimError(c, http.StatusBadRequest, "displayName required")
	}
	g, err := h.groups.Create(c.Request().Context(), org.ID, body.DisplayName, "")
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			return scimError(c, http.StatusConflict, "Group already exists")
		}
		return scimError(c, http.StatusInternalServerError, err.Error())
	}
	// Add initial members
	for _, m := range body.Members {
		uid, err := uuid.Parse(m.Value)
		if err == nil {
			_ = h.groups.AddMember(c.Request().Context(), g.ID, uid)
		}
	}
	members, _ := h.groups.ListMembers(c.Request().Context(), g.ID)
	// Bidirectional sync: propagate new group to all other external directories.
	if h.outboundPusher != nil {
		memberIDs := usersToIDs(members)
		go h.outboundPusher.PushGroup(c.Request().Context(), org.ID, scimpush.EventGroupCreated, g, memberIDs)
	}
	return c.JSON(http.StatusCreated, groupToSCIM(g, members, base))
}

func (h *Handler) ReplaceGroup(c echo.Context) error {
	base := scimBase(c)
	org := c.Get("scim_org").(*models.Organization)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid group id")
	}
	g, ok := h.groupInOrg(c, id)
	if !ok {
		return nil
	}
	var body scimGroupBody
	if err := c.Bind(&body); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid request body")
	}
	// Replace members: remove all then add new
	existing, _ := h.groups.ListMembers(c.Request().Context(), id)
	for _, u := range existing {
		_ = h.groups.RemoveMember(c.Request().Context(), id, u.ID)
	}
	for _, m := range body.Members {
		uid, err := uuid.Parse(m.Value)
		if err == nil && h.memberInOrg(c, uid) {
			_ = h.groups.AddMember(c.Request().Context(), id, uid)
		}
	}
	members, _ := h.groups.ListMembers(c.Request().Context(), id)
	// Bidirectional sync: propagate full-replace to all other external directories.
	if h.outboundPusher != nil {
		memberIDs := usersToIDs(members)
		go h.outboundPusher.PushGroup(c.Request().Context(), org.ID, scimpush.EventGroupUpdated, g, memberIDs)
	}
	return c.JSON(http.StatusOK, groupToSCIM(g, members, base))
}

func (h *Handler) PatchGroup(c echo.Context) error {
	base := scimBase(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid group id")
	}
	g, ok := h.groupInOrg(c, id)
	if !ok {
		return nil
	}
	var patch scimPatchBody
	if err := c.Bind(&patch); err != nil {
		return scimError(c, http.StatusBadRequest, "invalid patch body")
	}
	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "add":
			if strings.ToLower(op.Path) == "members" {
				for _, m := range extractMembers(op.Value) {
					uid, err := uuid.Parse(m)
					if err == nil && h.memberInOrg(c, uid) {
						_ = h.groups.AddMember(c.Request().Context(), id, uid)
					}
				}
			}
		case "remove":
			if strings.ToLower(op.Path) == "members" {
				for _, m := range extractMembers(op.Value) {
					uid, err := uuid.Parse(m)
					if err == nil {
						_ = h.groups.RemoveMember(c.Request().Context(), id, uid)
					}
				}
			}
		}
	}
	members, _ := h.groups.ListMembers(c.Request().Context(), id)
	// Bidirectional sync: propagate patch result to all other external directories.
	if h.outboundPusher != nil {
		memberIDs := usersToIDs(members)
		go h.outboundPusher.PushGroup(c.Request().Context(), g.OrgID, scimpush.EventGroupUpdated, g, memberIDs)
	}
	return c.JSON(http.StatusOK, groupToSCIM(g, members, base))
}

func (h *Handler) DeleteGroup(c echo.Context) error {
	org := c.Get("scim_org").(*models.Organization)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return scimError(c, http.StatusBadRequest, "invalid group id")
	}
	g, ok := h.groupInOrg(c, id)
	if !ok {
		return nil
	}
	var fetchErr error // group already fetched and org-checked above
	if err := h.groups.Delete(c.Request().Context(), id); err != nil {
		return scimError(c, http.StatusNotFound, "Group not found")
	}
	// Bidirectional sync: propagate deletion to all other external directories.
	if h.outboundPusher != nil && fetchErr == nil && g != nil {
		go h.outboundPusher.PushGroup(c.Request().Context(), org.ID, scimpush.EventGroupDeleted, g, nil)
	}
	return c.NoContent(http.StatusNoContent)
}

// usersToIDs extracts the UUID slice from a user list for PushGroup.
func usersToIDs(users []*models.User) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	return ids
}

// ─── Token management (admin API) ────────────────────────────────────────────

func (h *Handler) CreateToken(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	var body struct {
		Label string `json:"label"`
	}
	_ = c.Bind(&body)

	raw, err := generateToken()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate token")
	}
	hash := hashToken(raw)
	tok, err := h.tokens.Create(c.Request().Context(), orgID, hash, body.Label)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusCreated, map[string]any{
		"id":         tok.ID,
		"token":      raw, // shown once
		"label":      tok.Label,
		"created_at": tok.CreatedAt,
	})
}

func (h *Handler) ListTokens(c echo.Context) error {
	orgID, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	toks, err := h.tokens.ListByOrg(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, toks)
}

func (h *Handler) DeleteToken(c echo.Context) error {
	id, err := uuid.Parse(c.Param("token_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid token id")
	}
	if err := h.tokens.Delete(c.Request().Context(), id); err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "token not found")
	}
	return c.NoContent(http.StatusNoContent)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func userToSCIM(u *models.User, base string) map[string]any {
	active := u.IsActive
	name := map[string]any{}
	if u.FirstName != nil {
		name["givenName"] = *u.FirstName
	}
	if u.LastName != nil {
		name["familyName"] = *u.LastName
	}
	if u.FirstName != nil && u.LastName != nil {
		name["formatted"] = *u.FirstName + " " + *u.LastName
	}
	return map[string]any{
		"schemas":  []string{scimUserSchema},
		"id":       u.ID.String(),
		"userName": u.Email,
		"name":     name,
		"emails": []map[string]any{
			{"value": u.Email, "primary": true, "type": "work"},
		},
		"active": active,
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.Format(time.RFC3339),
			"lastModified": u.UpdatedAt.Format(time.RFC3339),
			"location":     base + "/Users/" + u.ID.String(),
		},
	}
}

func groupToSCIM(g *models.Group, members []*models.User, base string) map[string]any {
	mList := make([]map[string]any, len(members))
	for i, u := range members {
		mList[i] = map[string]any{
			"value":   u.ID.String(),
			"display": u.Email,
			"$ref":    base + "/Users/" + u.ID.String(),
		}
	}
	return map[string]any{
		"schemas":     []string{scimGroupSchema},
		"id":          g.ID.String(),
		"displayName": g.Name,
		"members":     mList,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      g.CreatedAt.Format(time.RFC3339),
			"lastModified": g.UpdatedAt.Format(time.RFC3339),
			"location":     base + "/Groups/" + g.ID.String(),
		},
	}
}

func scimBase(c echo.Context) string {
	slug := c.Param("org_slug")
	scheme := "https"
	if c.Request().TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + c.Request().Host + "/" + slug + "/scim/v2"
}

func scimError(c echo.Context, status int, detail string) error {
	return c.JSON(status, map[string]any{
		"schemas": []string{scimErrorSchema},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	})
}

func parsePagination(c echo.Context) (startIndex, count int) {
	startIndex = 1
	count = 100
	if s := c.QueryParam("startIndex"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			startIndex = v
		}
	}
	if cnt := c.QueryParam("count"); cnt != "" {
		if v, err := strconv.Atoi(cnt); err == nil && v > 0 {
			count = v
		}
	}
	return
}

func applyUserFilter(users []*models.User, filter string) []*models.User {
	// Parse "attr op value" — support eq only
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 {
		return users
	}
	attr := strings.ToLower(parts[0])
	op := strings.ToLower(parts[1])
	val := strings.Trim(parts[2], `"`)
	if op != "eq" {
		return users
	}
	var out []*models.User
	for _, u := range users {
		switch attr {
		case "username":
			if strings.EqualFold(u.Email, val) {
				out = append(out, u)
			}
		case "emails.value":
			if strings.EqualFold(u.Email, val) {
				out = append(out, u)
			}
		case "id":
			if u.ID.String() == val {
				out = append(out, u)
			}
		}
	}
	return out
}

func parseBoolValue(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.ToLower(val) == "true"
	}
	return false
}

func extractMembers(v any) []string {
	var out []string
	switch val := v.(type) {
	case []any:
		for _, item := range val {
			if m, ok := item.(map[string]any); ok {
				if id, ok := m["value"].(string); ok {
					out = append(out, id)
				}
			}
		}
	case map[string]any:
		if id, ok := val["value"].(string); ok {
			out = append(out, id)
		}
	}
	return out
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Request body types ───────────────────────────────────────────────────────

type scimUserBody struct {
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
	Name     struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
		Type    string `json:"type"`
	} `json:"emails"`
}

type scimGroupBody struct {
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

type scimPatchBody struct {
	Operations []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"Operations"`
}

// ─── Schema descriptors ───────────────────────────────────────────────────────

func userSchema(base string) map[string]any {
	return map[string]any{
		"id":          scimUserSchema,
		"name":        "User",
		"description": "User Account",
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     base + "/Schemas/" + scimUserSchema,
		},
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
			{"name": "name", "type": "complex", "required": false},
			{"name": "emails", "type": "complex", "multiValued": true, "required": false},
			{"name": "active", "type": "boolean", "required": false},
		},
	}
}

func groupSchema(base string) map[string]any {
	return map[string]any{
		"id":          scimGroupSchema,
		"name":        "Group",
		"description": "Group",
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     base + "/Schemas/" + scimGroupSchema,
		},
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "required": true},
			{"name": "members", "type": "complex", "multiValued": true, "required": false},
		},
	}
}
