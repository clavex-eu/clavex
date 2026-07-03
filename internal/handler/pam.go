package handler

// PAMHandler implements the Privileged Access Management API.
//
// Endpoints (all under /api/v1/organizations/:org_id/pam):
//
//	Access Requests (JIT):
//	  POST   /access-requests
//	  GET    /access-requests                 ?status=pending|active|...
//	  GET    /access-requests/:req_id
//	  POST   /access-requests/:req_id/approve
//	  POST   /access-requests/:req_id/deny
//	  POST   /access-requests/:req_id/revoke
//
//	Privileged Sessions:
//	  POST   /sessions
//	  GET    /sessions
//	  GET    /sessions/:session_id
//	  POST   /sessions/:session_id/events
//	  GET    /sessions/:session_id/events
//	  POST   /sessions/:session_id/end
//
//	Credential Vault:
//	  GET    /credentials
//	  POST   /credentials
//	  PUT    /credentials/:cred_id
//	  DELETE /credentials/:cred_id
//	  POST   /credentials/:cred_id/checkout
//	  POST   /credentials/:cred_id/return
//
//	Vault SSH CA ("Platform SSO for Linux"):
//	  GET    /ssh-ca              — get config (no token)
//	  PUT    /ssh-ca              — upsert config
//	  DELETE /ssh-ca
//	  GET    /ssh-ca/public-key   — CA public key for sshd AuthorizedPrincipalsCommand
//	  POST   /ssh-ca/sign         — sign SSH public key → ephemeral cert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/alerting"
	"github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/middleware"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/clavex-eu/clavex/internal/webhook"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// PAMHandler handles all PAM API requests.
type PAMHandler struct {
	repo        *repository.PAMRepository
	enc         *crypto.Encryptor
	webhookDisp *webhook.Dispatcher
	notifier    *alerting.PAMNotifier
}

// NewPAMHandler constructs a PAMHandler.
func NewPAMHandler(pool *pgxpool.Pool, enc *crypto.Encryptor, webhookDisp *webhook.Dispatcher, notifier *alerting.PAMNotifier) *PAMHandler {
	return &PAMHandler{
		repo:        repository.NewPAMRepository(pool),
		enc:         enc,
		webhookDisp: webhookDisp,
		notifier:    notifier,
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func pamOrgID(c echo.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param("org_id"))
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}
	return id, nil
}

func pamUUID(c echo.Context, param string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param(param))
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid "+param)
	}
	return id, nil
}

func pamPage(c echo.Context) (int, int) {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}
	return page, perPage
}

// ── Access Requests ───────────────────────────────────────────────────────────

type pamCreateRequestBody struct {
	ResourceType      string `json:"resource_type"`
	ResourceID        string `json:"resource_id"`
	ResourceName      string `json:"resource_name"`
	Justification     string `json:"justification"`
	RequestedDuration int    `json:"requested_duration"`
}

// CreateRequest handles POST /pam/access-requests.
func (h *PAMHandler) CreateRequest(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body pamCreateRequestBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.ResourceType == "" || body.ResourceID == "" || body.ResourceName == "" || body.Justification == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "resource_type, resource_id, resource_name, justification are required")
	}
	if body.RequestedDuration <= 0 {
		body.RequestedDuration = 60
	}

	// Use current admin user as requester.
	claims := adminClaimsFromContext(c)
	requesterID := claims.UserID

	ar := &repository.PAMAccessRequest{
		OrgID:             orgID,
		RequesterID:       requesterID,
		ResourceType:      body.ResourceType,
		ResourceID:        body.ResourceID,
		ResourceName:      body.ResourceName,
		Justification:     body.Justification,
		RequestedDuration: body.RequestedDuration,
	}
	if err := h.repo.CreateAccessRequest(c.Request().Context(), ar); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create access request")
	}
	return c.JSON(http.StatusCreated, ar)
}

// ListRequests handles GET /pam/access-requests.
func (h *PAMHandler) ListRequests(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	status := c.QueryParam("status")
	page, perPage := pamPage(c)
	results, total, err := h.repo.ListAccessRequests(c.Request().Context(), orgID, status, page, perPage)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list access requests")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"data":     results,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

// GetRequest handles GET /pam/access-requests/:req_id.
func (h *PAMHandler) GetRequest(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	reqID, err := pamUUID(c, "req_id")
	if err != nil {
		return err
	}
	ar, err := h.repo.GetAccessRequest(c.Request().Context(), orgID, reqID)
	if err != nil || ar == nil {
		return echo.NewHTTPError(http.StatusNotFound, "access request not found")
	}
	return c.JSON(http.StatusOK, ar)
}

type pamDecisionBody struct {
	Note   string `json:"note"`
	Reason string `json:"reason"`
}

// Approve handles POST /pam/access-requests/:req_id/approve.
func (h *PAMHandler) Approve(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	reqID, err := pamUUID(c, "req_id")
	if err != nil {
		return err
	}
	var body pamDecisionBody
	_ = c.Bind(&body)

	claims := adminClaimsFromContext(c)
	ar, err := h.repo.ApproveAccessRequest(c.Request().Context(), orgID, reqID, claims.UserID, body.Note)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to approve request")
	}
	if ar == nil {
		return echo.NewHTTPError(http.StatusConflict, "request not found or not in pending status")
	}
	return c.JSON(http.StatusOK, ar)
}

// Deny handles POST /pam/access-requests/:req_id/deny.
func (h *PAMHandler) Deny(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	reqID, err := pamUUID(c, "req_id")
	if err != nil {
		return err
	}
	var body pamDecisionBody
	_ = c.Bind(&body)

	claims := adminClaimsFromContext(c)
	ar, err := h.repo.DenyAccessRequest(c.Request().Context(), orgID, reqID, claims.UserID, body.Note)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to deny request")
	}
	if ar == nil {
		return echo.NewHTTPError(http.StatusConflict, "request not found or not in pending status")
	}
	return c.JSON(http.StatusOK, ar)
}

// Revoke handles POST /pam/access-requests/:req_id/revoke.
func (h *PAMHandler) Revoke(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	reqID, err := pamUUID(c, "req_id")
	if err != nil {
		return err
	}
	var body pamDecisionBody
	_ = c.Bind(&body)

	ar, err := h.repo.RevokeAccessRequest(c.Request().Context(), orgID, reqID, body.Reason)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to revoke request")
	}
	if ar == nil {
		return echo.NewHTTPError(http.StatusConflict, "request not found or not in an active/approved status")
	}
	return c.JSON(http.StatusOK, ar)
}

// ── Sessions ──────────────────────────────────────────────────────────────────

type pamStartSessionBody struct {
	AccessRequestID *string `json:"access_request_id"`
	SessionType     string  `json:"session_type"`
	TargetHost      *string `json:"target_host"`
	TargetPort      *int    `json:"target_port"`
	TargetUser      *string `json:"target_user"`
}

// StartSession handles POST /pam/sessions.
func (h *PAMHandler) StartSession(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body pamStartSessionBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.SessionType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "session_type is required")
	}

	claims := adminClaimsFromContext(c)
	clientIP := c.RealIP()

	s := &repository.PAMSession{
		OrgID:       orgID,
		UserID:      claims.UserID,
		SessionType: body.SessionType,
		TargetHost:  body.TargetHost,
		TargetPort:  body.TargetPort,
		TargetUser:  body.TargetUser,
		ClientIP:    &clientIP,
	}
	if body.AccessRequestID != nil {
		id, err := uuid.Parse(*body.AccessRequestID)
		if err == nil {
			s.AccessRequestID = &id
		}
	}
	if err := h.repo.StartSession(c.Request().Context(), s); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to start session")
	}
	return c.JSON(http.StatusCreated, s)
}

// ListSessions handles GET /pam/sessions.
func (h *PAMHandler) ListSessions(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	page, perPage := pamPage(c)
	sessions, total, err := h.repo.ListSessions(c.Request().Context(), orgID, page, perPage)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list sessions")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"data":     sessions,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

// GetSession handles GET /pam/sessions/:session_id.
func (h *PAMHandler) GetSession(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	sessionID, err := pamUUID(c, "session_id")
	if err != nil {
		return err
	}
	s, err := h.repo.GetSession(c.Request().Context(), orgID, sessionID)
	if err != nil || s == nil {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}
	return c.JSON(http.StatusOK, s)
}

// EndSession handles POST /pam/sessions/:session_id/end.
func (h *PAMHandler) EndSession(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	sessionID, err := pamUUID(c, "session_id")
	if err != nil {
		return err
	}
	if err := h.repo.EndSession(c.Request().Context(), orgID, sessionID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to end session")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "ended"})
}

type pamSessionEventBody struct {
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
}

// AddEvent handles POST /pam/sessions/:session_id/events.
func (h *PAMHandler) AddEvent(c echo.Context) error {
	_, err := pamOrgID(c)
	if err != nil {
		return err
	}
	sessionID, err := pamUUID(c, "session_id")
	if err != nil {
		return err
	}
	var body pamSessionEventBody
	if err := c.Bind(&body); err != nil || body.EventType == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "event_type is required")
	}
	payload := []byte(body.Payload)
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	ev := &repository.PAMSessionEvent{
		SessionID: sessionID,
		EventType: body.EventType,
		Payload:   payload,
	}
	if err := h.repo.AddSessionEvent(c.Request().Context(), ev); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to record event")
	}
	return c.JSON(http.StatusCreated, ev)
}

// ListEvents handles GET /pam/sessions/:session_id/events.
func (h *PAMHandler) ListEvents(c echo.Context) error {
	_, err := pamOrgID(c)
	if err != nil {
		return err
	}
	sessionID, err := pamUUID(c, "session_id")
	if err != nil {
		return err
	}
	events, err := h.repo.ListSessionEvents(c.Request().Context(), sessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list events")
	}
	return c.JSON(http.StatusOK, map[string]any{"data": events})
}

// ── Credential Vault ──────────────────────────────────────────────────────────

type pamCreateCredentialBody struct {
	Name                 string  `json:"name"`
	Description          *string `json:"description"`
	CredentialType       string  `json:"credential_type"`
	Username             *string `json:"username"`
	Secret               string  `json:"secret"` // plaintext — encrypted before storage
	TargetHost           *string `json:"target_host"`
	CheckoutDuration     int     `json:"checkout_duration"`
	RequireAccessRequest bool    `json:"require_access_request"`
	RotationIntervalDays *int    `json:"rotation_interval_days"` // nil = no auto-rotation
}

// ListCredentials handles GET /pam/credentials.
func (h *PAMHandler) ListCredentials(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	creds, err := h.repo.ListCredentials(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list credentials")
	}
	return c.JSON(http.StatusOK, map[string]any{"data": creds})
}

// CreateCredential handles POST /pam/credentials.
func (h *PAMHandler) CreateCredential(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body pamCreateCredentialBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.Name == "" || body.CredentialType == "" || body.Secret == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, credential_type, secret are required")
	}
	if body.CheckoutDuration <= 0 {
		body.CheckoutDuration = 60
	}

	encSecret, err := h.enc.Encrypt(body.Secret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to encrypt secret")
	}

	cred := &repository.PAMCredential{
		OrgID:                orgID,
		Name:                 body.Name,
		Description:          body.Description,
		CredentialType:       body.CredentialType,
		Username:             body.Username,
		TargetHost:           body.TargetHost,
		CheckoutDuration:     body.CheckoutDuration,
		RequireAccessRequest: body.RequireAccessRequest,
		RotationIntervalDays: body.RotationIntervalDays,
	}
	if err := h.repo.CreateCredential(c.Request().Context(), cred, encSecret); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create credential")
	}
	return c.JSON(http.StatusCreated, cred)
}

type pamUpdateCredentialBody struct {
	Name                 *string `json:"name"`
	Description          *string `json:"description"`
	Username             *string `json:"username"`
	Secret               *string `json:"secret"` // nil = no rotation
	TargetHost           *string `json:"target_host"`
	CheckoutDuration     *int    `json:"checkout_duration"`
	RequireAccessRequest *bool   `json:"require_access_request"`
	IsActive             *bool   `json:"is_active"`
	RotationIntervalDays *int    `json:"rotation_interval_days"` // nil = no change; 0 = clear
}

// UpdateCredential handles PUT /pam/credentials/:cred_id.
func (h *PAMHandler) UpdateCredential(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	credID, err := pamUUID(c, "cred_id")
	if err != nil {
		return err
	}
	var body pamUpdateCredentialBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}

	encSecret := ""
	if body.Secret != nil && *body.Secret != "" {
		enc, err := h.enc.Encrypt(*body.Secret)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to encrypt secret")
		}
		encSecret = enc
	}

	if err := h.repo.UpdateCredential(c.Request().Context(), orgID, credID,
		body.Name, body.Description, body.Username, body.TargetHost,
		body.CheckoutDuration, body.RequireAccessRequest, body.IsActive,
		body.RotationIntervalDays, encSecret,
	); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to update credential")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "updated"})
}

// DeleteCredential handles DELETE /pam/credentials/:cred_id.
func (h *PAMHandler) DeleteCredential(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	credID, err := pamUUID(c, "cred_id")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteCredential(c.Request().Context(), orgID, credID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete credential")
	}
	return c.NoContent(http.StatusNoContent)
}

type pamCheckoutBody struct {
	AccessRequestID *string `json:"access_request_id"`
	Reason          string  `json:"reason"`
}

// accessRequestAuthorizes reports whether ar is an approved (status "active"),
// unexpired, non-revoked access request raised by userID for the credential
// credID. Used to gate checkout of credentials marked require_access_request.
func accessRequestAuthorizes(ar *repository.PAMAccessRequest, credID, userID uuid.UUID) bool {
	return ar != nil &&
		ar.Status == "active" &&
		ar.RequesterID == userID &&
		ar.ResourceID == credID.String() &&
		ar.RevokedAt == nil &&
		ar.ExpiresAt != nil && time.Now().Before(*ar.ExpiresAt)
}

// Checkout handles POST /pam/credentials/:cred_id/checkout.
// Returns the decrypted secret once in the response.
func (h *PAMHandler) Checkout(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	credID, err := pamUUID(c, "cred_id")
	if err != nil {
		return err
	}
	var body pamCheckoutBody
	_ = c.Bind(&body)

	// Resolve access request ID if provided.
	var accessRequestID *uuid.UUID
	if body.AccessRequestID != nil {
		id, err := uuid.Parse(*body.AccessRequestID)
		if err == nil {
			accessRequestID = &id
		}
	}

	// Fetch credential to determine checkout_duration.
	cred, _, err := h.repo.GetCredential(c.Request().Context(), orgID, credID)
	if err != nil {
		if isNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "credential not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get credential")
	}

	claims := adminClaimsFromContext(c)

	// Approval gate: a credential marked require_access_request may only be
	// revealed when the caller presents an access request that is approved
	// (status "active"), was raised by this caller for THIS credential, and has
	// not expired or been revoked. Previously the access_request_id was recorded
	// for audit but never validated — the approval workflow was bypassable.
	if cred.RequireAccessRequest {
		if accessRequestID == nil {
			return echo.NewHTTPError(http.StatusForbidden, "this credential requires an approved access request")
		}
		ar, arErr := h.repo.GetAccessRequest(c.Request().Context(), orgID, *accessRequestID)
		if arErr != nil || !accessRequestAuthorizes(ar, credID, claims.UserID) {
			return echo.NewHTTPError(http.StatusForbidden, "no valid approved access request for this credential")
		}
	}

	co, encSecret, err := h.repo.CheckoutCredential(
		c.Request().Context(), orgID, credID, claims.UserID,
		accessRequestID, body.Reason, cred.CheckoutDuration,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to checkout credential")
	}

	// Decrypt secret once for the response.
	plainSecret, err := h.enc.Decrypt(encSecret)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to decrypt secret")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"checkout": co,
		"secret":   plainSecret,
		"warning":  "This secret will not be shown again. Store it securely.",
	})
}

// ReturnCheckout handles POST /pam/credentials/:cred_id/return.
func (h *PAMHandler) ReturnCheckout(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	// checkout_id is passed in the request body, not the path
	var body struct {
		CheckoutID string `json:"checkout_id"`
	}
	if err := c.Bind(&body); err != nil || body.CheckoutID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "checkout_id is required")
	}
	checkoutID, err := uuid.Parse(body.CheckoutID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid checkout_id")
	}
	if err := h.repo.ReturnCheckout(c.Request().Context(), orgID, checkoutID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to return checkout")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "returned"})
}

// ── Vault SSH CA ──────────────────────────────────────────────────────────────

type pamSSHCAUpsertBody struct {
	VaultAddr            string `json:"vault_addr"`
	VaultToken           string `json:"vault_token"` // plaintext — encrypted before storage
	VaultMount           string `json:"vault_mount"`
	VaultRole            string `json:"vault_role"`
	CertTTLSeconds       int    `json:"cert_ttl_seconds"`
	RequireAccessRequest bool   `json:"require_access_request"`
}

// GetSSHCA handles GET /pam/ssh-ca.
func (h *PAMHandler) GetSSHCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetSSHCAConfig(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get SSH CA config")
	}
	if cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SSH CA not configured")
	}
	return c.JSON(http.StatusOK, cfg)
}

// UpsertSSHCA handles PUT /pam/ssh-ca.
func (h *PAMHandler) UpsertSSHCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body pamSSHCAUpsertBody
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if body.VaultAddr == "" || body.VaultToken == "" || body.VaultRole == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "vault_addr, vault_token, vault_role are required")
	}
	if body.VaultMount == "" {
		body.VaultMount = "ssh"
	}
	if body.CertTTLSeconds <= 0 {
		body.CertTTLSeconds = 3600
	}

	encToken, err := h.enc.Encrypt(body.VaultToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to encrypt vault token")
	}

	if err := h.repo.UpsertSSHCAConfig(c.Request().Context(), orgID,
		body.VaultAddr, encToken, body.VaultMount, body.VaultRole,
		body.CertTTLSeconds, body.RequireAccessRequest,
	); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save SSH CA config")
	}

	// Try to fetch and cache the CA public key immediately.
	go func() {
		_ = h.refreshCAPublicKey(context.Background(), orgID, body.VaultAddr, body.VaultToken, body.VaultMount)
	}()

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// DeleteSSHCA handles DELETE /pam/ssh-ca.
func (h *PAMHandler) DeleteSSHCA(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	if err := h.repo.DeleteSSHCAConfig(c.Request().Context(), orgID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete SSH CA config")
	}
	return c.NoContent(http.StatusNoContent)
}

// GetCAPublicKey handles GET /pam/ssh-ca/public-key.
// Returns the CA public key in OpenSSH format for use in sshd_config:
//
//	TrustedUserCAKeys /etc/ssh/clavex-ca.pub
func (h *PAMHandler) GetCAPublicKey(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	cfg, encToken, err := h.repo.GetSSHCAConfigWithToken(c.Request().Context(), orgID)
	if err != nil {
		if isNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "SSH CA not configured")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get SSH CA config")
	}

	// Return cached key if available.
	if cfg.CAPublicKey != nil && *cfg.CAPublicKey != "" {
		return c.String(http.StatusOK, *cfg.CAPublicKey)
	}

	// Decrypt token and fetch from Vault.
	token, err := h.enc.Decrypt(encToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to decrypt vault token")
	}
	pubKey, err := fetchVaultCAPublicKey(c.Request().Context(), cfg.VaultAddr, cfg.VaultMount, token)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("failed to fetch CA public key from Vault: %v", err))
	}

	// Cache the key.
	_ = h.repo.UpdateSSHCAPublicKey(c.Request().Context(), orgID, pubKey)

	return c.String(http.StatusOK, pubKey)
}

type pamSignBody struct {
	PublicKey       string  `json:"public_key"`        // SSH public key (OpenSSH format)
	ValidPrincipals string  `json:"valid_principals"`  // comma-separated
	AccessRequestID *string `json:"access_request_id"` // optional JIT gating
}

// SignSSHPublicKey handles POST /pam/ssh-ca/sign.
// Signs the user's SSH public key with Vault CA and returns an ephemeral certificate.
func (h *PAMHandler) SignSSHPublicKey(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body pamSignBody
	if err := c.Bind(&body); err != nil || body.PublicKey == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "public_key is required")
	}

	cfg, encToken, err := h.repo.GetSSHCAConfigWithToken(c.Request().Context(), orgID)
	if err != nil || cfg == nil {
		return echo.NewHTTPError(http.StatusNotFound, "SSH CA not configured")
	}

	// Optional JIT gating: if require_access_request is true, verify one is active.
	if cfg.RequireAccessRequest {
		if body.AccessRequestID == nil {
			return echo.NewHTTPError(http.StatusForbidden, "an active access request is required to sign SSH keys")
		}
		arID, err := uuid.Parse(*body.AccessRequestID)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid access_request_id")
		}
		ar, err := h.repo.GetAccessRequest(c.Request().Context(), orgID, arID)
		if err != nil || ar == nil || ar.Status != "active" {
			return echo.NewHTTPError(http.StatusForbidden, "access request is not active")
		}
	}

	token, err := h.enc.Decrypt(encToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to decrypt vault token")
	}

	principals := body.ValidPrincipals
	if principals == "" {
		claims := adminClaimsFromContext(c)
		principals = claims.Email
	}

	ttl := fmt.Sprintf("%ds", cfg.CertTTLSeconds)
	signedCert, err := signWithVaultSSHCA(c.Request().Context(), cfg.VaultAddr, cfg.VaultMount, cfg.VaultRole, token, body.PublicKey, principals, ttl)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Vault signing failed: %v", err))
	}

	return c.JSON(http.StatusOK, map[string]any{
		"signed_key":   signedCert,
		"principals":   principals,
		"ttl":          cfg.CertTTLSeconds,
		"expires_at":   time.Now().Add(time.Duration(cfg.CertTTLSeconds) * time.Second),
		"instructions": sshCertInstructions(signedCert),
	})
}

// ── Vault HTTP helpers ────────────────────────────────────────────────────────

// vaultHTTPClient is SSRF-guarded: it refuses to dial private/loopback targets
// unless the operator opts in via http.allow_private_outbound_targets. vaultAddr
// comes from tenant PAM config, so it must be treated as untrusted.
var vaultHTTPClient = safehttp.Client(10*time.Second, false)

// SetVaultHTTPClient overrides the Vault HTTP client (SSRF-relaxed opt-in).
func SetVaultHTTPClient(hc *http.Client) {
	if hc != nil {
		vaultHTTPClient = hc
	}
}

// fetchVaultCAPublicKey fetches the CA public key from Vault SSH secrets engine.
func fetchVaultCAPublicKey(ctx context.Context, vaultAddr, mount, token string) (string, error) {
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/ca/public-key"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// signWithVaultSSHCA calls Vault SSH CA sign endpoint and returns the signed cert.
func signWithVaultSSHCA(ctx context.Context, vaultAddr, mount, role, token, publicKey, principals, ttl string) (string, error) {
	payload := map[string]string{
		"public_key":       publicKey,
		"valid_principals": principals,
		"ttl":              ttl,
		"cert_type":        "user",
	}
	body, _ := json.Marshal(payload)
	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + mount + "/sign/" + role
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := vaultHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("vault returned %d: %s", resp.StatusCode, errBody)
	}

	var result struct {
		Data struct {
			SerialNumber string `json:"serial_number"`
			SignedKey    string `json:"signed_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Data.SignedKey), nil
}

func (h *PAMHandler) refreshCAPublicKey(ctx context.Context, orgID uuid.UUID, vaultAddr, token, mount string) error {
	pubKey, err := fetchVaultCAPublicKey(ctx, vaultAddr, mount, token)
	if err != nil {
		return err
	}
	return h.repo.UpdateSSHCAPublicKey(ctx, orgID, pubKey)
}

func sshCertInstructions(cert string) string {
	return fmt.Sprintf(`Save the signed certificate as ~/.ssh/id_ed25519-cert.pub (or matching key name).
Then SSH with: ssh -i ~/.ssh/id_ed25519 user@host
The certificate is valid for the TTL period and requires no agent on the server.

Server setup (one-time, run as root):
  # Add to /etc/ssh/sshd_config:
  TrustedUserCAKeys /etc/ssh/clavex_ca.pub
  AuthorizedPrincipalsFile /etc/ssh/auth_principals/%%u

  # Create principals file for each local user, e.g. /etc/ssh/auth_principals/root:
  # List allowed email principals (one per line)

Then copy the CA public key: GET /pam/ssh-ca/public-key > /etc/ssh/clavex_ca.pub`)
}

// ── Claims helper ─────────────────────────────────────────────────────────────

// adminClaims is a minimal struct for extracting user info from the JWT context.
type adminClaims struct {
	UserID uuid.UUID
	Email  string
}

func adminClaimsFromContext(c echo.Context) adminClaims {
	cl := middleware.GetClaims(c)
	if cl == nil {
		return adminClaims{UserID: uuid.Nil}
	}
	id, _ := uuid.Parse(cl.Subject)
	return adminClaims{UserID: id, Email: cl.Email}
}

func isNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// ListRotationLog handles GET /pam/credentials/:cred_id/rotation-log.
// Returns the most recent rotation events for the specified credential.
func (h *PAMHandler) ListRotationLog(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	credID, err := pamUUID(c, "cred_id")
	if err != nil {
		return err
	}
	entries, err := h.repo.ListRotationLog(c.Request().Context(), orgID, credID, 0)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list rotation log")
	}
	return c.JSON(http.StatusOK, map[string]any{"data": entries})
}

// ── Break-Glass Emergency Access (PCI DSS 8.2.6) ─────────────────────────────

// GetBreakGlassConfig handles GET /pam/break-glass/config.
// Returns the org's break-glass policy (or safe defaults if not configured).
func (h *PAMHandler) GetBreakGlassConfig(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	cfg, err := h.repo.GetBreakGlassConfig(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch break-glass config")
	}
	uses, err := h.repo.CountBreakGlassUsesThisWeek(c.Request().Context(), orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to count break-glass uses")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"config":         cfg,
		"uses_this_week": uses,
	})
}

// UpsertBreakGlassConfig handles PUT /pam/break-glass/config.
// Saves (or overwrites) the break-glass policy for the org.
func (h *PAMHandler) UpsertBreakGlassConfig(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	var body repository.BreakGlassConfig
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	body.OrgID = orgID
	if body.MaxUsesPerWeek < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "max_uses_per_week must be >= 0")
	}
	if err := h.repo.UpsertBreakGlassConfig(c.Request().Context(), &body); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save break-glass config")
	}
	return c.JSON(http.StatusOK, body)
}

// BreakGlass handles POST /pam/access-requests/break-glass.
// Creates an emergency access request that bypasses the normal JIT approval
// workflow. Enforces weekly usage limits and fires a webhook notification.
// PCI DSS 8.2.6: all uses are audited and all admins notified immediately.
func (h *PAMHandler) BreakGlass(c echo.Context) error {
	orgID, err := pamOrgID(c)
	if err != nil {
		return err
	}
	requester := adminClaimsFromContext(c)

	var body struct {
		ResourceType      string `json:"resource_type"`
		ResourceID        string `json:"resource_id"`
		ResourceName      string `json:"resource_name"`
		Justification     string `json:"justification"`
		RequestedDuration int    `json:"requested_duration"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if body.ResourceName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "resource_name is required")
	}
	if body.RequestedDuration < 1 {
		return echo.NewHTTPError(http.StatusBadRequest, "requested_duration must be at least 1 minute")
	}

	ctx := c.Request().Context()

	// 1. Fetch org policy.
	cfg, err := h.repo.GetBreakGlassConfig(ctx, orgID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch break-glass config")
	}
	if !cfg.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "break-glass access is disabled for this organization")
	}
	if cfg.RequireJustification && len(strings.TrimSpace(body.Justification)) < 20 {
		return echo.NewHTTPError(http.StatusBadRequest, "justification must be at least 20 characters")
	}

	// 2. Enforce weekly limit (0 = unlimited).
	if cfg.MaxUsesPerWeek > 0 {
		uses, err := h.repo.CountBreakGlassUsesThisWeek(ctx, orgID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to count break-glass uses")
		}
		if uses >= cfg.MaxUsesPerWeek {
			return echo.NewHTTPError(http.StatusTooManyRequests,
				fmt.Sprintf("weekly break-glass limit of %d reached", cfg.MaxUsesPerWeek))
		}
	}

	// 3. Create the pre-approved request.
	req := &repository.PAMAccessRequest{
		OrgID:             orgID,
		RequesterID:       requester.UserID,
		ResourceType:      body.ResourceType,
		ResourceID:        body.ResourceID,
		ResourceName:      body.ResourceName,
		Justification:     body.Justification,
		RequestedDuration: body.RequestedDuration,
		IsBreakGlass:      true,
	}
	if err := h.repo.CreateBreakGlassRequest(ctx, req); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create break-glass request")
	}

	// 4. Fire webhook notification (PCI DSS: immediate admin notification).
	if cfg.NotifyOnUse && h.webhookDisp != nil {
		h.webhookDisp.Dispatch(orgID, webhook.EventPAMBreakGlassUsed, map[string]any{
			"request_id":         req.ID,
			"requester_id":       req.RequesterID,
			"requester_email":    requester.Email,
			"resource_type":      req.ResourceType,
			"resource_id":        req.ResourceID,
			"resource_name":      req.ResourceName,
			"justification":      req.Justification,
			"requested_duration": req.RequestedDuration,
			"expires_at":         req.ExpiresAt,
		})
	}

	// Fire Slack/Teams alert (non-blocking; only when notifier is configured).
	if h.notifier.IsEnabled() {
		h.notifier.AlertBreakGlass(req, requester.Email)
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"data":    req,
		"warning": "Break-glass access is fully audited. All administrators will be notified immediately.",
	})
}
