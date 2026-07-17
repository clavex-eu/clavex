package handler

import (
	"github.com/clavex-eu/clavex/internal/audit"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// Audit resource_type values for the admin entities managed declaratively by
// the Kubernetes operator. They are the discriminator the operator's event
// stream uses to map a live audit event to the corresponding CRD Kind, so the
// exact strings are part of the wire contract — do not rename without updating
// k8s-operator/internal/eventstream.
const (
	auditResourceOIDCClient       = "oidc_client"
	auditResourceRole             = "role"
	auditResourceGroup            = "group"
	auditResourceAuthPolicy       = "auth_policy"
	auditResourceOrg              = "org"
	auditResourceWebhook          = "webhook"
	auditResourceIdentityProvider = "identity_provider"
)

// auditActor returns the acting admin's user UUID from the request context, or
// nil when unavailable (e.g. API-key callers that carry no user identity).
func auditActor(c echo.Context) *uuid.UUID {
	v, ok := c.Get("user_id").(string)
	if !ok || v == "" {
		return nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil
	}
	return &id
}

// emitEntityAudit records a successful mutation of an operator-managed entity.
// It is a no-op when no emitter is wired, and never surfaces errors to the
// caller (Emit persists synchronously then fans out to the live stream).
func emitEntityAudit(c echo.Context, a *audit.Emitter, orgID uuid.UUID, action, resourceType, resourceID string, meta map[string]interface{}) {
	if a == nil {
		return
	}
	rt := resourceType
	var ridPtr *string
	if resourceID != "" {
		ridPtr = &resourceID
	}
	a.Emit(c.Request().Context(), audit.EmitParams{
		OrgID:        orgID,
		ActorID:      auditActor(c),
		Action:       action,
		ResourceType: &rt,
		ResourceID:   ridPtr,
		Status:       "success",
		Metadata:     meta,
	})
}
