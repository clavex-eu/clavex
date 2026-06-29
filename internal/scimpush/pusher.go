// Package scimpush implements outbound SCIM 2.0 provisioning.
// When a user or group is created, updated, or deactivated in Clavex, the
// Pusher fans the event out to every active external directory — turning
// Clavex into a bidirectional identity sync hub.
package scimpush

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/safehttp"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	// User events
	EventUserCreated     = "user.created"
	EventUserUpdated     = "user.updated"
	EventUserDeactivated = "user.deactivated"

	// Group events — for hub-and-spoke group membership sync
	EventGroupCreated = "group.created"
	EventGroupUpdated = "group.updated"
	EventGroupDeleted = "group.deleted"

	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchema      = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimPatchOp     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	pushTimeout     = 10 * time.Second
)

// AllEvents is the complete set of event names accepted in enabled_events.
var AllEvents = []string{
	EventUserCreated, EventUserUpdated, EventUserDeactivated,
	EventGroupCreated, EventGroupUpdated, EventGroupDeleted,
}

// Pusher sends outbound SCIM requests to configured external directories.
type Pusher struct {
	repo         *repository.ScimPushRepository
	deliveryRepo *repository.ScimPushDeliveryRepository // nil = no delivery logging
	userRepo     *repository.UserRepository             // for retry by user ID
	groupRepo    *repository.GroupRepository            // for retry by group ID
	client       *http.Client
}

// New creates a Pusher with an SSRF-safe HTTP client (private/loopback/link-local
// targets blocked). Use WithDeliveryRepo to enable delivery logging, or
// WithHTTPClient to override the client.
func New(repo *repository.ScimPushRepository) *Pusher {
	return &Pusher{
		repo:   repo,
		client: safehttp.Client(pushTimeout, false),
	}
}

// WithHTTPClient overrides the outbound HTTP client (e.g. an SSRF-relaxed client
// when the operator has opted into private outbound targets).
func (p *Pusher) WithHTTPClient(c *http.Client) *Pusher {
	if c != nil {
		p.client = c
	}
	return p
}

// WithDeliveryRepo attaches a delivery log repository. When set every push
// attempt (success or failure) is recorded so admins can audit and retry.
func (p *Pusher) WithDeliveryRepo(dr *repository.ScimPushDeliveryRepository) *Pusher {
	p.deliveryRepo = dr
	return p
}

// WithUserRepo attaches the user repository needed for PushByUserID (retry).
func (p *Pusher) WithUserRepo(r *repository.UserRepository) *Pusher {
	p.userRepo = r
	return p
}

// WithGroupRepo attaches the group repository needed for PushByGroupID (retry).
func (p *Pusher) WithGroupRepo(r *repository.GroupRepository) *Pusher {
	p.groupRepo = r
	return p
}

// Push fans out SCIM requests to all active configs for the org/event pair.
// Runs in the caller's goroutine; call with go if you don't want to block.
func (p *Pusher) Push(ctx context.Context, orgID uuid.UUID, event string, user *models.User) {
	configs, err := p.repo.ListActiveByOrgAndEvent(ctx, orgID, event)
	if err != nil {
		log.Error().Err(err).Str("event", event).Msg("scimpush: list configs failed")
		return
	}

	for _, cfg := range configs {
		start := time.Now()
		httpStatus, sendErr := p.sendUser(cfg, event, user)
		durMS := int(time.Since(start).Milliseconds())

		if sendErr != nil {
			log.Warn().
				Err(sendErr).
				Str("config_id", cfg.ID.String()).
				Str("endpoint", cfg.EndpointURL).
				Str("event", event).
				Msg("scimpush: delivery failed")
		}

		if p.deliveryRepo != nil {
			errMsg := (*string)(nil)
			if sendErr != nil {
				s := sendErr.Error()
				errMsg = &s
			}
			p.deliveryRepo.Record(ctx, repository.ScimDeliveryParams{
				ConfigID:    cfg.ID,
				Event:       event,
				SubjectID:   &user.ID,
				SubjectType: "user",
				HTTPStatus:  httpStatus,
				ErrorMsg:    errMsg,
				DurationMS:  &durMS,
			})
		}
	}
}

// PushGroup fans out SCIM group requests to all active configs subscribed to
// the event. memberIDs is the current membership snapshot after the operation.
func (p *Pusher) PushGroup(ctx context.Context, orgID uuid.UUID, event string, group *models.Group, memberIDs []uuid.UUID) {
	configs, err := p.repo.ListActiveByOrgAndEvent(ctx, orgID, event)
	if err != nil {
		log.Error().Err(err).Str("event", event).Msg("scimpush: list configs failed")
		return
	}

	for _, cfg := range configs {
		start := time.Now()
		httpStatus, sendErr := p.sendGroup(cfg, event, group, memberIDs)
		durMS := int(time.Since(start).Milliseconds())

		if sendErr != nil {
			log.Warn().
				Err(sendErr).
				Str("config_id", cfg.ID.String()).
				Str("endpoint", cfg.EndpointURL).
				Str("event", event).
				Msg("scimpush: group delivery failed")
		}

		if p.deliveryRepo != nil {
			errMsg := (*string)(nil)
			if sendErr != nil {
				s := sendErr.Error()
				errMsg = &s
			}
			p.deliveryRepo.Record(ctx, repository.ScimDeliveryParams{
				ConfigID:    cfg.ID,
				Event:       event,
				SubjectID:   &group.ID,
				SubjectType: "group",
				HTTPStatus:  httpStatus,
				ErrorMsg:    errMsg,
				DurationMS:  &durMS,
			})
		}
	}
}

// sendUser routes a user event to the correct HTTP verb and returns the HTTP
// status code (nil on network error) and any error.
func (p *Pusher) sendUser(cfg *models.ScimPushConfig, event string, user *models.User) (*int, error) {
	switch event {
	case EventUserCreated, EventUserUpdated:
		return p.putUser(cfg, user)
	case EventUserDeactivated:
		return p.deactivateUser(cfg, user)
	default:
		return nil, fmt.Errorf("unhandled event: %s", event)
	}
}

// sendGroup routes a group event.
func (p *Pusher) sendGroup(cfg *models.ScimPushConfig, event string, group *models.Group, memberIDs []uuid.UUID) (*int, error) {
	switch event {
	case EventGroupCreated, EventGroupUpdated:
		return p.putGroup(cfg, group, memberIDs)
	case EventGroupDeleted:
		return p.deleteGroup(cfg, group)
	default:
		return nil, fmt.Errorf("unhandled event: %s", event)
	}
}

// putUser sends a SCIM PUT /Users/{id} (full replace / create-or-update).
func (p *Pusher) putUser(cfg *models.ScimPushConfig, user *models.User) (*int, error) {
	resource := buildSCIMUser(user)
	body, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/Users/%s", cfg.EndpointURL, user.ID)
	return p.doRequest(cfg.BearerToken, http.MethodPut, url, body)
}

// deactivateUser sends a SCIM PATCH /Users/{id} setting active=false.
func (p *Pusher) deactivateUser(cfg *models.ScimPushConfig, user *models.User) (*int, error) {
	patch := map[string]any{
		"schemas": []string{scimPatchOp},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/Users/%s", cfg.EndpointURL, user.ID)
	return p.doRequest(cfg.BearerToken, http.MethodPatch, url, body)
}

// putGroup sends a SCIM PUT /Groups/{id}.
func (p *Pusher) putGroup(cfg *models.ScimPushConfig, group *models.Group, memberIDs []uuid.UUID) (*int, error) {
	resource := buildSCIMGroup(group, memberIDs)
	body, err := json.Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("%s/Groups/%s", cfg.EndpointURL, group.ID)
	return p.doRequest(cfg.BearerToken, http.MethodPut, url, body)
}

// deleteGroup sends a SCIM DELETE /Groups/{id}.
func (p *Pusher) deleteGroup(cfg *models.ScimPushConfig, group *models.Group) (*int, error) {
	url := fmt.Sprintf("%s/Groups/%s", cfg.EndpointURL, group.ID)
	return p.doRequest(cfg.BearerToken, http.MethodDelete, url, nil)
}

// doRequest executes an HTTP request and returns (httpStatus, error).
// httpStatus is nil on network-level errors (no response received).
func (p *Pusher) doRequest(bearerToken, method, url string, body []byte) (*int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	status := resp.StatusCode
	if status >= 400 {
		return &status, fmt.Errorf("SCIM %s returned %d", method, status)
	}
	return &status, nil
}

// ── SCIM 2.0 User resource ────────────────────────────────────────────────────

type scimUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId"`
	UserName   string      `json:"userName"`
	Active     bool        `json:"active"`
	Name       *scimName   `json:"name,omitempty"`
	Emails     []scimEmail `json:"emails"`
}

type scimName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

func buildSCIMUser(u *models.User) scimUser {
	su := scimUser{
		Schemas:    []string{scimSchema},
		ID:         u.ID.String(),
		ExternalID: u.ID.String(),
		UserName:   u.Email,
		Active:     u.IsActive,
		Emails: []scimEmail{
			{Value: u.Email, Type: "work", Primary: true},
		},
	}

	var firstName, lastName string
	if u.FirstName != nil {
		firstName = *u.FirstName
	}
	if u.LastName != nil {
		lastName = *u.LastName
	}
	if firstName != "" || lastName != "" {
		su.Name = &scimName{
			Formatted:  firstName + " " + lastName,
			GivenName:  firstName,
			FamilyName: lastName,
		}
	}

	return su
}

// ── SCIM 2.0 Group resource ───────────────────────────────────────────────────

type scimGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	ExternalID  string       `json:"externalId"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
}

type scimMember struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

func buildSCIMGroup(g *models.Group, memberIDs []uuid.UUID) scimGroup {
	members := make([]scimMember, 0, len(memberIDs))
	for _, id := range memberIDs {
		members = append(members, scimMember{Value: id.String(), Type: "User"})
	}
	return scimGroup{
		Schemas:     []string{scimGroupSchema},
		ID:          g.ID.String(),
		ExternalID:  g.ID.String(),
		DisplayName: g.Name,
		Members:     members,
	}
}

// ── Retry helpers (called from the delivery retry API) ────────────────────────

// PushByUserID fetches the user from the database and replays the event.
// Used exclusively by the retry endpoint — does not need the SCIM inbound context.
func (p *Pusher) PushByUserID(ctx context.Context, orgID uuid.UUID, event string, userID uuid.UUID) {
	if p.userRepo == nil {
		log.Warn().Msg("scimpush: retry skipped — user repo not attached")
		return
	}
	u, err := p.userRepo.GetByID(ctx, userID)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userID.String()).Msg("scimpush: retry — user not found")
		return
	}
	p.Push(ctx, orgID, event, u)
}

// PushByGroupID fetches the group from the database and replays the event.
func (p *Pusher) PushByGroupID(ctx context.Context, orgID uuid.UUID, event string, groupID uuid.UUID) {
	if p.groupRepo == nil {
		log.Warn().Msg("scimpush: retry skipped — group repo not attached")
		return
	}
	g, err := p.groupRepo.GetByID(ctx, groupID)
	if err != nil {
		log.Warn().Err(err).Str("group_id", groupID.String()).Msg("scimpush: retry — group not found")
		return
	}
	members, _ := p.groupRepo.ListMembers(ctx, groupID)
	memberIDs := make([]uuid.UUID, 0, len(members))
	for _, u := range members {
		memberIDs = append(memberIDs, u.ID)
	}
	p.PushGroup(ctx, orgID, event, g, memberIDs)
}

