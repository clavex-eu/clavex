// Package lifecycle implements the Joiner/Mover/Leaver (JML) workflow engine.
//
// Rules are stored in identity.lifecycle_rules and evaluated synchronously
// after SCIM user events (create, update, deactivate/delete).
//
// # Rule evaluation
//
// For each trigger event, active rules are fetched in priority order (lowest
// number first). ALL conditions of a rule must match for the rule to fire
// (AND logic). When a rule fires, all its actions are executed in order.
// Evaluation continues to the next rule (all-match, not first-match).
//
// # Conditions
//
//   field: email | first_name | last_name | is_active | <metadata key>
//   op:    eq | neq | contains | starts_with | ends_with | exists | not_exists
//
// # Actions
//
//   assign_role       – role_name
//   remove_role       – role_name
//   add_to_group      – group_name
//   remove_from_group – group_name
//   revoke_sessions   – (no params) revoke all active refresh tokens
//   send_notification – notification_type ("account_disabled" | "account_enabled")
package lifecycle

import (
	"context"
	"fmt"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Engine applies lifecycle rules to users.
type Engine struct {
	rules  *repository.LifecycleRepository
	users  *repository.UserRepository
	groups *repository.GroupRepository
	tokens *repository.RefreshTokenRepository
	ssf    *ssf.Dispatcher // nil = SSF not configured
}

// NewEngine creates a lifecycle engine.
// ssfDisp may be nil; if set, send_notification actions will fire SSF events.
func NewEngine(
	rules *repository.LifecycleRepository,
	users *repository.UserRepository,
	groups *repository.GroupRepository,
	tokens *repository.RefreshTokenRepository,
	ssfDisp *ssf.Dispatcher,
) *Engine {
	return &Engine{
		rules:  rules,
		users:  users,
		groups: groups,
		tokens: tokens,
		ssf:    ssfDisp,
	}
}

// UserContext is the set of attributes available to lifecycle conditions.
type UserContext struct {
	User    *models.User
	OrgSlug string
}

// buildAttrs flattens the user into a string map for condition evaluation.
func buildAttrs(uc UserContext) map[string]string {
	u := uc.User
	attrs := map[string]string{
		"email":     u.Email,
		"is_active": fmt.Sprintf("%v", u.IsActive),
	}
	if u.FirstName != nil {
		attrs["first_name"] = *u.FirstName
	}
	if u.LastName != nil {
		attrs["last_name"] = *u.LastName
	}
	// Flatten metadata (string values only)
	for k, v := range u.Metadata {
		if s, ok := v.(string); ok {
			attrs[k] = s
		}
	}
	return attrs
}

// matchesAll returns true if all conditions in the rule match the user context.
// An empty condition list matches everything.
func matchesAll(conditions []models.LifecycleCondition, attrs map[string]string) bool {
	for _, c := range conditions {
		val, exists := attrs[c.Field]
		switch c.Op {
		case "exists":
			if !exists {
				return false
			}
		case "not_exists":
			if exists {
				return false
			}
		case "eq":
			if !exists || !strings.EqualFold(val, c.Value) {
				return false
			}
		case "neq":
			if !exists || strings.EqualFold(val, c.Value) {
				return false
			}
		case "contains":
			if !exists || !strings.Contains(strings.ToLower(val), strings.ToLower(c.Value)) {
				return false
			}
		case "starts_with":
			if !exists || !strings.HasPrefix(strings.ToLower(val), strings.ToLower(c.Value)) {
				return false
			}
		case "ends_with":
			if !exists || !strings.HasSuffix(strings.ToLower(val), strings.ToLower(c.Value)) {
				return false
			}
		default:
			// unknown op → conservative: no match
			return false
		}
	}
	return true
}

// Apply fetches all active rules for the given trigger and executes the actions
// of every matching rule. Errors in individual actions are logged but do not
// stop subsequent rule processing.
func (e *Engine) Apply(ctx context.Context, trigger models.LifecycleTrigger, uc UserContext) {
	orgID := uc.User.OrgID
	userID := uc.User.ID

	rules, err := e.rules.ListActiveByTrigger(ctx, orgID, trigger)
	if err != nil {
		log.Error().Err(err).
			Str("trigger", string(trigger)).
			Str("org_id", orgID.String()).
			Msg("lifecycle: list rules failed")
		return
	}
	if len(rules) == 0 {
		return
	}

	attrs := buildAttrs(uc)

	for _, rule := range rules {
		if !matchesAll(rule.Conditions, attrs) {
			continue
		}
		log.Info().
			Str("rule", rule.Name).
			Str("trigger", string(trigger)).
			Str("user_id", userID.String()).
			Msg("lifecycle: rule matched")

		for _, action := range rule.Actions {
			if err := e.execAction(ctx, action, orgID, userID, uc.OrgSlug, uc.User.Email); err != nil {
				log.Error().Err(err).
					Str("rule", rule.Name).
					Str("action", action.Type).
					Str("user_id", userID.String()).
					Msg("lifecycle: action failed")
			}
		}
	}
}

func (e *Engine) execAction(ctx context.Context, a models.LifecycleAction, orgID, userID uuid.UUID, orgSlug, userEmail string) error {
	switch a.Type {
	case "assign_role":
		return e.assignRole(ctx, orgID, userID, a.RoleName)
	case "remove_role":
		return e.removeRole(ctx, orgID, userID, a.RoleName)
	case "add_to_group":
		return e.addToGroup(ctx, orgID, userID, a.GroupName)
	case "remove_from_group":
		return e.removeFromGroup(ctx, orgID, userID, a.GroupName)
	case "revoke_sessions":
		return e.tokens.RevokeAllByUser(ctx, orgID, userID)
	case "send_notification":
		return e.sendNotification(ctx, orgID, userID, orgSlug, userEmail, a.NotificationType)
	default:
		return fmt.Errorf("unknown action type %q", a.Type)
	}
}

func (e *Engine) assignRole(ctx context.Context, orgID, userID uuid.UUID, roleName string) error {
	role, err := e.users.GetRoleByName(ctx, orgID, roleName)
	if err != nil {
		return fmt.Errorf("assign_role: role %q not found: %w", roleName, err)
	}
	return e.users.AssignRole(ctx, userID, role.ID)
}

func (e *Engine) removeRole(ctx context.Context, orgID, userID uuid.UUID, roleName string) error {
	role, err := e.users.GetRoleByName(ctx, orgID, roleName)
	if err != nil {
		return fmt.Errorf("remove_role: role %q not found: %w", roleName, err)
	}
	return e.users.UnassignRole(ctx, userID, role.ID)
}

func (e *Engine) addToGroup(ctx context.Context, orgID, userID uuid.UUID, groupName string) error {
	group, err := e.groups.GetByName(ctx, orgID, groupName)
	if err != nil {
		return fmt.Errorf("add_to_group: group %q not found: %w", groupName, err)
	}
	return e.groups.AddMember(ctx, group.ID, userID)
}

func (e *Engine) removeFromGroup(ctx context.Context, orgID, userID uuid.UUID, groupName string) error {
	group, err := e.groups.GetByName(ctx, orgID, groupName)
	if err != nil {
		return fmt.Errorf("remove_from_group: group %q not found: %w", groupName, err)
	}
	return e.groups.RemoveMember(ctx, group.ID, userID)
}

func (e *Engine) sendNotification(ctx context.Context, orgID uuid.UUID, userID uuid.UUID, orgSlug, userEmail, notifType string) error {
	if e.ssf == nil {
		return nil
	}
	var eventType string
	switch notifType {
	case "account_disabled", "":
		eventType = ssf.EventAccountDisabled
	case "account_enabled":
		eventType = ssf.EventAccountEnabled
	case "account_purged":
		eventType = ssf.EventAccountPurged
	case "sessions_revoked":
		eventType = ssf.EventSessionsRevoked
	default:
		eventType = ssf.EventAccountDisabled
	}
	e.ssf.Dispatch(orgID, orgSlug, userID.String(), eventType, map[string]interface{}{
		"subject_email": userEmail,
	})
	return nil
}
