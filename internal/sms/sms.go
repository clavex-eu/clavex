// Package sms provides the SMS delivery interface and ForOrg factory.
// SMS provider implementations live in internal/connectorregistry and are
// registered on package init; adding a new provider does not require modifying
// this file.
package sms

import (
	"context"
	"fmt"

	"github.com/clavex-eu/clavex/internal/connectorregistry"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
)

// Provider is the SMS delivery interface.
// It is a type alias for connectorregistry.SMSSender so that third-party
// connectors and callers that import this package use the same type.
type Provider = connectorregistry.SMSSender

// ForOrg returns the SMS provider configured for an organisation.
// Returns an error if SMS is disabled, not configured, or the provider ID is
// unknown (i.e. not registered in the connector registry).
func ForOrg(ctx context.Context, repo *repository.SMSSettingsRepository, orgID uuid.UUID) (Provider, error) {
	s, err := repo.Get(ctx, orgID)
	if err != nil || !s.IsActive {
		return nil, fmt.Errorf("sms not configured for org %s", orgID)
	}
	p, err := connectorregistry.NewSMSProvider(s.Provider, s.Config)
	if err != nil {
		return nil, fmt.Errorf("sms: %w", err)
	}
	return p, nil
}
