package session

import (
	"context"
	"encoding/json"
	"time"
)

const (
	prefixWalletStepup     = "clavex:wallet_stepup:"
	prefixWalletStepupUser = "clavex:wallet_stepup_user:"
	walletStepupTTL        = 15 * time.Minute
)

// WalletStepUpChallenge holds an in-flight Continuous Adaptive Authentication
// wallet step-up challenge. When UEBA/risk scoring detects an anomaly during
// an active session, the user's IT-Wallet must present a fresh SPID/CIE SD-JWT
// credential to re-establish a high assurance level.
type WalletStepUpChallenge struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	UserID      string     `json:"user_id"`
	OrgSlug     string     `json:"org_slug"`
	Nonce       string     `json:"nonce"`
	VCTs        []string   `json:"vcts"` // accepted credential type URNs (SPID/CIE)
	IssuedAfter time.Time  `json:"issued_after"`
	Status      string     `json:"status"` // "pending" | "completed" | "failed"
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	RiskScore   int        `json:"risk_score"`
	RiskReasons []string   `json:"risk_reasons"`
}

// SaveWalletStepUpChallenge stores the challenge in Redis with a 15-minute TTL,
// and maintains a secondary index keyed on (orgID, userID) for pending-challenge
// lookup (used by the Introspect handler to avoid creating duplicate challenges).
func (s *Store) SaveWalletStepUpChallenge(ctx context.Context, c *WalletStepUpChallenge) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := s.rdb.SetEx(ctx, prefixWalletStepup+c.ID, b, walletStepupTTL).Err(); err != nil {
		return err
	}
	// Secondary index so Introspect can find the challenge by (orgID, userID).
	userKey := prefixWalletStepupUser + c.OrgID + ":" + c.UserID
	return s.rdb.SetEx(ctx, userKey, c.ID, walletStepupTTL).Err()
}

// GetWalletStepUpChallenge retrieves a challenge by its ID.
// Returns nil, redis.Nil when not found (e.g. expired or never created).
func (s *Store) GetWalletStepUpChallenge(ctx context.Context, id string) (*WalletStepUpChallenge, error) {
	b, err := s.rdb.Get(ctx, prefixWalletStepup+id).Bytes()
	if err != nil {
		return nil, err
	}
	var c WalletStepUpChallenge
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// GetPendingWalletStepUpChallenge returns the active pending challenge for the
// given (orgID, userID) pair, or nil if no pending challenge exists.
// Returns nil (no error) when there is nothing to return.
func (s *Store) GetPendingWalletStepUpChallenge(ctx context.Context, orgID, userID string) (*WalletStepUpChallenge, error) {
	userKey := prefixWalletStepupUser + orgID + ":" + userID
	challengeID, err := s.rdb.Get(ctx, userKey).Result()
	if err != nil {
		return nil, nil //nolint:nilerr // no pending challenge — not an error
	}
	challenge, err := s.GetWalletStepUpChallenge(ctx, challengeID)
	if err != nil || challenge == nil {
		return nil, nil //nolint:nilerr // expired or missing
	}
	if challenge.Status != "pending" {
		return nil, nil
	}
	return challenge, nil
}

// CompleteWalletStepUpChallenge marks the challenge as completed.
func (s *Store) CompleteWalletStepUpChallenge(ctx context.Context, id string) error {
	return s.updateWalletStepUpStatus(ctx, id, "completed")
}

// FailWalletStepUpChallenge marks the challenge as failed.
func (s *Store) FailWalletStepUpChallenge(ctx context.Context, id string) error {
	return s.updateWalletStepUpStatus(ctx, id, "failed")
}

func (s *Store) updateWalletStepUpStatus(ctx context.Context, id, status string) error {
	challenge, err := s.GetWalletStepUpChallenge(ctx, id)
	if err != nil {
		return err
	}
	challenge.Status = status
	now := time.Now()
	challenge.CompletedAt = &now
	b, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	// Preserve the remaining TTL (or give a 1-minute tombstone if already expired).
	remaining := time.Until(challenge.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Minute
	}
	return s.rdb.SetEx(ctx, prefixWalletStepup+id, b, remaining).Err()
}
