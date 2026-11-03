package session

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/redis/go-redis/v9"
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

// ErrWalletStepUpConsumed also covers expired/missing challenges: none may be
// resurrected or have a successful terminal state overwritten by a late failure.
var ErrWalletStepUpConsumed = errors.New("wallet step-up challenge is expired or already consumed")

var walletStepUpCAS = redis.NewScript(`
local current=redis.call('GET',KEYS[1])
if not current or current~=ARGV[1] then return 0 end
local ttl=redis.call('PTTL',KEYS[1])
local now=redis.call('TIME')
if ttl<=0 or tonumber(ARGV[3])<=tonumber(now[1])*1000+math.floor(tonumber(now[2])/1000) then return 0 end
redis.call('SET',KEYS[1],ARGV[2],'PX',ttl)
return 1
`)

func (s *Store) CompleteWalletStepUpForSubject(ctx context.Context, id, org, user, nonce string) error {
	return s.transitionWalletStepUp(ctx, id, "completed", org, user, nonce)
}

func (s *Store) updateWalletStepUpStatus(ctx context.Context, id, status string) error {
	return s.transitionWalletStepUp(ctx, id, status, "", "", "")
}

func (s *Store) transitionWalletStepUp(ctx context.Context, id, status, org, user, nonce string) error {
	if status != "completed" && status != "failed" {
		return ErrWalletStepUpConsumed
	}
	raw, err := s.rdb.Get(ctx, prefixWalletStepup+id).Bytes()
	if err != nil {
		return err
	}
	var challenge WalletStepUpChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return err
	}
	if challenge.ID != id || challenge.Status != "pending" || !time.Now().Before(challenge.ExpiresAt) {
		return ErrWalletStepUpConsumed
	}
	if org != "" && (challenge.OrgID != org || challenge.UserID != user || challenge.Nonce != nonce) {
		return ErrWalletStepUpConsumed
	}
	challenge.Status = status
	now := time.Now().UTC()
	challenge.CompletedAt = &now
	updated, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	result, err := walletStepUpCAS.Run(ctx, s.rdb, []string{prefixWalletStepup + id}, string(raw), string(updated), challenge.ExpiresAt.UnixMilli()).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrWalletStepUpConsumed
	}
	return nil
}
