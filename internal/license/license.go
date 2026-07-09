// Package license handles offline license JWT verification and org-limit enforcement.
//
// # Architecture
//
//   - The Clavex team signs license JWTs with an EC P-256 private key that is
//     never committed to the repository.
//   - The matching public key is embedded here for offline verification — no
//     network call is needed to validate a license at runtime.
//   - Community edition: one active organization, unlimited users, no license file.
//   - Enterprise edition: OrgLimit / Tier from the JWT claims.
//
// # Grace period
//
// When the org count exceeds the license limit for the first time,
// `installation.first_violation_at` is set in the database.
// After 30 days the installation is "hard-blocked": the OIDC authorize /
// token endpoints return 503 until a valid license is applied or orgs are removed.
package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// licensePublicKeyPEM is the Clavex license signing public key (EC P-256).
// The matching private key is held by Clavex and is never stored in this repo.
// Replace this constant with the real production key before public release.
const licensePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobp+sbXbJkTwkLKFE5+B6aUoAwiQ
54m27afDwVMj4w5gaETYXpHjDjSNn16QkXxE7YGt/ewYKgGThz2kxZfmzg==
-----END PUBLIC KEY-----`

const (
	// communityOrgLimit is the maximum number of active orgs without a license.
	communityOrgLimit = 1
	// gracePeriod is the time before the hard-block kicks in after the first violation.
	gracePeriod = 30 * 24 * time.Hour
	// checkInterval is how often the background checker re-queries the database.
	checkInterval = 5 * time.Minute
)

// License holds the verified claims from a Clavex license JWT.
type License struct {
	InstallationID string
	OrgLimit       int
	ExpiresAt      time.Time
	Tier           string
	// Plan is an optional finer-grained plan identifier (e.g. "business_trial").
	// It is informational: entitlements are decided by Tier + expiry. A 30-day
	// Business trial is simply a Tier="business" license whose exp is 30 days
	// out; when it expires the Checker reverts to community automatically, so
	// no special trial-expiry logic is required here.
	Plan string
}

// licenseClaims is the registered + private JWT claims set.
type licenseClaims struct {
	jwt.RegisteredClaims
	OrgLimit int    `json:"org_limit"`
	Tier     string `json:"tier"`
	Plan     string `json:"plan"`
}

// ParseLicenseFile reads and verifies a license JWT from path.
// Returns nil, nil when path is empty (community edition).
func ParseLicenseFile(path string) (*License, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // path comes from config
	if err != nil {
		return nil, fmt.Errorf("license: read %q: %w", path, err)
	}
	return ParseLicenseToken(string(data))
}

// ParseLicenseToken verifies and parses a raw license JWT string.
func ParseLicenseToken(tokenStr string) (*License, error) {
	pubKey, err := parsePublicKey(licensePublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("license: embedded public key: %w", err)
	}

	var c licenseClaims
	tok, err := jwt.ParseWithClaims(
		strings.TrimSpace(tokenStr), &c,
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("license: unexpected signing method %q", t.Header["alg"])
			}
			return pubKey, nil
		},
		jwt.WithValidMethods([]string{"ES256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("license: invalid token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("license: token not valid")
	}

	sub, _ := c.GetSubject()
	exp, _ := c.GetExpirationTime()

	return &License{
		InstallationID: sub,
		OrgLimit:       c.OrgLimit,
		ExpiresAt:      exp.Time,
		Tier:           c.Tier,
		Plan:           c.Plan,
	}, nil
}

func parsePublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC public key")
	}
	return ecPub, nil
}

// State is the cached enforcement state, safe to read from any goroutine.
type State struct {
	// Valid: a non-expired license is loaded.
	Valid bool `json:"valid"`
	// Tier: "community" when no license.
	Tier string `json:"tier"`
	// Plan: optional finer-grained plan id (e.g. "business_trial"); empty unless
	// a valid license carries a plan claim. Informational only.
	Plan string `json:"plan,omitempty"`
	// OrgLimit: max allowed active organizations.
	OrgLimit int `json:"org_limit"`
	// CurrentOrgCount: live count at the last check cycle.
	CurrentOrgCount int `json:"current_org_count"`
	// ExceedsLimit: CurrentOrgCount > OrgLimit.
	ExceedsLimit bool `json:"exceeds_limit"`
	// FirstViolationAt: when the limit was first exceeded (nil = never).
	FirstViolationAt *time.Time `json:"first_violation_at,omitempty"`
	// GracePeriodExpired: violation has persisted longer than gracePeriod.
	GracePeriodExpired bool `json:"grace_period_expired"`
	// WarningMessage: human-readable description for banners and headers.
	WarningMessage string `json:"warning_message,omitempty"`
	// AuthBlocked: OIDC authorize/token must return 503 for new sessions.
	AuthBlocked bool `json:"auth_blocked"`
	// LicenseExpiresAt: JWT exp claim (zero if no license).
	LicenseExpiresAt time.Time `json:"license_expires_at,omitempty"`
	// LicenseExpiringSoon: license expires within 14 days.
	LicenseExpiringSoon bool `json:"license_expiring_soon"`
	// InstallationMismatch: the license is bound (sub) to a different installation
	// than this deployment. When enforcement is on, the licensed tier is dropped.
	InstallationMismatch bool `json:"installation_mismatch,omitempty"`
}

// HasBusinessEntitlement reports whether the installation is entitled to the
// Business feature set (WS-Fed, custom domains, BYOK, SIEM sinks, Marketplace
// publishing, multi-org). True only for a currently-valid Business or Enterprise
// license. A 30-day Business trial is a Tier=="business" license with a near
// exp, so it satisfies this while valid and stops satisfying it the moment the
// Checker recomputes state after expiry — no dedicated trial handling needed.
func (s State) HasBusinessEntitlement() bool {
	if !s.Valid {
		return false
	}
	switch s.Tier {
	case "business", "enterprise":
		return true
	default:
		return false
	}
}

// licenseBindingOK reports whether a license whose sub is licSub may run on the
// installation identified by localID. Unbound licenses (empty sub or the "*"
// site-license wildcard) run anywhere; otherwise the sub must equal localID.
func licenseBindingOK(licSub, localID string) bool {
	if licSub == "" || licSub == "*" {
		return true
	}
	return licSub == localID
}

// LicenseBindingID returns the stable per-installation identifier a license is
// bound to: the installation_uuid singleton (migration 000064). Unlike
// InstallationID (which hashes hostname+uuid for the privacy-preserving feed id),
// this is stable across hostname changes and shared by every node of a cluster
// pointed at the same database.
func LicenseBindingID(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var uuidStr string
	if err := pool.QueryRow(ctx,
		`SELECT installation_uuid::text FROM installation WHERE id = 1`,
	).Scan(&uuidStr); err != nil {
		return "", fmt.Errorf("license: read installation_uuid: %w", err)
	}
	return uuidStr, nil
}

// Checker periodically evaluates license compliance and caches the result.
type Checker struct {
	pool           *pgxpool.Pool
	lic            *License // nil = community (no license loaded)
	rawToken       string   // raw JWT string; empty for community edition
	enforceBinding bool     // reject licenses bound to a different installation
	mu             sync.RWMutex
	state          State
}

// NewChecker creates a Checker. lic may be nil for community edition.
// enforceBinding rejects (reverts to community) a license bound to a different
// installation_uuid than this deployment's.
func NewChecker(pool *pgxpool.Pool, lic *License, enforceBinding bool) *Checker {
	limit := communityOrgLimit
	tier := "community"
	plan := ""
	if lic != nil {
		limit = lic.OrgLimit
		tier = lic.Tier
		plan = lic.Plan
	}
	return &Checker{
		pool:           pool,
		lic:            lic,
		enforceBinding: enforceBinding,
		state: State{
			Valid:    lic != nil,
			Tier:     tier,
			OrgLimit: limit,
			Plan:     plan,
		},
	}
}

// Start performs an immediate compliance check and launches a background
// goroutine that re-checks every checkInterval. It returns when ctx is done.
func (c *Checker) Start(ctx context.Context) {
	c.refresh(ctx)
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.refresh(ctx)
			}
		}
	}()
}

// State returns the current cached license state. Safe to call concurrently.
func (c *Checker) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *Checker) refresh(ctx context.Context) {
	s := c.computeState(ctx)
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()

	switch {
	case s.AuthBlocked:
		log.Warn().
			Int("orgs", s.CurrentOrgCount).Int("limit", s.OrgLimit).
			Msg("license: hard-block active — new authentication requests rejected")
	case s.ExceedsLimit:
		log.Warn().Str("msg", s.WarningMessage).Msg("license: org limit exceeded (grace period active)")
	}
}

func (c *Checker) computeState(ctx context.Context) State {
	limit := communityOrgLimit
	tier := "community"
	plan := ""
	var licExpires time.Time
	licValid := false

	mismatch := false
	if c.lic != nil {
		limit = c.lic.OrgLimit
		tier = c.lic.Tier
		plan = c.lic.Plan
		licExpires = c.lic.ExpiresAt
		licValid = time.Now().Before(licExpires)
		if !licValid {
			// Expired license (incl. an expired Business trial) reverts to
			// community limits.
			limit = communityOrgLimit
			tier = "community"
			plan = ""
		}
		// Installation binding (anti-sharing): a license bound to a specific
		// installation_uuid must not be honoured on a different deployment.
		if licValid && c.enforceBinding {
			if localID, err := LicenseBindingID(ctx, c.pool); err != nil {
				// Transient DB error reading the uuid — don't penalise; log and skip
				// this cycle (the org-count query below would fail too).
				log.Warn().Err(err).Msg("license: cannot read installation binding id; skipping binding check")
			} else if !licenseBindingOK(c.lic.InstallationID, localID) {
				mismatch = true
				limit = communityOrgLimit
				tier = "community"
				plan = ""
				licValid = false
			}
		}
	}

	s := State{
		Valid:                c.lic == nil || licValid, // community is always "valid"
		Tier:                 tier,
		Plan:                 plan,
		OrgLimit:             limit,
		LicenseExpiresAt:     licExpires,
		InstallationMismatch: mismatch,
	}
	if mismatch {
		s.WarningMessage = "License is bound to a different installation; reverting to community tier. " +
			"Re-issue the license for this installation's id, or disable license.enforce_installation_binding during a DB migration."
	}
	if !licExpires.IsZero() {
		s.LicenseExpiringSoon = time.Until(licExpires) < 14*24*time.Hour
	}

	// Count active organizations.
	var orgCount int
	if err := c.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM organizations WHERE is_active = TRUE`,
	).Scan(&orgCount); err != nil {
		log.Error().Err(err).Msg("license: failed to count organizations")
		return s
	}
	s.CurrentOrgCount = orgCount

	if orgCount <= limit {
		// In compliance — clear any stale violation record.
		if err := c.clearViolation(ctx); err != nil {
			log.Error().Err(err).Msg("license: failed to clear violation timestamp")
		}
		return s
	}

	// Over limit.
	s.ExceedsLimit = true

	firstViolation, err := c.getOrSetViolation(ctx)
	if err != nil {
		log.Error().Err(err).Msg("license: failed to read/set violation timestamp")
		return s
	}
	s.FirstViolationAt = firstViolation

	if time.Since(*firstViolation) >= gracePeriod {
		s.GracePeriodExpired = true
		s.AuthBlocked = true
		s.WarningMessage = fmt.Sprintf(
			"License limit exceeded (%d/%d orgs). Grace period expired. "+
				"New authentication is blocked. Apply a license or remove organizations.",
			orgCount, limit,
		)
	} else {
		remaining := gracePeriod - time.Since(*firstViolation)
		days := int(remaining.Hours() / 24)
		s.WarningMessage = fmt.Sprintf(
			"License limit exceeded (%d/%d orgs). Grace period: %d day(s) remaining. "+
				"Apply a license or remove organizations to restore compliance.",
			orgCount, limit, days,
		)
	}
	return s
}

// getOrSetViolation returns the existing first_violation_at or sets it to NOW().
func (c *Checker) getOrSetViolation(ctx context.Context) (*time.Time, error) {
	var t *time.Time
	if err := c.pool.QueryRow(ctx,
		`SELECT first_violation_at FROM installation WHERE id = 1`,
	).Scan(&t); err != nil {
		return nil, err
	}
	if t != nil {
		return t, nil
	}
	// First violation — record timestamp.
	now := time.Now()
	if _, err := c.pool.Exec(ctx,
		`UPDATE installation SET first_violation_at = NOW() WHERE id = 1 AND first_violation_at IS NULL`,
	); err != nil {
		return nil, err
	}
	return &now, nil
}

// clearViolation resets first_violation_at when the installation is back in compliance.
func (c *Checker) clearViolation(ctx context.Context) error {
	_, err := c.pool.Exec(ctx,
		`UPDATE installation SET first_violation_at = NULL WHERE id = 1 AND first_violation_at IS NOT NULL`,
	)
	return err
}

// Reload validates newToken and, if valid, hot-swaps the active license without
// restarting the server. The background checker will pick up the new state on
// its next tick (within checkInterval), but an immediate refresh is triggered.
func (c *Checker) Reload(ctx context.Context, newToken string) error {
	lic, err := ParseLicenseToken(newToken)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.lic = lic
	c.rawToken = newToken
	c.mu.Unlock()
	// Trigger an immediate compliance re-check so the new state is reflected
	// in the very next State() call.
	c.refresh(ctx)
	return nil
}

// RawToken returns the raw license JWT string, or empty for community edition.
func (c *Checker) RawToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rawToken
}

// PersistToken stores the raw license JWT in the installation table so it
// survives server restarts. Call this after a successful Reload().
func PersistToken(ctx context.Context, pool *pgxpool.Pool, token string) error {
	_, err := pool.Exec(ctx,
		`UPDATE installation SET license_token = $1 WHERE id = 1`,
		token,
	)
	return err
}

// LoadFromDB reads the persisted license token from the installation table.
// Returns (nil, "", nil) when no token is stored (community edition).
func LoadFromDB(ctx context.Context, pool *pgxpool.Pool) (*License, string, error) {
	var token *string
	if err := pool.QueryRow(ctx,
		`SELECT license_token FROM installation WHERE id = 1`,
	).Scan(&token); err != nil {
		return nil, "", fmt.Errorf("license: read from DB: %w", err)
	}
	if token == nil || *token == "" {
		return nil, "", nil
	}
	lic, err := ParseLicenseToken(*token)
	if err != nil {
		return nil, *token, fmt.Errorf("license: DB token invalid: %w", err)
	}
	return lic, *token, nil
}

// InstallationID returns the privacy-preserving installation identifier:
//
//	hex(sha256(hostname + installation_uuid))
//
// The UUID is read from the singleton `installation` table created by migration 000064.
func InstallationID(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	var uuidStr string
	if err := pool.QueryRow(ctx,
		`SELECT installation_uuid::text FROM installation WHERE id = 1`,
	).Scan(&uuidStr); err != nil {
		return "", fmt.Errorf("license: read installation_uuid: %w", err)
	}
	hostname, _ := os.Hostname()
	sum := sha256.Sum256([]byte(hostname + uuidStr))
	return hex.EncodeToString(sum[:]), nil
}
