// Package federation — revnet.go
//
// Cross-installation Revocation Network.
//
// When installation A revokes a credential it calls
// RevNetDispatcher.Propagate(...).  The dispatcher fetches every active
// FederatedInstallation for the org, checks that the revocation reason is in
// the partner's propagate_on list, builds a CAEP credential-change SET signed
// with the local signing key, and POSTs it to the partner's ssf_endpoint.
//
// The receiving installation exposes a handler (see handler/revnet.go) that
// calls VerifyAndApply to validate the incoming SET and revoke matching local
// credentials.
package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// ── Repository interface ──────────────────────────────────────────────────────

type revnetRepo interface {
	ListActiveFederatedInstallations(ctx context.Context, orgID uuid.UUID) ([]*models.FederatedInstallation, error)
	GetFederatedInstallationByTokenHash(ctx context.Context, tokenHash string) (*models.FederatedInstallation, error)
	RevokeByVCTAndUser(ctx context.Context, orgID uuid.UUID, vct string, userSub string, reason string) error
}

// ── Outbound: RevNetDispatcher ────────────────────────────────────────────────

// RevNetDispatcher propagates credential revocations to all active federated
// partner installations for a given org.
type RevNetDispatcher struct {
	pool   *pgxpool.Pool
	repo   revnetRepo
	setcfg *ssf.SETConfig
}

// NewRevNetDispatcher creates a dispatcher.  setcfg must contain the local
// installation's signing key and issuer URL.
func NewRevNetDispatcher(pool *pgxpool.Pool, repo revnetRepo, setcfg *ssf.SETConfig) *RevNetDispatcher {
	return &RevNetDispatcher{pool: pool, repo: repo, setcfg: setcfg}
}

// Propagate sends a credential-change SET to all active federated partners whose
// propagate_on policy includes the given reason.  It runs asynchronously.
func (d *RevNetDispatcher) Propagate(
	orgID uuid.UUID,
	cred *models.IssuedCredential,
	userSub string,
	reason string,
) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.propagate(ctx, orgID, cred, userSub, reason)
	}()
}

func (d *RevNetDispatcher) propagate(
	ctx context.Context,
	orgID uuid.UUID,
	cred *models.IssuedCredential,
	userSub string,
	reason string,
) {
	partners, err := d.repo.ListActiveFederatedInstallations(ctx, orgID)
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID.String()).Msg("revnet: list federated installations")
		return
	}

	for _, p := range partners {
		if !reasonInPolicy(reason, p.PropagateOn) {
			continue
		}
		if err := d.send(ctx, p, cred, userSub, reason); err != nil {
			log.Warn().Err(err).
				Str("partner", p.EntityID).
				Str("cred_id", cred.ID.String()).
				Msg("revnet: propagation failed")
		} else {
			log.Info().
				Str("partner", p.EntityID).
				Str("vct", cred.VCT).
				Str("reason", reason).
				Msg("revnet: revocation propagated")
		}
	}
}

func (d *RevNetDispatcher) send(
	ctx context.Context,
	p *models.FederatedInstallation,
	cred *models.IssuedCredential,
	userSub string,
	reason string,
) error {
	subject := ssf.IssSubject(d.setcfg.Issuer, userSub)
	body := map[string]interface{}{
		"change_type":      "revoked",
		"vct":              cred.VCT,
		"credential_hash":  cred.SDJWTHash,
		"reason":           reason,
	}
	// Use the partner's entity_id as the SET audience so it can validate aud.
	compact, _, err := ssf.BuildSET(d.setcfg, p.EntityID, subject, ssf.EventCredentialChange, body)
	if err != nil {
		return fmt.Errorf("build SET: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.SSFEndpoint,
		bytes.NewBufferString(compact))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Authorization", "Bearer "+p.OutboundToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("partner returned %d", resp.StatusCode)
	}
	return nil
}

// ── Inbound: VerifyAndApply ───────────────────────────────────────────────────

// InboundEvent is the decoded payload from a partner's credential-change SET.
type InboundEvent struct {
	SenderEntityID  string
	VCT             string
	CredentialHash  string
	UserSub         string
	Reason          string
}

// VerifyAndApply validates an inbound credential-change SET from a federated
// partner and revokes the matching local credentials.
//
// The caller (handler/revnet.go) has already authenticated the request by
// looking up the federated_installation row via the inbound_token_hash; that
// row is passed here as sender so we can fetch its JWKS URI for signature
// verification.
func VerifyAndApply(
	ctx context.Context,
	repo revnetRepo,
	orgID uuid.UUID,
	sender *models.FederatedInstallation,
	setJWT string,
) (*InboundEvent, error) {
	// Fetch the sender's public keys (in-process JWKS cache via lestrrat-go/jwx).
	keySet, err := jwk.Fetch(ctx, sender.JWKSUri)
	if err != nil {
		return nil, fmt.Errorf("revnet: fetch jwks %s: %w", sender.JWKSUri, err)
	}

	// Verify signature and parse JWT.
	parsed, err := jwt.Parse([]byte(setJWT),
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("revnet: invalid SET signature: %w", err)
	}

	// Extract the credential-change event body.
	eventsRaw, ok := parsed.Get("events")
	if !ok {
		return nil, fmt.Errorf("revnet: SET missing events claim")
	}
	eventsMap, ok := eventsRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("revnet: events claim malformed")
	}
	eventBody, ok := eventsMap[ssf.EventCredentialChange]
	if !ok {
		return nil, fmt.Errorf("revnet: unexpected event type in SET")
	}
	bodyMap, _ := eventBody.(map[string]interface{})

	vct, _ := bodyMap["vct"].(string)
	if vct == "" {
		return nil, fmt.Errorf("revnet: missing vct in event body")
	}

	// Extract user_sub from the subject identifier.
	userSub := ""
	if subRaw, ok := parsed.Get("sub_id"); ok {
		if subMap, ok := subRaw.(map[string]interface{}); ok {
			userSub, _ = subMap["sub"].(string)
		}
	}

	reason, _ := bodyMap["reason"].(string)
	credHash, _ := bodyMap["credential_hash"].(string)

	// Apply revocation to matching local credentials.
	if userSub != "" {
		if err := repo.RevokeByVCTAndUser(ctx, orgID, vct, userSub, "federated:"+reason); err != nil {
			return nil, fmt.Errorf("revnet: apply local revocation: %w", err)
		}
	}

	return &InboundEvent{
		SenderEntityID: sender.EntityID,
		VCT:            vct,
		CredentialHash: credHash,
		UserSub:        userSub,
		Reason:         reason,
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func reasonInPolicy(reason string, policy []string) bool {
	r := strings.ToLower(reason)
	for _, p := range policy {
		if strings.ToLower(p) == r {
			return true
		}
	}
	return false
}

// TokenHash returns the SHA-256 hex digest used to look up inbound_token_hash.
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// ParseTokenHash parses a "Bearer <token>" header and returns the hex SHA-256.
func ParseTokenHash(authHeader string) (string, bool) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return TokenHash(parts[1]), true
}

