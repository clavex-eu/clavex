package ssf_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/ssf"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv
}

func newTestConfig(t *testing.T) *ssf.SETConfig {
	t.Helper()
	return &ssf.SETConfig{
		Issuer:     "https://id.example.com/test-org",
		PrivateKey: generateKey(t),
		KID:        "test-key-1",
	}
}

// parseVerify parses and verifies a compact SET JWT using the public key
// derived from cfg. Returns the parsed jwt.Token.
func parseVerify(t *testing.T, compact string, cfg *ssf.SETConfig) jwt.Token {
	t.Helper()
	priv, ok := cfg.PrivateKey.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey")

	pubJWK, err := jwk.FromRaw(&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, cfg.KID))

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(pubJWK))

	tok, err := jwt.Parse(
		[]byte(compact),
		jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(false), // we check claims manually
	)
	require.NoError(t, err, "JWT signature verification failed")
	return tok
}

// parseProtectedHeaders returns the protected header map of the first
// signature in a compact JWS/JWT.
func parseProtectedHeaders(t *testing.T, compact string) jws.Headers {
	t.Helper()
	msg, err := jws.Parse([]byte(compact))
	require.NoError(t, err)
	require.NotEmpty(t, msg.Signatures())
	return msg.Signatures()[0].ProtectedHeaders()
}

// ── BuildSET ─────────────────────────────────────────────────────────────────

func TestBuildSET_ReturnsValidRS256JWT(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-123")

	compact, jti, err := ssf.BuildSET(cfg, "client-abc", subject, ssf.EventSessionRevoked, nil)

	require.NoError(t, err)
	assert.NotEmpty(t, compact)
	assert.NotEmpty(t, jti)

	// Must be three dot-separated base64url parts.
	parts := strings.Split(compact, ".")
	assert.Len(t, parts, 3, "compact JWT should have 3 parts")
}

func TestBuildSET_HeaderTypIsSecEventJWT(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-123")

	compact, _, err := ssf.BuildSET(cfg, "client-abc", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	hdrs := parseProtectedHeaders(t, compact)

	typVal, ok := hdrs.Get("typ")
	require.True(t, ok, "typ header must be present")
	assert.Equal(t, "secevent+jwt", typVal, "RFC 8417 §2.1: typ must be secevent+jwt")
}

func TestBuildSET_HeaderKIDPropagated(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-123")

	compact, _, err := ssf.BuildSET(cfg, "client-abc", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	hdrs := parseProtectedHeaders(t, compact)
	assert.Equal(t, cfg.KID, hdrs.KeyID())
}

func TestBuildSET_AlgorithmIsRS256(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-123")

	compact, _, err := ssf.BuildSET(cfg, "client-abc", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	hdrs := parseProtectedHeaders(t, compact)
	assert.Equal(t, jwa.RS256.String(), hdrs.Algorithm().String())
}

func TestBuildSET_SignatureVerifiesWithPublicKey(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-123")

	compact, _, err := ssf.BuildSET(cfg, "client-abc", subject, ssf.EventAccountDisabled, nil)
	require.NoError(t, err)

	// parseVerify fails the test if signature is invalid.
	parseVerify(t, compact, cfg)
}

func TestBuildSET_ClaimsIssAudJTI(t *testing.T) {
	cfg := newTestConfig(t)
	audience := "rp-client-xyz"
	subject := ssf.IssSubject(cfg.Issuer, "user-456")

	compact, jti, err := ssf.BuildSET(cfg, audience, subject, ssf.EventCredentialChange, nil)
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)

	assert.Equal(t, cfg.Issuer, tok.Issuer(), "iss must equal config issuer")
	assert.Contains(t, tok.Audience(), audience, "aud must contain the stream's client_id")
	assert.Equal(t, jti, tok.JwtID(), "jti in return value must match jti in token")
	assert.NotEmpty(t, tok.JwtID())
}

func TestBuildSET_EventsClaimStructure(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-789")
	eventBody := map[string]interface{}{"reason": "admin"}

	compact, _, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventAccountDisabled, eventBody)
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)

	// "events" claim must be a JSON object with the event URI as key.
	rawEvents, ok := tok.Get("events")
	require.True(t, ok, "events claim must be present (RFC 8417 §2.2)")

	events, ok := rawEvents.(map[string]interface{})
	require.True(t, ok, "events must be a map")
	require.Contains(t, events, ssf.EventAccountDisabled, "events key must be the event type URI")

	payload, ok := events[ssf.EventAccountDisabled].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "admin", payload["reason"])
}

func TestBuildSET_NilEventBodyBecomesEmptyObject(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "u")

	compact, _, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)
	rawEvents, ok := tok.Get("events")
	require.True(t, ok)
	events := rawEvents.(map[string]interface{})
	payload, ok := events[ssf.EventSessionRevoked].(map[string]interface{})
	require.True(t, ok)
	assert.Empty(t, payload, "nil event body should serialise as empty object {}")
}

func TestBuildSET_SubIDClaimPresent(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "user-sub-001")

	compact, _, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)

	rawSubID, ok := tok.Get("sub_id")
	require.True(t, ok, "sub_id claim must be present")

	// sub_id is serialised as a map (JSON object).
	subIDMap, ok := rawSubID.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "iss_sub", subIDMap["format"])
	assert.Equal(t, cfg.Issuer, subIDMap["iss"])
	assert.Equal(t, "user-sub-001", subIDMap["sub"])
}

func TestBuildSET_ToeClaimPresent(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "u")
	before := time.Now().Unix()

	compact, _, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventCredentialChange, nil)
	require.NoError(t, err)

	after := time.Now().Unix()
	tok := parseVerify(t, compact, cfg)

	rawToe, ok := tok.Get("toe")
	require.True(t, ok, "toe (time of event) claim must be present")

	// toe is serialised as a JSON number; jwx returns it as json.Number or float64.
	var toe int64
	switch v := rawToe.(type) {
	case float64:
		toe = int64(v)
	case json.Number:
		n, err := v.Int64()
		require.NoError(t, err)
		toe = n
	default:
		t.Fatalf("unexpected toe type %T", rawToe)
	}
	assert.GreaterOrEqual(t, toe, before)
	assert.LessOrEqual(t, toe, after)
}

func TestBuildSET_EachCallProducesUniqueJTI(t *testing.T) {
	cfg := newTestConfig(t)
	subject := ssf.IssSubject(cfg.Issuer, "u")

	_, jti1, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)
	_, jti2, err := ssf.BuildSET(cfg, "aud", subject, ssf.EventSessionRevoked, nil)
	require.NoError(t, err)

	assert.NotEqual(t, jti1, jti2, "each BuildSET call must produce a unique jti")
}

// ── BuildVerificationSET ─────────────────────────────────────────────────────

func TestBuildVerificationSET_EventTypeURI(t *testing.T) {
	cfg := newTestConfig(t)

	compact, _, err := ssf.BuildVerificationSET(cfg, "client-123", "state-abc")
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)

	rawEvents, ok := tok.Get("events")
	require.True(t, ok)
	events := rawEvents.(map[string]interface{})
	require.Contains(t, events, ssf.VerificationEventType, "verification SET must use the verification event URI")
}

func TestBuildVerificationSET_StateEchoed(t *testing.T) {
	cfg := newTestConfig(t)

	compact, _, err := ssf.BuildVerificationSET(cfg, "client-123", "my-state-42")
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)
	rawEvents := tok.PrivateClaims()["events"].(map[string]interface{})
	payload := rawEvents[ssf.VerificationEventType].(map[string]interface{})
	assert.Equal(t, "my-state-42", payload["state"])
}

func TestBuildVerificationSET_EmptyStateOmitted(t *testing.T) {
	cfg := newTestConfig(t)

	compact, _, err := ssf.BuildVerificationSET(cfg, "client-123", "")
	require.NoError(t, err)

	tok := parseVerify(t, compact, cfg)
	rawEvents := tok.PrivateClaims()["events"].(map[string]interface{})
	payload := rawEvents[ssf.VerificationEventType].(map[string]interface{})
	_, hasState := payload["state"]
	assert.False(t, hasState, "state key should be absent when empty")
}

// ── SignPushPayload ───────────────────────────────────────────────────────────

func TestSignPushPayload_Format(t *testing.T) {
	sig := ssf.SignPushPayload([]byte("secret"), []byte("body"))
	assert.True(t, strings.HasPrefix(sig, "sha256="), "signature must be prefixed with sha256=")
	// 7 chars for "sha256=" + 64 hex chars for SHA-256
	assert.Len(t, sig, 7+64)
}

func TestSignPushPayload_Deterministic(t *testing.T) {
	sig1 := ssf.SignPushPayload([]byte("key"), []byte("payload"))
	sig2 := ssf.SignPushPayload([]byte("key"), []byte("payload"))
	assert.Equal(t, sig1, sig2, "same inputs must produce same HMAC")
}

func TestSignPushPayload_DifferentSecrets(t *testing.T) {
	sig1 := ssf.SignPushPayload([]byte("key1"), []byte("payload"))
	sig2 := ssf.SignPushPayload([]byte("key2"), []byte("payload"))
	assert.NotEqual(t, sig1, sig2)
}

func TestSignPushPayload_DifferentBodies(t *testing.T) {
	sig1 := ssf.SignPushPayload([]byte("key"), []byte("body1"))
	sig2 := ssf.SignPushPayload([]byte("key"), []byte("body2"))
	assert.NotEqual(t, sig1, sig2)
}

// ── GenerateStreamSecret / HashStreamSecret ───────────────────────────────────

func TestGenerateStreamSecret_Length(t *testing.T) {
	s, err := ssf.GenerateStreamSecret()
	require.NoError(t, err)
	// 32 bytes base64url-encoded without padding: ceil(32*4/3) = 43 chars
	assert.Len(t, s, 43)
}

func TestGenerateStreamSecret_Unique(t *testing.T) {
	s1, err := ssf.GenerateStreamSecret()
	require.NoError(t, err)
	s2, err := ssf.GenerateStreamSecret()
	require.NoError(t, err)
	assert.NotEqual(t, s1, s2)
}

func TestHashStreamSecret_Deterministic(t *testing.T) {
	h1 := ssf.HashStreamSecret("my-secret")
	h2 := ssf.HashStreamSecret("my-secret")
	assert.Equal(t, h1, h2)
}

func TestHashStreamSecret_IsHexSHA256(t *testing.T) {
	h := ssf.HashStreamSecret("any")
	// SHA-256 hex = 64 lowercase hex chars
	assert.Len(t, h, 64)
	assert.Regexp(t, "^[0-9a-f]+$", h)
}

// ── BuildTransmitterMetadata ──────────────────────────────────────────────────

func TestBuildTransmitterMetadata_Fields(t *testing.T) {
	base := "https://id.example.com/my-org"
	meta := ssf.BuildTransmitterMetadata(base)

	assert.Equal(t, base, meta.Issuer)
	assert.Equal(t, base+"/.well-known/jwks.json", meta.JWKSUri)
	assert.Equal(t, base+"/ssf/stream", meta.ConfigurationEndpoint)
	assert.Equal(t, base+"/ssf/stream/status", meta.StatusEndpoint)
	assert.Contains(t, meta.DeliveryMethodsSupported, ssf.PushMethodURI)
	assert.Contains(t, meta.DeliveryMethodsSupported, ssf.PollMethodURI)
	assert.NotEmpty(t, meta.EventTypesSupported)
	assert.Contains(t, meta.EventTypesSupported, ssf.EventSessionRevoked)
	assert.Contains(t, meta.EventTypesSupported, ssf.EventAccountDisabled)
}

// ── streamWantsEvent (via dispatcher integration) ────────────────────────────

// stubRepo is a no-op StreamQueuer for dispatcher unit tests.
type stubRepo struct {
	mu          sync.Mutex
	pushStreams  []*models.SSFStream
	pollStreams  []*models.SSFStream
	enqueuedJTI []string
}

func (r *stubRepo) ListPushEnabled(_ context.Context, _ uuid.UUID) ([]*models.SSFStream, error) {
	return r.pushStreams, nil
}
func (r *stubRepo) ListPollEnabled(_ context.Context, _ uuid.UUID) ([]*models.SSFStream, error) {
	return r.pollStreams, nil
}
func (r *stubRepo) EnqueueSET(_ context.Context, _ uuid.UUID, jti, _, _ string) error {
	r.mu.Lock()
	r.enqueuedJTI = append(r.enqueuedJTI, jti)
	r.mu.Unlock()
	return nil
}

func newStream(clientID string, events []string, method string) *models.SSFStream {
	ep := "http://receiver.example.com/push"
	return &models.SSFStream{
		ID:              uuid.New(),
		OrgID:           uuid.New(),
		ClientID:        clientID,
		DeliveryMethod:  method,
		PushEndpoint:    &ep,
		EventsRequested: events,
		Status:          "enabled",
	}
}

func TestDispatcher_PollStream_EnqueuesSETForWantedEvent(t *testing.T) {
	cfg := newTestConfig(t)
	repo := &stubRepo{
		pollStreams: []*models.SSFStream{
			newStream("rp-1", []string{ssf.EventAccountDisabled}, "poll"),
		},
	}
	d := ssf.NewDispatcher(repo, cfg)

	orgID := uuid.New()
	// dispatch is synchronous via the unexported path; call the public Dispatch
	// and give the goroutine time to run.
	d.Dispatch(orgID, "test-org", "user-sub", ssf.EventAccountDisabled, nil)

	// Wait briefly for the goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		n := len(repo.enqueuedJTI)
		repo.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Len(t, repo.enqueuedJTI, 1, "exactly one SET should be enqueued for the poll stream")
}

func TestDispatcher_PollStream_SkipsUnwantedEvent(t *testing.T) {
	cfg := newTestConfig(t)
	repo := &stubRepo{
		pollStreams: []*models.SSFStream{
			// stream only wants session-revoked, not account-disabled
			newStream("rp-1", []string{ssf.EventSessionRevoked}, "poll"),
		},
	}
	d := ssf.NewDispatcher(repo, cfg)

	d.Dispatch(uuid.New(), "org", "sub", ssf.EventAccountDisabled, nil)
	time.Sleep(100 * time.Millisecond)

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Empty(t, repo.enqueuedJTI, "no SET should be enqueued for an unwanted event type")
}

func TestDispatcher_MultipleStreams_OnlyMatchingEnqueued(t *testing.T) {
	cfg := newTestConfig(t)
	repo := &stubRepo{
		pollStreams: []*models.SSFStream{
			newStream("rp-wants", []string{ssf.EventCredentialChange}, "poll"),
			newStream("rp-skip", []string{ssf.EventSessionRevoked}, "poll"),
		},
	}
	d := ssf.NewDispatcher(repo, cfg)

	d.Dispatch(uuid.New(), "org", "sub", ssf.EventCredentialChange, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		n := len(repo.enqueuedJTI)
		repo.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Len(t, repo.enqueuedJTI, 1, "only the matching stream should receive a SET")
}

func TestDynamicConfig_IssuerDerivedPerOrg(t *testing.T) {
	priv := generateKey(t)
	base := &ssf.SETConfig{PrivateKey: priv, KID: "k1"}

	repo := &stubRepo{
		pollStreams: []*models.SSFStream{
			newStream("client-1", []string{ssf.EventAccountPurged}, "poll"),
		},
	}
	d := ssf.NewDynamicDispatcher(repo, base, func(slug string) string {
		return "https://id.example.com/" + slug
	})

	d.Dispatch(uuid.New(), "acme", "user-1", ssf.EventAccountPurged, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		repo.mu.Lock()
		n := len(repo.enqueuedJTI)
		repo.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	repo.mu.Lock()
	jti := repo.enqueuedJTI
	repo.mu.Unlock()

	require.Len(t, jti, 1)
	// The SET is enqueued — verify the JTI is a valid UUID (proxy for a properly built SET).
	_, err := uuid.Parse(jti[0])
	assert.NoError(t, err, "enqueued JTI must be a valid UUID")
}

// ── IssSubject ────────────────────────────────────────────────────────────────

func TestIssSubject(t *testing.T) {
	s := ssf.IssSubject("https://issuer.example.com", "user-999")
	assert.Equal(t, "iss_sub", s.Format)
	assert.Equal(t, "https://issuer.example.com", s.Issuer)
	assert.Equal(t, "user-999", s.Subject)
}
