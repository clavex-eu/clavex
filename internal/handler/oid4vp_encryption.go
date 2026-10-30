package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	secretcrypto "github.com/clavex-eu/clavex/internal/crypto"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// WithResponseEncryption uses the deployment's existing secret-encryption key,
// shared across replicas. JAR signing keys are never reused for ECDH or wrapping.
func (h *OID4VPHandler) WithResponseEncryption(enc *secretcrypto.Encryptor) *OID4VPHandler {
	h.responseEncryption = enc
	return h
}

type vpResponseKeyEnvelope struct {
	KeyID      string `json:"key_id"`
	RequestID  string `json:"request_id"`
	OrgID      string `json:"org_id"`
	PrivateDER []byte `json:"private_der"`
}

func (h *OID4VPHandler) responseKey(ctx context.Context, s *models.PresentationSession, create bool) (*ecdsa.PrivateKey, jwk.Key, error) {
	if h.responseEncryption == nil {
		return nil, nil, fmt.Errorf("response encryption not configured")
	}
	if len(s.ResponseKeyCiphertext) == 0 && create {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		// The polling API treats request_id as a bearer capability. Keep it out
		// of the unencrypted JWE header by using a sealed, domain-tagged selector.
		kid, err := h.responseEncryption.Encrypt("oid4vp-response-key:" + s.RequestID)
		if err != nil {
			return nil, nil, err
		}
		plain, err := json.Marshal(vpResponseKeyEnvelope{KeyID: kid, RequestID: s.RequestID, OrgID: s.OrgID.String(), PrivateDER: der})
		if err != nil {
			return nil, nil, err
		}
		cipher, err := h.responseEncryption.EncryptBytes(plain)
		if err != nil {
			return nil, nil, err
		}
		s.ResponseKeyCiphertext, err = h.repo.SetPresentationResponseKey(ctx, s.OrgID, s.RequestID, cipher)
		if err != nil {
			return nil, nil, err
		}
	}
	plain, err := h.responseEncryption.DecryptBytes(s.ResponseKeyCiphertext)
	if err != nil {
		return nil, nil, err
	}
	var stored vpResponseKeyEnvelope
	if err = json.Unmarshal(plain, &stored); err != nil {
		return nil, nil, err
	}
	if stored.RequestID != s.RequestID || stored.OrgID != s.OrgID.String() || stored.KeyID == "" {
		return nil, nil, fmt.Errorf("response key session mismatch")
	}
	raw, err := x509.ParsePKCS8PrivateKey(stored.PrivateDER)
	if err != nil {
		return nil, nil, err
	}
	key, ok := raw.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("invalid response key")
	}
	public, err := jwk.FromRaw(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	for name, value := range map[string]any{"kid": stored.KeyID, "alg": jwa.ECDH_ES, "use": "enc"} {
		if err = public.Set(name, value); err != nil {
			return nil, nil, err
		}
	}
	s.ResponseKeyThumbprint, err = public.Thumbprint(crypto.SHA256)
	return key, public, err
}

func (h *OID4VPHandler) responseClientMetadata(ctx context.Context, s *models.PresentationSession) (map[string]interface{}, error) {
	metadata := make(map[string]interface{}, len(defaultClientMetadata)+2)
	for k, v := range defaultClientMetadata {
		metadata[k] = v
	}
	if s.ResponseMode == "direct_post.jwt" {
		_, key, err := h.responseKey(ctx, s, true)
		if err != nil {
			return nil, err
		}
		metadata["jwks"] = map[string]any{"keys": []jwk.Key{key}}
		metadata["encrypted_response_enc_values_supported"] = []string{"A128GCM", "A256GCM"}
	}
	return metadata, nil
}

type encryptedVPResponse struct {
	State            string          `json:"state"`
	VPToken          json.RawMessage `json:"vp_token"`
	Error            string          `json:"error"`
	ErrorDescription string          `json:"error_description"`
}

func (h *OID4VPHandler) decryptVPResponse(c echo.Context, compact string) (*models.PresentationSession, *encryptedVPResponse, error) {
	invalid := fmt.Errorf("invalid encrypted authorization response")
	if h.responseEncryption == nil || len(compact) > 2*1024*1024 || strings.Count(compact, ".") != 4 {
		return nil, nil, invalid
	}
	message, err := jwe.Parse([]byte(compact))
	if err != nil {
		return nil, nil, invalid
	}
	header := message.ProtectedHeaders()
	if header.Algorithm() != jwa.ECDH_ES || (header.ContentEncryption() != jwa.A128GCM && header.ContentEncryption() != jwa.A256GCM) || header.Compression() != "" || len(header.Critical()) != 0 || header.KeyID() == "" || len(header.KeyID()) > 128 {
		return nil, nil, invalid
	}
	epk := header.EphemeralPublicKey()
	if epk == nil {
		return nil, nil, invalid
	}
	var ephemeral any
	if err = epk.Raw(&ephemeral); err != nil {
		return nil, nil, invalid
	}
	ec, ok := ephemeral.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, nil, invalid
	}
	if !secretcrypto.IsEncrypted(header.KeyID()) {
		return nil, nil, invalid
	}
	selector, err := h.responseEncryption.Decrypt(header.KeyID())
	if err != nil {
		return nil, nil, invalid
	}
	requestID, ok := strings.CutPrefix(selector, "oid4vp-response-key:")
	if !ok || requestID == "" {
		return nil, nil, invalid
	}
	ctx := c.Request().Context()
	s, err := h.repo.GetPresentationSession(ctx, requestID)
	if err != nil {
		return nil, nil, invalid
	}
	org, err := h.resolveOrgVP(c)
	if err != nil {
		return nil, nil, err
	}
	if s.OrgID != org.ID || s.ResponseMode != "direct_post.jwt" || s.Status != "pending" || !time.Now().Before(s.ExpiresAt) {
		return nil, nil, invalid
	}
	key, public, err := h.responseKey(ctx, s, false)
	if err != nil || public.KeyID() != header.KeyID() {
		return nil, nil, invalid
	}
	plain, err := jwe.Decrypt([]byte(compact), jwe.WithKey(jwa.ECDH_ES, key))
	if err != nil {
		return nil, nil, invalid
	}
	if len(plain) > 2*1024*1024 {
		return nil, nil, invalid
	}
	var response encryptedVPResponse
	if err = json.Unmarshal(plain, &response); err != nil {
		return nil, nil, invalid
	}
	expected := s.RequestID
	if s.State != nil {
		expected = *s.State
	}
	if response.State != expected || response.State == "" {
		return nil, nil, invalid
	}
	if response.Error != "" && len(response.VPToken) > 0 {
		return nil, nil, invalid
	}
	return s, &response, nil
}

func (h *OID4VPHandler) defaultResponseMode() string {
	if h.responseEncryption != nil {
		return "direct_post.jwt"
	}
	return "direct_post"
}
