package handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Attesters are explicitly pinned per organization. No key supplied in a proof
// or an attestation can add itself to this trust store.
// settings.credential_key_attesters = [{"issuer":"...","jwks":{"keys":[...]}}]
type credentialKeyAttester struct {
	Issuer string          `json:"issuer"`
	JWKS   json.RawMessage `json:"jwks"`
}

func credentialAttesterKeys(org *models.Organization) (map[string][]jwk.Key, []interface{}, error) {
	byIssuer := map[string][]jwk.Key{}
	var advertised []interface{}
	value, ok := org.Settings["credential_key_attesters"]
	if !ok {
		return byIssuer, advertised, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	var entries []credentialKeyAttester
	if err := json.Unmarshal(b, &entries); err != nil || len(entries) > 20 {
		return nil, nil, fmt.Errorf("invalid credential_key_attesters configuration")
	}
	for _, entry := range entries {
		if entry.Issuer == "" || byIssuer[entry.Issuer] != nil {
			return nil, nil, fmt.Errorf("invalid or duplicate attester issuer")
		}
		set, err := jwk.Parse(entry.JWKS)
		if err != nil || set.Len() == 0 || set.Len() > 20 {
			return nil, nil, fmt.Errorf("invalid attester JWKS")
		}
		for i := 0; i < set.Len(); i++ {
			key, _ := set.Key(i)
			private, err := jwk.IsPrivateKey(key)
			if err != nil || private || (key.KeyType() != jwa.RSA && key.KeyType() != jwa.EC) {
				return nil, nil, fmt.Errorf("attester keys must be public asymmetric keys")
			}
			var raw any
			if err := key.Raw(&raw); err != nil {
				return nil, nil, fmt.Errorf("invalid attester key")
			}
			switch k := raw.(type) {
			case *ecdsa.PublicKey:
				if k.Curve != elliptic.P256() {
					return nil, nil, fmt.Errorf("attester EC keys must use P-256")
				}
			case *rsa.PublicKey:
				if k.N.BitLen() < 2048 {
					return nil, nil, fmt.Errorf("attester RSA keys require at least 2048 bits")
				}
			default:
				return nil, nil, fmt.Errorf("unsupported attester key")
			}
			byIssuer[entry.Issuer] = append(byIssuer[entry.Issuer], key)
			advertised = append(advertised, key)
		}
	}
	return byIssuer, advertised, nil
}

func validateCredentialAttestations(org *models.Organization, cfg *models.CredentialConfig, req *credentialRequest, proofs []verifiedCredentialProof, now time.Time, contexts ...context.Context) error {
	trusted, _, err := credentialAttesterKeys(org)
	if err != nil {
		return err
	}
	raws, err := req.proofJWTs()
	if err != nil {
		return err
	}
	if len(raws) != len(proofs) {
		return invalidCredentialProof("inconsistent holder proofs")
	}
	for i, raw := range raws {
		msg, err := jws.Parse([]byte(raw))
		if err != nil || len(msg.Signatures()) != 1 {
			return invalidCredentialProof("invalid holder proof")
		}
		header := msg.Signatures()[0].ProtectedHeaders()
		value, present := header.Get("key_attestation")
		if !present {
			if cfg.RequireKeyAttestation {
				return invalidCredentialProof("key attestation is required")
			}
			continue
		}
		attestation, ok := value.(string)
		if !ok || attestation == "" {
			return invalidCredentialProof("invalid key_attestation header")
		}
		ka, err := jws.Parse([]byte(attestation))
		if err != nil || len(ka.Signatures()) != 1 {
			return invalidCredentialProof("invalid key attestation JWT")
		}
		kh := ka.Signatures()[0].ProtectedHeaders()
		alg := kh.Algorithm()
		if kh.Type() != "key-attestation+jwt" || len(kh.Critical()) > 0 || (alg != jwa.ES256 && alg != jwa.PS256 && alg != jwa.RS256) || (cfg.CredentialFormat == "mso_mdoc" && alg != jwa.ES256) {
			return invalidCredentialProof("invalid key attestation type or algorithm")
		}
		var claims struct {
			Issuer    string            `json:"iss"`
			IssuedAt  *int64            `json:"iat"`
			ExpiresAt *int64            `json:"exp"`
			Nonce     string            `json:"nonce"`
			Keys      []json.RawMessage `json:"attested_keys"`
			Status    json.RawMessage   `json:"status"`
		}
		if err := json.Unmarshal(ka.Payload(), &claims); err != nil || claims.IssuedAt == nil || claims.ExpiresAt == nil || len(claims.Keys) == 0 || len(claims.Keys) > 100 {
			return invalidCredentialProof("missing or malformed key attestation claims")
		}
		if *claims.IssuedAt > now.Add(time.Minute).Unix() || *claims.ExpiresAt <= now.Unix() || *claims.ExpiresAt <= *claims.IssuedAt || claims.Nonce != proofs[i].Nonce {
			return invalidCredentialProof("expired or incorrectly bound key attestation")
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(ka.Payload(), &payload) != nil {
			return invalidCredentialProof("invalid key attestation payload")
		}
		if _, present := payload["iss"]; present && claims.Issuer == "" {
			return invalidCredentialProof("invalid key attestation issuer")
		}
		if value, present := org.Settings["key_attestation_issuer_required"]; present {
			required, valid := value.(bool)
			if !valid {
				return fmt.Errorf("invalid key attestation issuer policy")
			}
			if required && claims.Issuer == "" {
				return invalidCredentialProof("key attestation issuer is required by profile")
			}
		}
		// D.1 does not require iss. Resolve an issuer-less attestation only through
		// one unambiguous configured signer; never through its own jwk/x5c header.
		selectedIssuer := ""
		attempts := 0
		for issuer, keys := range trusted {
			if claims.Issuer != "" && issuer != claims.Issuer {
				continue
			}
			for _, key := range keys {
				if kh.KeyID() != "" && key.KeyID() != kh.KeyID() {
					continue
				}
				attempts++
				if attempts > 20 {
					return invalidCredentialProof("ambiguous or oversized attestation signer selection")
				}
				if _, err := jws.Verify([]byte(attestation), jws.WithKey(alg, key)); err == nil {
					if selectedIssuer != "" && selectedIssuer != issuer {
						return invalidCredentialProof("ambiguous attestation signer identity")
					}
					selectedIssuer = issuer
					break
				}
			}
		}
		if selectedIssuer == "" {
			return invalidCredentialProof("key attestation issuer or signing key is not trusted")
		}
		claims.Issuer = selectedIssuer

		if _, err := jwt.Parse([]byte(attestation), jwt.WithVerify(false), jwt.WithValidate(true), jwt.WithAcceptableSkew(time.Minute)); err != nil {
			return invalidCredentialProof("key attestation is not temporally valid")
		}
		wanted, err := proofs[i].Key.Thumbprint(crypto.SHA256)
		if err != nil {
			return invalidCredentialProof("invalid holder public key")
		}
		bound := false
		for _, encoded := range claims.Keys {
			key, err := jwk.ParseKey(encoded)
			if err != nil {
				return invalidCredentialProof("invalid attested key")
			}
			if _, err := marshalCredentialHolderKey(key); err != nil {
				return err
			}
			actual, err := key.Thumbprint(crypto.SHA256)
			if err != nil {
				return invalidCredentialProof("invalid attested key")
			}
			if string(actual) == string(wanted) {
				bound = true
			}
		}
		if !bound {
			return invalidCredentialProof("holder key is not included in attested_keys")
		}
		required := false
		if value, ok := org.Settings["key_attestation_status_required"]; ok {
			flag, valid := value.(bool)
			if !valid {
				return oid4w.ErrStatusUnavailable
			}
			required = flag
		}
		ctx := context.Background()
		if len(contexts) > 0 {
			ctx = contexts[0]
		}
		if err := oid4w.CheckDelegatedStatus(ctx, org.ID.String(), org.Settings, "key-attestation+jwt", claims.Issuer, "key-attestation+jwt", claims.Status, required); err != nil {
			if errors.Is(err, oid4w.ErrStatusUnavailable) {
				return err
			}
			return invalidCredentialProof("key attestation status is invalid")
		}

		if len(claims.Status) > 0 {
			proofs[i].StatusParents = append(proofs[i].StatusParents, oid4w.StatusParent{Format: "key-attestation+jwt", Issuer: claims.Issuer, Type: "key-attestation+jwt", Status: claims.Status})
		}
	}
	return nil
}
