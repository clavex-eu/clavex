package oid4w

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// VerifiedCredentialIdentity is populated by verifiers, never deserialized from
// wallet claims. Key possession, issuer trust and account identity are distinct.
type VerifiedCredentialIdentity struct {
	Format              string
	Issuer              string
	CredentialType      string
	Subject             string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	IssuerTrusted       bool
	SignedByLocalIssuer bool
	HolderBound         bool
	IssuerJWTHash       string
	Status              json.RawMessage
	CertificateChains   [][]*x509.Certificate
	IssuerCOSEHash      string
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	for _, key := range []crypto.PublicKey{a, b} {
		value := reflect.ValueOf(key)
		if value.Kind() == reflect.Ptr && value.IsNil() {
			return false
		}
	}
	ax, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bx, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && string(ax) == string(bx)
}

// Read identifying fields from the signed issuer JWT, not disclosure overrides.
func verifiedSDJWTIdentity(raw string, trusted, local, bound bool) (*VerifiedCredentialIdentity, error) {
	token, err := jwt.Parse([]byte(raw), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, err
	}
	vct, _ := token.Get("vct")
	credentialType, _ := vct.(string)
	evidence := &VerifiedCredentialIdentity{Format: "dc+sd-jwt", Issuer: token.Issuer(), CredentialType: credentialType, Subject: token.Subject(), IssuedAt: token.IssuedAt(), ExpiresAt: token.Expiration(), IssuerTrusted: trusted, SignedByLocalIssuer: local, HolderBound: bound, IssuerJWTHash: HashToken(raw)}
	if value, ok := token.Get("status"); ok {
		evidence.Status, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	return evidence, nil
}

// A DS public-key identity survives certificate renewal using the same key;
// rotating that key requires explicit review of account links.
func MDOCIssuerIdentity(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "x509-spki-sha256:" + hex.EncodeToString(h[:])
}

type WalletIdentityProfile struct {
	Format         string   `json:"format"`
	Issuer         string   `json:"issuer"`
	CredentialType string   `json:"credential_type"`
	ClaimPath      []string `json:"claim_path"`
}

func (p WalletIdentityProfile) Validate() error {
	if (p.Format != "dc+sd-jwt" && p.Format != "mso_mdoc") || p.Issuer == "" || len(p.Issuer) > 512 || p.CredentialType == "" || len(p.CredentialType) > 512 || len(p.ClaimPath) == 0 || len(p.ClaimPath) > 8 {
		return fmt.Errorf("invalid wallet identity profile")
	}
	if p.Format == "mso_mdoc" && len(p.ClaimPath) != 2 {
		return fmt.Errorf("mdoc identity requires a namespace and element path")
	}
	for _, part := range p.ClaimPath {
		if part == "" || len(part) > 128 || strings.ContainsRune(part, 0) {
			return fmt.Errorf("invalid identity claim path")
		}
		switch strings.ToLower(part) {
		case "email", "email_address", "name", "given_name", "family_name", "first_name", "last_name", "full_name", "birthdate", "birth_date":
			return fmt.Errorf("mutable/demographic fields cannot link wallet accounts")
		}
	}
	return nil
}

func WalletIdentityProfiles(settings map[string]interface{}) ([]WalletIdentityProfile, error) {
	value, ok := settings["wallet_identity_profiles"]
	if !ok {
		return nil, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var profiles []WalletIdentityProfile
	if err := json.Unmarshal(b, &profiles); err != nil || len(profiles) > 100 {
		return nil, fmt.Errorf("invalid wallet identity profiles")
	}
	seen := map[string]bool{}
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		key, _ := json.Marshal([]string{p.Format, p.Issuer, p.CredentialType})
		if seen[string(key)] {
			return nil, fmt.Errorf("ambiguous wallet identity profiles")
		}
		seen[string(key)] = true
	}
	return profiles, nil
}

func (p WalletIdentityProfile) Identifier(claims map[string]any) (string, error) {
	var value any = claims
	for _, part := range p.ClaimPath {
		object, ok := value.(map[string]any)
		if !ok {
			return "", fmt.Errorf("identity claim is not disclosed")
		}
		value = object[part]
	}
	identifier, ok := value.(string)
	if !ok || strings.TrimSpace(identifier) == "" || len(identifier) > 1024 {
		return "", fmt.Errorf("stable identity claim must be a nonempty string")
	}
	return identifier, nil
}

// Digests avoid retaining the raw identifier. They remain sensitive personal
// references, not anonymized data or a replacement for database access controls.
func (p WalletIdentityProfile) Digest(orgID, identifier string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if orgID == "" || strings.TrimSpace(identifier) == "" || len(identifier) > 1024 {
		return nil, fmt.Errorf("invalid external identifier")
	}
	b, err := json.Marshal([]any{orgID, p.Format, p.Issuer, p.CredentialType, p.ClaimPath, identifier})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
