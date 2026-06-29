package federation

// trustmark.go — OpenID Federation 1.0 Trust Mark issuance (OIDF §8).
//
// Trust Marks are signed JWTs (typ: "trust-mark+jwt") issued by a recognised
// Trust Mark issuer (here: Clavex acting as TA). They attest that the subject
// entity satisfies a particular policy requirement, such as:
//
//   - eIDAS 2.0 Wallet Provider accreditation
//   - eIDAS 2.0 PID Provider accreditation
//   - EUDIW interoperability certification
//   - Consortium-specific role (e.g. "verified-member")
//
// Trust Mark JWT structure (OIDF §8.2):
//
//	{
//	  "iss": "<trust-mark-issuer-entity-id>",
//	  "sub": "<subject-entity-id>",
//	  "id":  "<trust-mark-id-uri>",
//	  "iat": <unix-ts>,
//	  "exp": <unix-ts>,
//	  "logo_uri": "...",   // optional
//	  "ref":      "...",   // optional — policy document URI
//	  "delegation": "..."  // optional — compact JWS if issuer ≠ TA
//	}

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// TrustMarkClaims is the payload of a trust-mark+jwt.
type TrustMarkClaims struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	TrustMarkID string `json:"id"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	LogoURI    string `json:"logo_uri,omitempty"`
	Ref        string `json:"ref,omitempty"`
}

// IssueTrustMark signs a Trust Mark JWT for the given subject.
//
//   - issuerEntityID — the TA's entity ID (goes in "iss")
//   - subject        — the entity receiving the trust mark (goes in "sub")
//   - trustMarkID    — the trust mark type URI (goes in "id")
//   - logoURI        — optional logo for this trust mark type
//   - ref            — optional policy document URI
//   - lifetime       — validity window (e.g. 365*24*time.Hour)
//   - signer         — signing key (PS256 recommended per eIDAS 2.0)
//   - alg            — signature algorithm
//   - kid            — key ID for the JWS header
//
// Returns a compact JWS (base64url.base64url.base64url).
func IssueTrustMark(
	issuerEntityID, subject, trustMarkID string,
	logoURI, ref string,
	lifetime time.Duration,
	signer crypto.Signer,
	alg jwa.SignatureAlgorithm,
	kid string,
) (string, time.Time, error) {
	if alg == "" {
		alg = jwa.PS256
	}

	now := time.Now()
	exp := now.Add(lifetime)

	claims := TrustMarkClaims{
		Issuer:      issuerEntityID,
		Subject:     subject,
		TrustMarkID: trustMarkID,
		IssuedAt:    now.Unix(),
		ExpiresAt:   exp.Unix(),
		LogoURI:     logoURI,
		Ref:         ref,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("federation/trustmark: marshal claims: %w", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	// OIDF §8.2: the "typ" header MUST be "trust-mark+jwt".
	_ = hdrs.Set("typ", "trust-mark+jwt")

	signed, err := jws.Sign(payload, jws.WithKey(alg, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("federation/trustmark: sign: %w", err)
	}
	return string(signed), exp, nil
}
