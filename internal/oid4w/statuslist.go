package oid4w

// JWT Token Status List profile, pinned to draft-ietf-oauth-status-list-21.
// Local issuance uses binary states; the strict validator also reads 2/4/8-bit
// external lists. This is not W3C StatusList2021 or an RFC 9457 document.

import (
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// StatusListSize is the default capacity (number of credential slots).
// A 1-bit-per-credential list of 65536 entries fits in ~8 KB uncompressed
// and typically <100 bytes compressed.
const StatusListSize = 65536

// credentialStatus values
const (
	StatusValid     byte = 0
	StatusRevoked   byte = 1
	StatusSuspended byte = 2
)

// StatusList holds the in-memory bitstring for one list.
type StatusList struct {
	bits  []byte
	width int
}

// NewStatusList allocates an empty status list (all bits = 0 = VALID).
func NewStatusList() *StatusList {
	return NewStatusListWithBits(1)
}

// NewStatusListWithBits supports the JWT status-list widths without changing
// the number of slots. Existing one-bit lists remain readable.
func NewStatusListWithBits(width int) *StatusList {
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return nil
	}
	return &StatusList{bits: make([]byte, StatusListSize*width/8), width: width}
}
func (sl *StatusList) Bits() int { return sl.width }

// DecodeStatusList decompresses and decodes a base64url-encoded status list.
func DecodeStatusList(encoded string) (*StatusList, error) {
	return DecodeStatusListWithBits(encoded, 1)
}
func DecodeStatusListWithBits(encoded string, width int) (*StatusList, error) {
	if NewStatusListWithBits(width) == nil {
		return nil, fmt.Errorf("unsupported local status width")
	}
	if len(encoded) > 128*1024 {
		return nil, fmt.Errorf("local status list exceeds size limit")
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Try standard base64 as well (some issuers use padding)
		compressed, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("status list: base64 decode: %w", err)
		}
	}
	r, err := zlib.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		return nil, fmt.Errorf("status list: zlib open: %w", err)
	}
	defer r.Close()
	bits, err := io.ReadAll(io.LimitReader(r, int64(StatusListSize*width/8+1)))
	if err != nil {
		return nil, fmt.Errorf("status list: zlib read: %w", err)
	}
	if len(bits) != StatusListSize*width/8 {
		return nil, fmt.Errorf("status list: invalid local list size")
	}
	return &StatusList{bits: bits, width: width}, nil
}

// Encode compresses the bitstring and returns a base64url string suitable
// for embedding in a JWT status_list claim.
func (sl *StatusList) Encode() (string, error) {
	var buf strings.Builder
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(sl.bits); err != nil {
		return "", fmt.Errorf("status list: zlib write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("status list: zlib close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(buf.String())), nil
}

// Get returns the status value at index.
func (sl *StatusList) Get(index int) (byte, error) {
	if sl.width < 1 || index < 0 || index >= StatusListSize || index*sl.width/8 >= len(sl.bits) {
		return 0, fmt.Errorf("status list index out of range")
	}
	return (sl.bits[index*sl.width/8] >> uint(index*sl.width%8)) & byte((1<<sl.width)-1), nil
}

// Set updates one status value without changing neighbouring entries.
func (sl *StatusList) Set(index int, val byte) error {
	if _, err := sl.Get(index); err != nil {
		return err
	}
	mask := byte((1 << sl.width) - 1)
	if int(val) > int(mask) {
		return fmt.Errorf("status does not fit list width")
	}
	pos, shift := index*sl.width/8, uint(index*sl.width%8)
	sl.bits[pos] = (sl.bits[pos] & ^(mask << shift)) | (val << shift)
	return nil
}

// Revoke marks the credential at index as revoked.
func (sl *StatusList) Revoke(index int) error { return sl.Set(index, StatusRevoked) }

// Restore marks the credential at index as valid again (un-revoke).
func (sl *StatusList) Restore(index int) error { return sl.Set(index, StatusValid) }

// IsRevoked returns true if the credential at index has been revoked.
func (sl *StatusList) IsRevoked(index int) (bool, error) {
	v, err := sl.Get(index)
	return v == StatusRevoked, err
}

// ── JWT Status List Token ─────────────────────────────────────────────────────

// StatusListJWTParams are the parameters for signing a status list JWT.
type StatusListJWTParams struct {
	Issuer     string
	ListID     uuid.UUID // becomes the "sub" / URL path of the list
	StatusList *StatusList
	TTL        time.Duration
	ListURI    string
	Signer     crypto.Signer
	Algorithm  jwa.SignatureAlgorithm
	PrivateKey *rsa.PrivateKey
	KID        string
}

// IssueStatusListJWT signs the status list as a JWT.
// The resulting compact JWS should be served with
// Content-Type: application/statuslist+jwt.
func IssueStatusListJWT(p StatusListJWTParams) (string, error) {
	if p.StatusList == nil {
		return "", fmt.Errorf("status list is required")
	}
	if p.TTL <= 0 {
		return "", fmt.Errorf("positive status token lifetime is required")
	}
	if p.ListURI == "" {
		p.ListURI = strings.TrimRight(p.Issuer, "/") + "/oid4vci/status-list/" + p.ListID.String()
	}
	if _, err := ParseStatusClaim([]byte(fmt.Sprintf(`{"status_list":{"idx":0,"uri":%q}}`, p.ListURI))); err != nil {
		return "", err
	}
	signer := p.Signer
	if signer == nil {
		if p.PrivateKey == nil {
			return "", fmt.Errorf("status signer is required")
		}
		signer = p.PrivateKey
	}
	alg := p.Algorithm
	if alg == "" {
		alg = jwa.RS256
	}
	if alg != jwa.RS256 && alg != jwa.PS256 && alg != jwa.ES256 {
		return "", fmt.Errorf("unsupported status signing algorithm")
	}
	encoded, err := p.StatusList.Encode()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Issuer(p.Issuer).
		Subject(p.ListURI).
		IssuedAt(now).
		Expiration(now.Add(p.TTL)).
		Claim("ttl", 60).
		Claim("status_list", map[string]any{
			"bits": p.StatusList.Bits(),
			"lst":  encoded,
		}).
		Build()
	if err != nil {
		return "", fmt.Errorf("status list jwt: build: %w", err)
	}

	hdrs := jws.NewHeaders()
	if p.KID != "" {
		_ = hdrs.Set(jws.KeyIDKey, p.KID)
	}
	// typ = statuslist+jwt per the IETF draft
	_ = hdrs.Set(jws.TypeKey, "statuslist+jwt")

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, signer, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("status list jwt: sign: %w", err)
	}
	return string(signed), nil
}

// ── Status claim builder (embedded in VC) ────────────────────────────────────

// StatusClaim is the value embedded in an SD-JWT as the "status" claim
// (draft-ietf-oauth-status-list §5).
type StatusClaim struct {
	StatusList StatusRef `json:"status_list"`
}

// StatusRef points to a position in a remote status list.
type StatusRef struct {
	IDX int    `json:"idx"`
	URI string `json:"uri"`
}

// BuildStatusClaim constructs the status claim for embedding in an SD-JWT VC.
//
//	listURI: absolute URL where the status list JWT is served,
//	         e.g. "https://clavex.example.com/org/oid4vci/status-list/<uuid>"
//	index:   the credential's index within the list
func BuildStatusClaim(listURI string, index int) StatusClaim {
	return StatusClaim{
		StatusList: StatusRef{
			IDX: index,
			URI: listURI,
		},
	}
}

// ── Verifier helper ───────────────────────────────────────────────────────────

// ErrRevoked is returned when a credential's status bit is set to REVOKED.
var ErrRevoked = errors.New("credential revoked")

// CheckStatus verifies the status of a credential given the encoded status
// list JWT and the credential's status claim.
//
// This is a local check (no network call). The caller is responsible for
// fetching and passing the correct statusListJWT for the given URI.
func CheckStatus(statusListJWT string, sc StatusClaim, pubKey *rsa.PublicKey) error {
	list, err := ValidateStatusListToken(statusListJWT, sc, "", pubKey, time.Now(), 5*time.Minute)
	if err != nil {
		return err
	}
	return list.Check(sc.StatusList.IDX)
}
