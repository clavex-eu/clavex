package oid4w

// Token Status List — IETF draft-ietf-oauth-status-list (also compatible with
// W3C StatusList2021).  This implementation follows the JWT-based encoding:
//
//   GET /:slug/oid4vci/status-list/:id
//   → application/statuslist+jwt  (RFC 9457-style JWT VC)
//
// Each status list is a bitstring encoded as a zlib-compressed byte array,
// then base64url-encoded.  Each credential occupies 1 bit:
//   0 = VALID
//   1 = REVOKED
//
// References:
//   https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.txt
//   https://w3c.github.io/vc-status-list-2021/

import (
	"compress/zlib"
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
	StatusValid   byte = 0
	StatusRevoked byte = 1
)

// StatusList holds the in-memory bitstring for one list.
type StatusList struct {
	bits []byte // len = ceil(StatusListSize / 8)
}

// NewStatusList allocates an empty status list (all bits = 0 = VALID).
func NewStatusList() *StatusList {
	return &StatusList{bits: make([]byte, StatusListSize/8)}
}

// DecodeStatusList decompresses and decodes a base64url-encoded status list.
func DecodeStatusList(encoded string) (*StatusList, error) {
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
	bits, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("status list: zlib read: %w", err)
	}
	return &StatusList{bits: bits}, nil
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

// Get returns the status byte (0 or 1) at the given index.
func (sl *StatusList) Get(index int) (byte, error) {
	if index < 0 || index >= StatusListSize {
		return 0, fmt.Errorf("status list: index %d out of range [0, %d)", index, StatusListSize)
	}
	bytePos := index / 8
	bitPos := uint(index % 8)
	return (sl.bits[bytePos] >> bitPos) & 1, nil
}

// Set sets the status bit at index to val (0 or 1).
func (sl *StatusList) Set(index int, val byte) error {
	if index < 0 || index >= StatusListSize {
		return fmt.Errorf("status list: index %d out of range [0, %d)", index, StatusListSize)
	}
	if val > 1 {
		return fmt.Errorf("status list: val must be 0 or 1, got %d", val)
	}
	bytePos := index / 8
	bitPos := uint(index % 8)
	if val == 1 {
		sl.bits[bytePos] |= 1 << bitPos
	} else {
		sl.bits[bytePos] &^= 1 << bitPos
	}
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
	PrivateKey *rsa.PrivateKey
	KID        string
}

// IssueStatusListJWT signs the status list as a JWT.
// The resulting compact JWS should be served with
// Content-Type: application/statuslist+jwt.
func IssueStatusListJWT(p StatusListJWTParams) (string, error) {
	encoded, err := p.StatusList.Encode()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Issuer(p.Issuer).
		Subject(p.ListID.String()).
		IssuedAt(now).
		Expiration(now.Add(p.TTL)).
		Claim("status_list", map[string]any{
			"bits": 1,
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
	_ = hdrs.Set(jws.ContentTypeKey, "statuslist+jwt")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, p.PrivateKey, jws.WithProtectedHeaders(hdrs)))
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
//   listURI: absolute URL where the status list JWT is served,
//            e.g. "https://clavex.example.com/org/oid4vci/status-list/<uuid>"
//   index:   the credential's index within the list
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
	tok, err := jwt.Parse([]byte(statusListJWT),
		jwt.WithKey(jwa.RS256, pubKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return fmt.Errorf("status list: verify jwt: %w", err)
	}

	slRaw, ok := tok.Get("status_list")
	if !ok {
		return fmt.Errorf("status list: missing status_list claim")
	}
	slMap, ok := slRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("status list: status_list claim is not an object")
	}
	lstRaw, ok := slMap["lst"].(string)
	if !ok {
		return fmt.Errorf("status list: missing lst field")
	}

	sl, err := DecodeStatusList(lstRaw)
	if err != nil {
		return err
	}

	revoked, err := sl.IsRevoked(sc.StatusList.IDX)
	if err != nil {
		return err
	}
	if revoked {
		return ErrRevoked
	}
	return nil
}
