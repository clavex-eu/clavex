package oid4w

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var ErrSuspended = errors.New("credential suspended")
var ErrUnknownStatus = errors.New("credential status is unknown")

// Only this mechanism is supported by this profile. Nulls, missing indices and
// ambiguous extra mechanisms cannot silently turn into an active slot zero.
func ParseStatusClaim(raw []byte) (StatusClaim, error) {
	var mechanisms map[string]json.RawMessage
	if err := json.Unmarshal(raw, &mechanisms); err != nil || len(mechanisms) != 1 {
		return StatusClaim{}, ErrUnknownStatus
	}
	value, ok := mechanisms["status_list"]
	if !ok {
		return StatusClaim{}, ErrUnknownStatus
	}
	var ref struct {
		IDX *int    `json:"idx"`
		URI *string `json:"uri"`
	}
	if err := json.Unmarshal(value, &ref); err != nil || ref.IDX == nil || *ref.IDX < 0 || *ref.IDX > 2147483647 || ref.URI == nil || len(*ref.URI) > 2048 {
		return StatusClaim{}, ErrUnknownStatus
	}
	u, err := url.Parse(*ref.URI)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return StatusClaim{}, ErrUnknownStatus
	}
	return BuildStatusClaim(*ref.URI, *ref.IDX), nil
}

type ValidatedStatusList struct {
	bits       int
	data       []byte
	FreshUntil time.Time
}

func (s *ValidatedStatusList) Check(index int) error {
	if s == nil || (s.bits != 1 && s.bits != 2 && s.bits != 4 && s.bits != 8) {
		return ErrUnknownStatus
	}
	if index < 0 || index >= len(s.data)*(8/s.bits) {
		return ErrUnknownStatus
	}
	value := (s.data[index/(8/s.bits)] >> uint((index%(8/s.bits))*s.bits)) & byte((1<<s.bits)-1)
	switch value {
	case 0:
		return nil
	case 1:
		return ErrRevoked
	case 2:
		return ErrSuspended
	default:
		return ErrUnknownStatus
	}
}

// No discovery or network request occurs here. The caller must supply an
// authorized status signer, not a key from JWT headers or an untrusted URL.
// FreshUntil is the conservative policy bound for any future caching layer.
type StatusValidationPolicy struct {
	RequireIssuerClaim bool
	RequireExpiration  bool
}

func ValidateStatusListToken(raw string, ref StatusClaim, issuer string, key crypto.PublicKey, now time.Time, maxAge time.Duration, policies ...StatusValidationPolicy) (*ValidatedStatusList, error) {
	if len(raw) > 512*1024 || key == nil || (reflect.ValueOf(key).Kind() == reflect.Pointer && reflect.ValueOf(key).IsNil()) || maxAge <= 0 || maxAge > 24*time.Hour {
		return nil, ErrUnknownStatus
	}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return nil, ErrUnknownStatus
	}
	if _, err := ParseStatusClaim(refJSON); err != nil {
		return nil, err
	}
	message, err := jws.Parse([]byte(raw))
	if err != nil || len(message.Signatures()) != 1 {
		return nil, ErrUnknownStatus
	}
	head := message.Signatures()[0].ProtectedHeaders()
	if head.Type() != "statuslist+jwt" || len(head.Critical()) > 0 {
		return nil, fmt.Errorf("status token type is invalid")
	}
	alg := head.Algorithm()
	if alg != jwa.RS256 && alg != jwa.PS256 && alg != jwa.ES256 {
		return nil, fmt.Errorf("unsupported status signature algorithm")
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKey(alg, key), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("status signature is invalid: %w", err)
	}
	policy := StatusValidationPolicy{}
	if len(policies) > 0 {
		policy = policies[0]
	}
	_, hasIssuer := token.Get("iss")
	if token.Subject() != ref.StatusList.URI || hasIssuer && (token.Issuer() == "" || issuer != "" && token.Issuer() != issuer) || policy.RequireIssuerClaim && !hasIssuer {
		return nil, fmt.Errorf("status token issuer or URI does not match")
	}
	iat, exp := token.IssuedAt(), token.Expiration()
	_, hasExpiration := token.Get("exp")
	if iat.IsZero() || iat.After(now.Add(30*time.Second)) || token.NotBefore().After(now) || hasExpiration && (exp.IsZero() || !exp.After(iat) || !now.Before(exp)) || policy.RequireExpiration && !hasExpiration {
		return nil, fmt.Errorf("invalid status token time window")
	}
	fresh := iat.Add(maxAge)
	if hasExpiration && exp.Before(fresh) {
		fresh = exp
	}
	if v, ok := token.Get("ttl"); ok {
		encoded, e := json.Marshal(v)
		if e != nil {
			return nil, ErrUnknownStatus
		}
		var seconds float64
		if json.Unmarshal(encoded, &seconds) != nil || seconds <= 0 || seconds > 86400 {
			return nil, fmt.Errorf("invalid status token ttl")
		}
		deadline := iat.Add(time.Duration(seconds * float64(time.Second)))
		if deadline.Before(fresh) {
			fresh = deadline
		}
	}
	if !now.Before(fresh) {
		return nil, fmt.Errorf("status token is stale")
	}
	v, ok := token.Get("status_list")
	if !ok {
		return nil, ErrUnknownStatus
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, ErrUnknownStatus
	}
	var body struct {
		Bits *int    `json:"bits"`
		Lst  *string `json:"lst"`
	}
	if err := json.Unmarshal(encoded, &body); err != nil || body.Bits == nil || body.Lst == nil {
		return nil, ErrUnknownStatus
	}
	width := *body.Bits
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported status bit width")
	}
	if len(*body.Lst) > 192*1024 {
		return nil, fmt.Errorf("compressed status list exceeds limit")
	}
	compressed, err := base64.RawURLEncoding.DecodeString(*body.Lst)
	if err != nil {
		return nil, fmt.Errorf("invalid status list encoding")
	}
	input := bytes.NewReader(compressed)
	reader, err := zlib.NewReader(input)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil || len(data) == 0 || len(data) > 1024*1024 || input.Len() != 0 {
		return nil, fmt.Errorf("invalid or oversized decompressed status list")
	}
	list := &ValidatedStatusList{bits: width, data: data, FreshUntil: fresh}
	if ref.StatusList.IDX >= len(data)*(8/width) {
		return nil, ErrUnknownStatus
	}
	return list, nil
}
