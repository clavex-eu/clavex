package oid4w

import (
	"context"
	"encoding/json"
	"errors"
)

// StatusParent is retained only after attestation signature, issuer and holder
// binding validation. It contains the status pointer, not the attestation JWT,
// wallet identifier, patient attributes or holder key.
type StatusParent struct {
	Format string          `json:"format"`
	Issuer string          `json:"issuer"`
	Type   string          `json:"type"`
	Status json.RawMessage `json:"status"`
}

func ParseStatusParents(raw json.RawMessage) ([]StatusParent, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 256*1024 {
		return nil, ErrStatusUnavailable
	}
	var parents []StatusParent
	if json.Unmarshal(raw, &parents) != nil || len(parents) > 100 {
		return nil, ErrStatusUnavailable
	}
	for _, parent := range parents {
		if parent.Format != "key-attestation+jwt" && parent.Format != "wallet-attestation+jwt" {
			return nil, ErrStatusUnavailable
		}
		if parent.Issuer == "" || parent.Type == "" || len(parent.Status) == 0 {
			return nil, ErrStatusUnavailable
		}
	}
	return parents, nil
}
func CheckStatusParents(ctx context.Context, scope string, settings map[string]interface{}, raw json.RawMessage) error {
	parents, err := ParseStatusParents(raw)
	if err != nil {
		return err
	}
	var result error
	for _, parent := range parents {
		err := CheckDelegatedStatus(ctx, scope, settings, parent.Format, parent.Issuer, parent.Type, parent.Status, true)
		if errors.Is(err, ErrRevoked) {
			return ErrRevoked
		}
		if err != nil {
			if errors.Is(err, ErrSuspended) && result == nil {
				result = ErrSuspended
			} else if !errors.Is(err, ErrSuspended) {
				result = err
			}
		}
	}
	return result
}
