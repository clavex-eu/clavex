package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Read only the explicit key-attestation signer configured for the test suite.
// Wallet client-authentication keys and credential issuer CAs are separate trust.
func conformanceAttesters(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var plan struct {
		VCI struct {
			Issuer string          `json:"client_attestation_issuer"`
			Keys   json.RawMessage `json:"key_attestation_jwks"`
		} `json:"vci"`
	}
	if err = json.Unmarshal(raw, &plan); err != nil {
		return nil, err
	}
	if plan.VCI.Issuer == "" {
		return nil, fmt.Errorf("missing conformance attestation issuer")
	}
	keys, err := jwk.Parse(plan.VCI.Keys)
	if err != nil {
		return nil, err
	}
	if keys.Len() == 0 {
		return nil, fmt.Errorf("missing conformance key-attestation keys")
	}
	public, err := jwk.PublicSetOf(keys)
	if err != nil {
		return nil, err
	}
	return json.Marshal([]map[string]any{{"issuer": plan.VCI.Issuer, "jwks": public}})
}
