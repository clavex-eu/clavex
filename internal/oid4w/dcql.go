package oid4w

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
)

// This verifier currently supports one SD-JWT credential per DCQL response.
// Reject larger queries explicitly instead of silently selecting the first item.
type sdjwtDCQLQuery struct {
	Credentials    []sdjwtCredentialQuery `json:"credentials"`
	CredentialSets json.RawMessage        `json:"credential_sets"`
}

type sdjwtCredentialQuery struct {
	ID             string `json:"id"`
	Format         string `json:"format"`
	Multiple       bool   `json:"multiple"`
	RequireBinding *bool  `json:"require_cryptographic_holder_binding"`
	Meta           struct {
		VCTValues []string `json:"vct_values"`
	} `json:"meta"`
	Claims    []dcqlClaimQuery `json:"claims"`
	ClaimSets [][]string       `json:"claim_sets"`
}

type dcqlClaimQuery struct {
	ID   string `json:"id"`
	Path []any  `json:"path"`
	// values is a wallet-side privacy hint, not an authorization condition.
	// OID4VP Final 6.4.1 requires separate security decisions by the verifier.
}

var dcqlID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func parseSDJWTDCQL(query map[string]interface{}) (*sdjwtCredentialQuery, error) {
	b, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("dcql: encode query: %w", err)
	}
	var q sdjwtDCQLQuery
	if err := json.Unmarshal(b, &q); err != nil {
		return nil, fmt.Errorf("dcql: invalid query: %w", err)
	}
	if len(q.Credentials) != 1 || len(q.CredentialSets) != 0 {
		return nil, fmt.Errorf("dcql: this verifier requires one credential query without credential_sets")
	}
	c := &q.Credentials[0]
	if !dcqlID.MatchString(c.ID) || c.Format != "dc+sd-jwt" || c.Multiple {
		return nil, fmt.Errorf("dcql: expected a single dc+sd-jwt presentation with a valid query id")
	}
	if c.Claims != nil && len(c.Claims) == 0 {
		return nil, fmt.Errorf("dcql: claims must not be empty")
	}
	if c.ClaimSets != nil && len(c.ClaimSets) == 0 {
		return nil, fmt.Errorf("dcql: claim_sets must not be empty")
	}
	ids := map[string]bool{}
	paths := map[string]bool{}
	for _, claim := range c.Claims {
		if len(claim.Path) == 0 {
			return nil, fmt.Errorf("dcql: claim path is required")
		}
		for _, component := range claim.Path {
			switch v := component.(type) {
			case string, nil:
			case float64:
				if v < 0 || math.Trunc(v) != v {
					return nil, fmt.Errorf("dcql: invalid array index")
				}
			default:
				return nil, fmt.Errorf("dcql: invalid path component")
			}
		}
		path, _ := json.Marshal(claim.Path)
		if paths[string(path)] {
			return nil, fmt.Errorf("dcql: duplicate claim path")
		}
		paths[string(path)] = true
		if claim.ID != "" {
			if !dcqlID.MatchString(claim.ID) || ids[claim.ID] {
				return nil, fmt.Errorf("dcql: invalid or duplicate claim id")
			}
			ids[claim.ID] = true
		} else if c.ClaimSets != nil {
			return nil, fmt.Errorf("dcql: claim id required with claim_sets")
		}
	}
	for _, set := range c.ClaimSets {
		if len(set) == 0 {
			return nil, fmt.Errorf("dcql: empty claim set")
		}
		for _, id := range set {
			if !ids[id] {
				return nil, fmt.Errorf("dcql: unknown claim id %q", id)
			}
		}
	}
	return c, nil
}

// ExtractDCQLSDJWT validates the final response envelope before extracting the
// single supported presentation. An unrelated query ID must not be accepted.
func ExtractDCQLSDJWT(vpToken string, query map[string]interface{}) (string, error) {
	c, err := parseSDJWTDCQL(query)
	if err != nil {
		return "", err
	}
	var envelope map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &envelope); err != nil {
		return "", fmt.Errorf("dcql: invalid vp_token envelope: %w", err)
	}
	if len(envelope) != 1 || len(envelope[c.ID]) != 1 || envelope[c.ID][0] == "" {
		return "", fmt.Errorf("dcql: expected exactly one presentation for query %q", c.ID)
	}
	return envelope[c.ID][0], nil
}

func (q *sdjwtCredentialQuery) requiresBinding() bool {
	return q.RequireBinding == nil || *q.RequireBinding
}

func (q *sdjwtCredentialQuery) match(claims map[string]any) error {
	if len(q.Meta.VCTValues) > 0 {
		vct, _ := claims["vct"].(string)
		found := false
		for _, allowed := range q.Meta.VCTValues {
			found = found || vct == allowed
		}
		if !found {
			return fmt.Errorf("dcql: credential type does not match vct_values")
		}
	}
	present := map[string]bool{}
	all := true
	for _, claim := range q.Claims {
		ok := dcqlPathExists(claims, claim.Path)
		present[claim.ID] = ok
		all = all && ok
	}
	if q.ClaimSets == nil {
		if !all {
			return fmt.Errorf("dcql: required claim is missing")
		}
		return nil
	}
	for _, set := range q.ClaimSets {
		matched := true
		for _, id := range set {
			matched = matched && present[id]
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("dcql: no requested claim set is satisfied")
}

func dcqlPathExists(value any, path []any) bool {
	if len(path) == 0 {
		return true
	}
	switch component := path[0].(type) {
	case string:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		next, found := object[component]
		return found && dcqlPathExists(next, path[1:])
	case float64:
		array, ok := value.([]any)
		if !ok || component < 0 || component >= float64(len(array)) || math.Trunc(component) != component {
			return false
		}
		return dcqlPathExists(array[int(component)], path[1:])
	case nil:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range array {
			if dcqlPathExists(item, path[1:]) {
				return true
			}
		}
	}
	return false
}
