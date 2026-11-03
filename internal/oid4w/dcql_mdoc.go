package oid4w

import (
	"encoding/json"
	"fmt"
)

// MDOCQuery is the supported single-document DCQL profile. Unsupported query
// shapes fail explicitly instead of silently selecting an arbitrary document.
type MDOCQuery struct {
	ID             string `json:"id"`
	Format         string `json:"format"`
	Multiple       bool   `json:"multiple"`
	RequireBinding *bool  `json:"require_cryptographic_holder_binding"`
	Meta           struct {
		DocType string `json:"doctype_value"`
	} `json:"meta"`
	Claims    []dcqlClaimQuery `json:"claims"`
	ClaimSets [][]string       `json:"claim_sets"`
}

func ParseMDOCQuery(query map[string]interface{}) (*MDOCQuery, error) {
	var q struct {
		Credentials []MDOCQuery     `json:"credentials"`
		Sets        json.RawMessage `json:"credential_sets"`
	}
	b, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &q); err != nil {
		return nil, err
	}
	if len(q.Credentials) != 1 || len(q.Sets) > 0 {
		return nil, fmt.Errorf("mdoc DCQL requires one credential query without credential_sets")
	}
	c := &q.Credentials[0]
	if !dcqlID.MatchString(c.ID) || c.Format != "mso_mdoc" || c.Multiple || c.Meta.DocType == "" || (c.RequireBinding != nil && !*c.RequireBinding) {
		return nil, fmt.Errorf("unsupported mdoc DCQL query")
	}
	// Reuse claim-set/identifier validation while retaining mdoc's two-string paths.
	for _, claim := range c.Claims {
		if len(claim.Path) != 2 {
			return nil, fmt.Errorf("mdoc claim paths require namespace and element identifier")
		}
		for _, v := range claim.Path {
			if s, ok := v.(string); !ok || s == "" {
				return nil, fmt.Errorf("mdoc claim paths must contain non-empty strings")
			}
		}
	}
	check := map[string]interface{}{"credentials": []any{map[string]any{"id": c.ID, "format": "dc+sd-jwt", "claims": c.Claims}}}
	if c.Claims == nil {
		delete(check["credentials"].([]any)[0].(map[string]any), "claims")
	}
	if c.ClaimSets != nil {
		check["credentials"].([]any)[0].(map[string]any)["claim_sets"] = c.ClaimSets
	}
	if _, err := parseSDJWTDCQL(check); err != nil {
		return nil, err
	}
	return c, nil
}

func (q *MDOCQuery) Extract(vpToken string) (string, error) {
	var envelope map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &envelope); err != nil {
		return "", err
	}
	if len(envelope) != 1 || len(envelope[q.ID]) != 1 || envelope[q.ID][0] == "" {
		return "", fmt.Errorf("mdoc DCQL requires exactly one presentation for %q", q.ID)
	}
	return envelope[q.ID][0], nil
}

func (q *MDOCQuery) Match(docType string, attrs map[string]map[string]any) error {
	if docType != q.Meta.DocType {
		return fmt.Errorf("mdoc doctype does not match query")
	}
	claims := make(map[string]any, len(attrs))
	for ns, v := range attrs {
		claims[ns] = v
	}
	return (&sdjwtCredentialQuery{Claims: q.Claims, ClaimSets: q.ClaimSets}).match(claims)
}
