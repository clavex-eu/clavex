package oid4w

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const MaxDCQLCredentials = 32
const MaxDCQLPresentations = 32

type DCQLCredential struct {
	ID       string
	Format   string
	Multiple bool
	// Single preserves the constraints for reuse by the per-format verifier.
	// It deliberately clears multiple and credential_sets for one instance only.
	Single map[string]interface{}
}
type DCQLCredentialSet struct {
	Options  [][]string `json:"options"`
	Required *bool      `json:"required"`
}
type DCQLQuery struct {
	Credentials []DCQLCredential
	Sets        []DCQLCredentialSet
}

func ParseDCQL(query map[string]interface{}) (*DCQLQuery, error) {
	raw, err := json.Marshal(query)
	if err != nil || len(raw) > 64*1024 {
		return nil, fmt.Errorf("dcql: query exceeds limits")
	}
	var wire struct {
		Credentials []map[string]json.RawMessage `json:"credentials"`
		Sets        json.RawMessage              `json:"credential_sets"`
	}
	if json.Unmarshal(raw, &wire) != nil || len(wire.Credentials) == 0 || len(wire.Credentials) > MaxDCQLCredentials {
		return nil, fmt.Errorf("dcql: invalid credential queries")
	}
	parsed := &DCQLQuery{}
	ids := map[string]bool{}
	for _, item := range wire.Credentials {
		var id, format string
		if json.Unmarshal(item["id"], &id) != nil || len(id) > 128 || !dcqlID.MatchString(id) || ids[id] || json.Unmarshal(item["format"], &format) != nil {
			return nil, fmt.Errorf("dcql: invalid or duplicate query id/format")
		}
		ids[id] = true
		var multiple bool
		if value, ok := item["multiple"]; ok {
			if string(value) == "null" || json.Unmarshal(value, &multiple) != nil {
				return nil, fmt.Errorf("dcql: multiple must be boolean")
			}
		}
		if value, ok := item["require_cryptographic_holder_binding"]; ok {
			var flag bool
			if string(value) == "null" || json.Unmarshal(value, &flag) != nil {
				return nil, fmt.Errorf("dcql: holder binding must be boolean")
			}
		}
		var meta map[string]json.RawMessage
		if json.Unmarshal(item["meta"], &meta) != nil || meta == nil {
			return nil, fmt.Errorf("dcql: meta must be an object")
		}
		if _, ok := item["trusted_authorities"]; ok {
			return nil, fmt.Errorf("dcql: trusted_authorities requires a configured framework-specific implementation")
		}
		if value, ok := item["claims"]; ok {
			var claims []json.RawMessage
			if string(value) == "null" || json.Unmarshal(value, &claims) != nil || len(claims) > 128 {
				return nil, fmt.Errorf("dcql: invalid claims or too many claims")
			}
		}
		var claimShapes []struct {
			Path []any `json:"path"`
		}
		if value, ok := item["claims"]; ok {
			if json.Unmarshal(value, &claimShapes) != nil {
				return nil, fmt.Errorf("dcql: invalid claim paths")
			}
			for _, claim := range claimShapes {
				if len(claim.Path) > 16 {
					return nil, fmt.Errorf("dcql: claim path too deep")
				}
			}
		}
		delete(item, "multiple")
		singleRaw, err := json.Marshal(map[string]any{"credentials": []any{item}})
		if err != nil {
			return nil, err
		}
		var single map[string]interface{}
		if json.Unmarshal(singleRaw, &single) != nil {
			return nil, fmt.Errorf("dcql: invalid credential query")
		}
		switch format {
		case "dc+sd-jwt":
			if _, err := parseSDJWTDCQL(single); err != nil {
				return nil, err
			}
		case "mso_mdoc":
			if _, err := ParseMDOCQuery(single); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("dcql: unsupported credential format")
		}
		parsed.Credentials = append(parsed.Credentials, DCQLCredential{ID: id, Format: format, Multiple: multiple, Single: single})
	}
	if len(wire.Sets) > 0 {
		if string(wire.Sets) == "null" || json.Unmarshal(wire.Sets, &parsed.Sets) != nil || len(parsed.Sets) == 0 || len(parsed.Sets) > 32 {
			return nil, fmt.Errorf("dcql: invalid credential sets")
		}
		// Validate required separately: JSON null cannot silently change its default.
		var rawSets []map[string]json.RawMessage
		_ = json.Unmarshal(wire.Sets, &rawSets)
		for i, set := range parsed.Sets {
			if value, ok := rawSets[i]["required"]; ok && string(value) == "null" {
				return nil, fmt.Errorf("dcql: required must be boolean")
			}
			if len(set.Options) == 0 || len(set.Options) > 32 {
				return nil, fmt.Errorf("dcql: invalid credential set options")
			}
			for _, option := range set.Options {
				if len(option) == 0 || len(option) > MaxDCQLCredentials {
					return nil, fmt.Errorf("dcql: invalid credential set option")
				}
				seen := map[string]bool{}
				for _, id := range option {
					if !ids[id] || seen[id] {
						return nil, fmt.Errorf("dcql: unknown/duplicate credential set id")
					}
					seen[id] = true
				}
			}
		}
	}
	return parsed, nil
}

// ParsePresentations validates the full envelope before any cryptographic work.
// Duplicate JSON object keys are rejected rather than overwritten by a map.
func (q *DCQLQuery) ParsePresentations(raw string) (map[string][]string, error) {
	if len(raw) > 4*1024*1024 {
		return nil, fmt.Errorf("dcql: presentation envelope exceeds limit")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("dcql: expected presentation object")
	}
	envelope := map[string][]string{}
	total := 0
	byID := map[string]DCQLCredential{}
	for _, credential := range q.Credentials {
		byID[credential.ID] = credential
	}
	for decoder.More() {
		token, err := decoder.Token()
		id, ok := token.(string)
		if err != nil || !ok {
			return nil, fmt.Errorf("dcql: invalid query id")
		}
		credential, known := byID[id]
		if !known {
			return nil, fmt.Errorf("dcql: unexpected query id")
		}
		if _, duplicate := envelope[id]; duplicate {
			return nil, fmt.Errorf("dcql: repeated query id")
		}
		var values []string
		if decoder.Decode(&values) != nil || len(values) == 0 || len(values) > 8 || !credential.Multiple && len(values) != 1 {
			return nil, fmt.Errorf("dcql: invalid presentation cardinality")
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || seen[value] {
				return nil, fmt.Errorf("dcql: empty/repeated credential instance")
			}
			seen[value] = true
		}
		envelope[id] = values
		total += len(values)
		if total > MaxDCQLPresentations {
			return nil, fmt.Errorf("dcql: too many presentations")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("dcql: invalid envelope")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("dcql: trailing JSON data")
	}
	if total == 0 {
		return nil, fmt.Errorf("dcql: no presentations")
	}
	if q.Sets == nil {
		for _, credential := range q.Credentials {
			if len(envelope[credential.ID]) == 0 {
				return nil, fmt.Errorf("dcql: missing required credential")
			}
		}
	} else {
		for _, set := range q.Sets {
			satisfied := false
			for _, option := range set.Options {
				complete := true
				for _, id := range option {
					present := len(envelope[id]) > 0
					complete = complete && present
				}
				satisfied = satisfied || complete
			}
			if !satisfied && (set.Required == nil || *set.Required) {
				return nil, fmt.Errorf("dcql: unsatisfied credential set")
			}
		}
	}
	return envelope, nil
}

// Each result retains its own issuer, claims, binding and status. Never infer
// that credentials belong to one account merely because a wallet grouped them.
type VerifiedDCQLCredential struct {
	QueryID  string
	Instance int
	Result   *VerificationResult
}

func ComposeDCQLResult(query *DCQLQuery, credentials []VerifiedDCQLCredential) (*VerificationResult, error) {
	if len(credentials) == 0 {
		return nil, fmt.Errorf("dcql: no verified credentials")
	}
	if len(query.Credentials) == 1 && len(credentials) == 1 {
		return credentials[0].Result, nil
	}
	result := &VerificationResult{Claims: map[string]any{}, Credentials: credentials}
	result.RefreshDCQLClaims()
	return result, nil
}
func (r *VerificationResult) RefreshDCQLClaims() {
	if len(r.Credentials) == 0 {
		return
	}
	entries := make([]map[string]any, 0, len(r.Credentials))
	for _, credential := range r.Credentials {
		child := credential.Result
		if child == nil || child.Identity == nil {
			continue
		}
		e := child.Identity
		entries = append(entries, map[string]any{"query_id": credential.QueryID, "instance": credential.Instance, "format": e.Format, "issuer": e.Issuer, "credential_type": e.CredentialType, "claims": child.Claims, "credential_status": child.StatusAssessment, "certificate_status": child.CertificateStatusAssessment})
	}
	r.Claims = map[string]any{"_clavex_presentations": entries}
}
