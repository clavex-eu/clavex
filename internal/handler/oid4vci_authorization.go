package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/oidc"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Explicit credential authorization is required; an ordinary OIDC token does
// not grant issuance. RAR grants take precedence over credential scopes.
func credentialConfigurationAuthorized(token jwt.Token, configID, issuer string) bool {
	if raw, ok := token.Get("authorization_details"); ok {
		b, err := json.Marshal(raw)
		if err != nil {
			return false
		}
		var entries []struct {
			Type            string          `json:"type"`
			ConfigurationID string          `json:"credential_configuration_id"`
			Locations       []string        `json:"locations"`
			Identifiers     json.RawMessage `json:"credential_identifiers"`
		}
		if err := json.Unmarshal(b, &entries); err != nil {
			return false
		}
		hasCredentialGrants := false
		for _, entry := range entries {
			if entry.Type != "openid_credential" {
				continue
			}
			hasCredentialGrants = true
			if entry.ConfigurationID != configID || len(entry.Identifiers) > 0 {
				continue
			}
			if len(entry.Locations) > 0 {
				matches := false
				for _, location := range entry.Locations {
					matches = matches || location == issuer
				}
				if !matches {
					continue
				}
			}
			return true
		}
		if hasCredentialGrants {
			return false
		}
	}
	scope, ok := token.Get("scope")
	if !ok {
		return false
	}
	value, ok := scope.(string)
	if !ok {
		return false
	}
	for _, grant := range strings.Fields(value) {
		if grant == configID {
			return true
		}
	}
	return false
}

func offerConfigurationMatches(requested, offered string) bool {
	return requested == "" || requested == offered || requested == oid4w.CredentialConfigID(offered)
}

// Certificate bindings are proven by the actual TLS connection, never by
// arbitrary forwarded certificate headers. DPoP possession is checked by the
// credential handler immediately after this check.
func credentialAccessTokenValid(token jwt.Token, request *http.Request, now time.Time) bool {
	iat, exp := token.IssuedAt(), token.Expiration()
	if iat.IsZero() || exp.IsZero() || !exp.After(iat) || iat.After(now.Add(time.Minute)) {
		return false
	}
	_, dpopBound := oidc.JKTFromCNF(token)
	thumbprint, mtlsBound := oidc.ThumbprintFromCNF(token)
	if mtlsBound {
		certificate := oidc.CertFromConnectionState(request.TLS)
		if certificate == nil || certificate.X5TS256 != thumbprint {
			return false
		}
	}
	if _, hasCNF := token.Get("cnf"); hasCNF && !dpopBound && !mtlsBound {
		return false
	}
	return dpopBound || mtlsBound || exp.Sub(iat) <= 5*time.Minute
}
