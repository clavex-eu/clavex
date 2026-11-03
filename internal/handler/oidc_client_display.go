package handler

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/clavex-eu/clavex/internal/models"
)

// Client URLs are browser-facing metadata, never backend fetch targets.
func validClientDisplayURL(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > 2048 || strings.IndexFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && u.Opaque == ""
}

func validateClientDisplayMetadata(logo, policy, tos string) error {
	for _, field := range []struct{ name, value string }{{"logo_uri", logo}, {"policy_uri", policy}, {"tos_uri", tos}} {
		if !validClientDisplayURL(field.value) {
			return fmt.Errorf("%s must be an absolute HTTP(S) URL without credentials", field.name)
		}
	}
	return nil
}

// Raw strings stay subject to html/template's URL filtering and escaping.
func clientDisplayData(client *models.OIDCClient) (name, logo, policy, tos string) {
	if client == nil {
		return
	}
	name = client.Name
	if client.LogoURL != nil && validClientDisplayURL(*client.LogoURL) {
		logo = *client.LogoURL
	}
	if value, ok := client.Metadata["policy_uri"].(string); ok && validClientDisplayURL(value) {
		policy = value
	}
	if value, ok := client.Metadata["tos_uri"].(string); ok && validClientDisplayURL(value) {
		tos = value
	}
	return
}
