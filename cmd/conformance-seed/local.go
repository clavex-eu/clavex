package main

import "strings"

func init() {
	// Keep existing online registrations and add exact callbacks for new Final plans.
	for _, alias := range []string{"clavex-fapi-final-dpop", "clavex-fapi-final-mtls", "clavex-fapi-jarm-final"} {
		u := "https://www.certification.openid.net/test/a/" + alias
		conformanceRedirectURIs = append(conformanceRedirectURIs, u+"/callback", u+"/callback?dummy1=lorem&dummy2=ipsum")
		conformancePostLogoutURIs = append(conformancePostLogoutURIs, u+"/post_logout_redirect")
	}
	redirects := append([]string(nil), conformanceRedirectURIs...)
	for _, u := range redirects {
		conformanceRedirectURIs = append(conformanceRedirectURIs, strings.Replace(u, "https://www.certification.openid.net", "https://localhost.emobix.co.uk:8443", 1))
	}
	logouts := append([]string(nil), conformancePostLogoutURIs...)
	for _, u := range logouts {
		conformancePostLogoutURIs = append(conformancePostLogoutURIs, strings.Replace(u, "https://www.certification.openid.net", "https://localhost.emobix.co.uk:8443", 1))
	}
}
