package connectorregistry

func ptr(s string) *string { return &s }

func init() {
	// ── Core social ───────────────────────────────────────────────────────────

	RegisterSocial(&SocialDef{
		ID:               "google",
		DisplayName:      "Google",
		Category:         "social",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		UserinfoURL:      ptr("https://openidconnect.googleapis.com/v1/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
	})

	RegisterSocial(&SocialDef{
		ID:               "github",
		DisplayName:      "GitHub",
		Category:         "social",
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserinfoURL:      ptr("https://api.github.com/user"),
		Scopes:           "read:user user:email",
		EmailClaim:       "email",
		FirstNameClaim:   "name",
		LastNameClaim:    "name",
		Notes:            "Clavex automatically calls /user/emails when the primary email is not public on the profile.",
	})

	RegisterSocial(&SocialDef{
		ID:               "gitlab",
		DisplayName:      "GitLab",
		Category:         "social",
		AuthorizationURL: "https://gitlab.com/oauth/authorize",
		TokenURL:         "https://gitlab.com/oauth/token",
		UserinfoURL:      ptr("https://gitlab.com/oauth/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
	})

	RegisterSocial(&SocialDef{
		ID:               "microsoft",
		DisplayName:      "Microsoft (Entra ID / personal)",
		Category:         "enterprise",
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserinfoURL:      ptr("https://graph.microsoft.com/oidc/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		Notes:            "For single-tenant apps replace 'common' with your tenant ID.",
	})

	RegisterSocial(&SocialDef{
		ID:               "apple",
		DisplayName:      "Apple",
		Category:         "social",
		AuthorizationURL: "https://appleid.apple.com/auth/authorize",
		TokenURL:         "https://appleid.apple.com/auth/token",
		UserinfoURL:      ptr("https://appleid.apple.com/auth/userinfo"),
		Scopes:           "name email",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "apple_team_id", Label: "Team ID", Type: "text", Required: true,
				Description: "Your 10-character Apple Developer Team ID."},
			{Key: "apple_key_id", Label: "Key ID", Type: "text", Required: true,
				Description: "The identifier of your Sign in with Apple private key."},
			{Key: "apple_private_key", Label: "Private Key (.p8)", Type: "textarea", Required: true,
				Description: "Paste the full contents of your .p8 file including the header and footer lines."},
		},
		Notes: "Clavex automatically generates the ES256 JWT client_secret on every token exchange — no manual renewal needed.",
	})

	RegisterSocial(&SocialDef{
		ID:               "linkedin",
		DisplayName:      "LinkedIn",
		Category:         "social",
		AuthorizationURL: "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:         "https://www.linkedin.com/oauth/v2/accessToken",
		UserinfoURL:      ptr("https://api.linkedin.com/v2/userinfo"),
		Scopes:           "openid profile email",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
	})

	// ── Extended social ───────────────────────────────────────────────────────

	RegisterSocial(&SocialDef{
		ID:               "facebook",
		DisplayName:      "Facebook",
		Category:         "social",
		AuthorizationURL: "https://www.facebook.com/v18.0/dialog/oauth",
		TokenURL:         "https://graph.facebook.com/v18.0/oauth/access_token",
		UserinfoURL:      ptr("https://graph.facebook.com/me?fields=id,name,email,first_name,last_name"),
		Scopes:           "email public_profile",
		EmailClaim:       "email",
		FirstNameClaim:   "first_name",
		LastNameClaim:    "last_name",
	})

	RegisterSocial(&SocialDef{
		ID:               "twitter",
		DisplayName:      "X (Twitter)",
		Category:         "social",
		AuthorizationURL: "https://twitter.com/i/oauth2/authorize",
		TokenURL:         "https://api.twitter.com/2/oauth2/token",
		UserinfoURL:      ptr("https://api.twitter.com/2/users/me?user.fields=name,username,profile_image_url"),
		Scopes:           "tweet.read users.read offline.access",
		EmailClaim:       "email",
		FirstNameClaim:   "name",
		LastNameClaim:    "name",
		Notes:            "X's basic OAuth2 tier does not provide an email address. Consider collecting email via the Clavex email-prompt step.",
	})

	RegisterSocial(&SocialDef{
		ID:               "discord",
		DisplayName:      "Discord",
		Category:         "social",
		AuthorizationURL: "https://discord.com/api/oauth2/authorize",
		TokenURL:         "https://discord.com/api/oauth2/token",
		UserinfoURL:      ptr("https://discord.com/api/users/@me"),
		Scopes:           "identify email",
		EmailClaim:       "email",
		FirstNameClaim:   "username",
		LastNameClaim:    "username",
	})

	RegisterSocial(&SocialDef{
		ID:               "slack",
		DisplayName:      "Slack",
		Category:         "social",
		AuthorizationURL: "https://slack.com/openid/connect/authorize",
		TokenURL:         "https://slack.com/api/openid.connect.token",
		UserinfoURL:      ptr("https://slack.com/api/openid.connect.userInfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
	})

	RegisterSocial(&SocialDef{
		ID:               "spotify",
		DisplayName:      "Spotify",
		Category:         "social",
		AuthorizationURL: "https://accounts.spotify.com/authorize",
		TokenURL:         "https://accounts.spotify.com/api/token",
		UserinfoURL:      ptr("https://api.spotify.com/v1/me"),
		Scopes:           "user-read-email user-read-private",
		EmailClaim:       "email",
		FirstNameClaim:   "display_name",
		LastNameClaim:    "display_name",
	})

	RegisterSocial(&SocialDef{
		ID:               "twitch",
		DisplayName:      "Twitch",
		Category:         "social",
		AuthorizationURL: "https://id.twitch.tv/oauth2/authorize",
		TokenURL:         "https://id.twitch.tv/oauth2/token",
		UserinfoURL:      ptr("https://id.twitch.tv/oauth2/userinfo"),
		Scopes:           "openid user:read:email",
		EmailClaim:       "email",
		FirstNameClaim:   "preferred_username",
		LastNameClaim:    "preferred_username",
	})

	RegisterSocial(&SocialDef{
		ID:               "bitbucket",
		DisplayName:      "Bitbucket",
		Category:         "social",
		AuthorizationURL: "https://bitbucket.org/site/oauth2/authorize",
		TokenURL:         "https://bitbucket.org/site/oauth2/access_token",
		UserinfoURL:      ptr("https://api.bitbucket.org/2.0/user"),
		Scopes:           "account email",
		EmailClaim:       "email",
		FirstNameClaim:   "display_name",
		LastNameClaim:    "display_name",
		Notes:            "Email is returned from /2.0/user/emails; Clavex fetches it automatically.",
	})

	RegisterSocial(&SocialDef{
		ID:               "notion",
		DisplayName:      "Notion",
		Category:         "social",
		AuthorizationURL: "https://api.notion.com/v1/oauth/authorize",
		TokenURL:         "https://api.notion.com/v1/oauth/token",
		Scopes:           "",
		EmailClaim:       "email",
		FirstNameClaim:   "name",
		LastNameClaim:    "name",
	})

	// ── Enterprise ────────────────────────────────────────────────────────────

	RegisterSocial(&SocialDef{
		ID:               "okta",
		DisplayName:      "Okta",
		Category:         "enterprise",
		AuthorizationURL: "https://{domain}/oauth2/default/v1/authorize",
		TokenURL:         "https://{domain}/oauth2/default/v1/token",
		UserinfoURL:      ptr("https://{domain}/oauth2/default/v1/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "domain", Label: "Okta Domain", Type: "text", Required: true,
				Placeholder: "your-org.okta.com",
				Description: "Your Okta domain without https:// prefix."},
		},
		Notes: "Replace {domain} in the endpoint URLs with your Okta domain (e.g. company.okta.com).",
	})

	RegisterSocial(&SocialDef{
		ID:               "salesforce",
		DisplayName:      "Salesforce",
		Category:         "enterprise",
		AuthorizationURL: "https://login.salesforce.com/services/oauth2/authorize",
		TokenURL:         "https://login.salesforce.com/services/oauth2/token",
		UserinfoURL:      ptr("https://login.salesforce.com/services/oauth2/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		Notes:            "Sandbox orgs use test.salesforce.com instead of login.salesforce.com.",
	})

	RegisterSocial(&SocialDef{
		ID:               "ping",
		DisplayName:      "Ping Identity",
		Category:         "enterprise",
		AuthorizationURL: "https://{environment_id}.auth.pingone.com/{environment_id}/as/authorize",
		TokenURL:         "https://{environment_id}.auth.pingone.com/{environment_id}/as/token",
		UserinfoURL:      ptr("https://{environment_id}.auth.pingone.com/{environment_id}/as/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "environment_id", Label: "PingOne Environment ID", Type: "text", Required: true,
				Description: "Found in the PingOne admin console under Environments."},
		},
	})

	RegisterSocial(&SocialDef{
		ID:               "aws_cognito",
		DisplayName:      "AWS Cognito",
		Category:         "enterprise",
		AuthorizationURL: "https://{user_pool_domain}.auth.{region}.amazoncognito.com/oauth2/authorize",
		TokenURL:         "https://{user_pool_domain}.auth.{region}.amazoncognito.com/oauth2/token",
		UserinfoURL:      ptr("https://{user_pool_domain}.auth.{region}.amazoncognito.com/oauth2/userInfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "user_pool_domain", Label: "User Pool Domain", Type: "text", Required: true,
				Description: "The domain prefix configured in your Cognito User Pool."},
			{Key: "region", Label: "AWS Region", Type: "text", Required: true,
				Placeholder: "eu-west-1"},
		},
	})

	RegisterSocial(&SocialDef{
		ID:               "auth0",
		DisplayName:      "Auth0",
		Category:         "enterprise",
		AuthorizationURL: "https://{domain}/authorize",
		TokenURL:         "https://{domain}/oauth/token",
		UserinfoURL:      ptr("https://{domain}/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "domain", Label: "Auth0 Domain", Type: "text", Required: true,
				Placeholder: "your-tenant.eu.auth0.com"},
		},
	})

	RegisterSocial(&SocialDef{
		ID:               "keycloak",
		DisplayName:      "Keycloak",
		Category:         "enterprise",
		AuthorizationURL: "https://{host}/realms/{realm}/protocol/openid-connect/auth",
		TokenURL:         "https://{host}/realms/{realm}/protocol/openid-connect/token",
		UserinfoURL:      ptr("https://{host}/realms/{realm}/protocol/openid-connect/userinfo"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
		ConfigSchema: []ConfigField{
			{Key: "host", Label: "Keycloak Host", Type: "url", Required: true,
				Placeholder: "https://keycloak.company.com"},
			{Key: "realm", Label: "Realm", Type: "text", Required: true,
				Placeholder: "master"},
		},
	})

	// ── Asian social providers ────────────────────────────────────────────────

	RegisterSocial(&SocialDef{
		ID:               "line",
		DisplayName:      "LINE",
		Category:         "social",
		AuthorizationURL: "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:         "https://api.line.me/oauth2/v2.1/token",
		UserinfoURL:      ptr("https://api.line.me/v2/profile"),
		Scopes:           "profile openid email",
		EmailClaim:       "email",
		FirstNameClaim:   "displayName",
		LastNameClaim:    "displayName",
	})

	RegisterSocial(&SocialDef{
		ID:               "kakao",
		DisplayName:      "Kakao",
		Category:         "social",
		AuthorizationURL: "https://kauth.kakao.com/oauth/authorize",
		TokenURL:         "https://kauth.kakao.com/oauth/token",
		UserinfoURL:      ptr("https://kapi.kakao.com/v2/user/me"),
		Scopes:           "profile_nickname profile_image account_email",
		EmailClaim:       "kakao_account.email",
		FirstNameClaim:   "properties.nickname",
		LastNameClaim:    "properties.nickname",
	})

	RegisterSocial(&SocialDef{
		ID:               "naver",
		DisplayName:      "Naver",
		Category:         "social",
		AuthorizationURL: "https://nid.naver.com/oauth2.0/authorize",
		TokenURL:         "https://nid.naver.com/oauth2.0/token",
		UserinfoURL:      ptr("https://openapi.naver.com/v1/nid/me"),
		Scopes:           "name email",
		EmailClaim:       "response.email",
		FirstNameClaim:   "response.name",
		LastNameClaim:    "response.name",
	})

	RegisterSocial(&SocialDef{
		ID:               "yahoo_japan",
		DisplayName:      "Yahoo! JAPAN",
		Category:         "social",
		AuthorizationURL: "https://auth.login.yahoo.co.jp/yconnect/v2/authorization",
		TokenURL:         "https://auth.login.yahoo.co.jp/yconnect/v2/token",
		UserinfoURL:      ptr("https://userinfo.yahooapis.jp/yconnect/v2/attribute"),
		Scopes:           "openid email profile",
		EmailClaim:       "email",
		FirstNameClaim:   "given_name",
		LastNameClaim:    "family_name",
	})
}
