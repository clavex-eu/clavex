-- Per-org custom Universal Login HTML template.
-- When non-null, Clavex renders this instead of the built-in login.html.
-- The value is a Go html/template string; allowed variables mirror loginData:
--   {{.OrgName}}, {{.OrgSlug}}, {{.LogoURL}}, {{.ClientName}}, {{.ActionURL}},
--   {{.LoginSessionID}}, {{.Email}}, {{.Error}}, {{.Nonce}},
--   {{.PasskeyEnabled}}, {{.CaptchaEnabled}}, {{.CaptchaSiteKey}}, {{.CaptchaScriptURL}}
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS custom_login_html TEXT DEFAULT NULL;
