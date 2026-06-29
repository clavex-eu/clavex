// Package middleware defines the canonical admin-console permission tokens.
//
// Permission format: "<resource>:<action>" where action is "read" or "write".
// Write permission always implies read (i.e. a "write" holder can also call
// GET/HEAD endpoints for that resource). Superadmins and legacy org admins
// (users with no admin_role_assignments) bypass all permission checks.
//
// Resource → permission tokens mapping:
//
//	users              → users:read, users:write
//	roles              → roles:read, roles:write
//	groups             → groups:read, groups:write
//	clients            → clients:read, clients:write   (OIDC apps, scopes, mappers)
//	identity_providers → identity_providers:read, identity_providers:write
//	security           → security:read, security:write (MFA, password policy,
//	                     WebAuthn, CAPTCHA, IP allowlist, auth policies, rate limits)
//	audit              → audit:read, audit:write       (log viewer, sinks, proofs)
//	sessions           → sessions:read, sessions:write
//	branding           → branding:read, branding:write (org + client branding,
//	                     custom login template, enrichment hook)
//	smtp               → smtp:read, smtp:write
//	webhooks           → webhooks:read, webhooks:write
//	compliance         → compliance:read, compliance:write (GDPR, NIS2, DSAR)
//	delegated_admins   → delegated_admins:read, delegated_admins:write
package middleware

const (
	PermUsersRead     = "users:read"
	PermUsersWrite    = "users:write"
	PermRolesRead     = "roles:read"
	PermRolesWrite    = "roles:write"
	PermGroupsRead    = "groups:read"
	PermGroupsWrite   = "groups:write"
	PermClientsRead   = "clients:read"
	PermClientsWrite  = "clients:write"
	PermIDPRead       = "identity_providers:read"
	PermIDPWrite      = "identity_providers:write"
	PermSecurityRead  = "security:read"
	PermSecurityWrite = "security:write"
	PermAuditRead     = "audit:read"
	PermAuditWrite    = "audit:write"
	PermSessionsRead  = "sessions:read"
	PermSessionsWrite = "sessions:write"
	PermBrandingRead  = "branding:read"
	PermBrandingWrite = "branding:write"
	PermSMTPRead      = "smtp:read"
	PermSMTPWrite     = "smtp:write"
	PermSMSRead       = "sms:read"
	PermSMSWrite      = "sms:write"
	PermWebhooksRead  = "webhooks:read"
	PermWebhooksWrite = "webhooks:write"
	PermComplianceRead  = "compliance:read"
	PermComplianceWrite = "compliance:write"
	PermDelegatedRead   = "delegated_admins:read"
	PermDelegatedWrite  = "delegated_admins:write"
)

// AllPermissions lists every valid permission token, used by the
// GET /api/v1/admin-roles/permissions endpoint.
var AllPermissions = []PermissionInfo{
	{Token: PermUsersRead, Resource: "users", Action: "read", Description: "View users, login history, anomaly signals, and risk scores."},
	{Token: PermUsersWrite, Resource: "users", Action: "write", Description: "Create, update, and delete users; reset passwords; bulk import; impersonate."},
	{Token: PermRolesRead, Resource: "roles", Action: "read", Description: "List org roles and their members."},
	{Token: PermRolesWrite, Resource: "roles", Action: "write", Description: "Create and delete roles; assign and unassign roles from users."},
	{Token: PermGroupsRead, Resource: "groups", Action: "read", Description: "List groups and their members."},
	{Token: PermGroupsWrite, Resource: "groups", Action: "write", Description: "Create and delete groups; manage group membership and group roles."},
	{Token: PermClientsRead, Resource: "clients", Action: "read", Description: "List OIDC clients, scopes, and protocol mappers."},
	{Token: PermClientsWrite, Resource: "clients", Action: "write", Description: "Create, update, and delete OIDC clients; rotate secrets; manage scopes and mappers."},
	{Token: PermIDPRead, Resource: "identity_providers", Action: "read", Description: "List identity providers, LDAP connections, SAML SPs, SCIM push configs."},
	{Token: PermIDPWrite, Resource: "identity_providers", Action: "write", Description: "Create, update, and delete identity providers, LDAP connections, SAML SPs, SCIM push configs."},
	{Token: PermSecurityRead, Resource: "security", Action: "read", Description: "Read password policy, WebAuthn policy, CAPTCHA config, IP allowlist, auth policies."},
	{Token: PermSecurityWrite, Resource: "security", Action: "write", Description: "Update password policy, WebAuthn policy, CAPTCHA config, IP allowlist, auth policies."},
	{Token: PermAuditRead, Resource: "audit", Action: "read", Description: "View audit logs, proofs, and usage analytics."},
	{Token: PermAuditWrite, Resource: "audit", Action: "write", Description: "Manage audit sinks, update retention, seal Merkle proofs."},
	{Token: PermSessionsRead, Resource: "sessions", Action: "read", Description: "List active org and user sessions; view trusted devices."},
	{Token: PermSessionsWrite, Resource: "sessions", Action: "write", Description: "Revoke sessions and trusted devices."},
	{Token: PermBrandingRead, Resource: "branding", Action: "read", Description: "Read org and client branding, custom login template, enrichment hook config."},
	{Token: PermBrandingWrite, Resource: "branding", Action: "write", Description: "Update branding, custom login template, and enrichment hook."},
	{Token: PermSMTPRead, Resource: "smtp", Action: "read", Description: "Read SMTP server configuration."},
	{Token: PermSMTPWrite, Resource: "smtp", Action: "write", Description: "Update SMTP server configuration; send test emails."},
	{Token: PermSMSRead, Resource: "sms", Action: "read", Description: "Read SMS gateway provider configuration."},
	{Token: PermSMSWrite, Resource: "sms", Action: "write", Description: "Update SMS gateway provider configuration; send test messages."},
	{Token: PermWebhooksRead, Resource: "webhooks", Action: "read", Description: "List webhooks and delivery history."},
	{Token: PermWebhooksWrite, Resource: "webhooks", Action: "write", Description: "Create, update, and delete webhooks; retry deliveries."},
	{Token: PermComplianceRead, Resource: "compliance", Action: "read", Description: "Read GDPR/NIS2 reports, DSAR data, and processing records."},
	{Token: PermComplianceWrite, Resource: "compliance", Action: "write", Description: "Execute GDPR erasure, manage processing records."},
	{Token: PermDelegatedRead, Resource: "delegated_admins", Action: "read", Description: "View delegated admin roles and their assignments."},
	{Token: PermDelegatedWrite, Resource: "delegated_admins", Action: "write", Description: "Create, update, delete delegated admin roles; assign and unassign them to users."},
}

// PermissionInfo describes a single permission token.
type PermissionInfo struct {
	Token       string `json:"token"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}
