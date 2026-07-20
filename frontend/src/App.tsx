import { Component, type ReactNode, type ErrorInfo } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { useAuthStore } from '@/stores/auth'

// Zustand v5 + localStorage is fully synchronous — the store is already
// hydrated before any component renders. No useHydration() needed.

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null }
  static getDerivedStateFromError(error: Error) { return { error } }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 32, fontFamily: 'monospace' }}>
          <h2 style={{ color: '#dc2626' }}>Something went wrong</h2>
          <pre style={{ marginTop: 8, fontSize: 12, color: '#555' }}>{String(this.state.error)}</pre>
        </div>
      )
    }
    return this.props.children
  }
}

import LoginPage from '@/pages/Login'
import ComparisonPage from '@/components/ComparisonPage'
import PricingPage from '@/pages/Pricing'
import MarketplacePage from '@/pages/Marketplace'

// Superadmin
import SuperAdminLayout from '@/layouts/SuperAdminLayout'
import SuperadminSigningKeysPage from '@/pages/superadmin/SigningKeys'
import OrgsPage from '@/pages/superadmin/Orgs'
import OrgDetailPage from '@/pages/superadmin/OrgDetail'
import OrgUsersPage from '@/pages/superadmin/OrgUsers'
import OrgClientsPage from '@/pages/superadmin/OrgClients'
import OrgBrandingPage from '@/pages/superadmin/OrgBranding'
import OrgAuditPage from '@/pages/superadmin/OrgAudit'
import OrgRolesPage from '@/pages/superadmin/OrgRoles'
import OrgCaptchaPage from '@/pages/superadmin/OrgCaptcha'
import ProvisionOrgPage from '@/pages/superadmin/ProvisionOrg'
import HealthDashboardPage from '@/pages/superadmin/HealthDashboard'

// Tenant admin
import TenantLayout from '@/layouts/TenantLayout'
import TenantDashboard from '@/pages/tenant/Dashboard'
import TenantUsersPage from '@/pages/tenant/Users'
import TenantRolesPage from '@/pages/tenant/Roles'
import TenantGroupsPage from '@/pages/tenant/Groups'
import TenantClientsPage from '@/pages/tenant/Clients'
import TenantClientScopesPage from '@/pages/tenant/ClientScopes'
import TenantBrandingPage from '@/pages/tenant/Branding'
import TenantCaptchaPage from '@/pages/tenant/Captcha'
import TenantAuditPage from '@/pages/tenant/Audit'
import TenantLdapPage from '@/pages/tenant/Ldap'
import TenantSessionsPage from '@/pages/tenant/Sessions'
import TenantWebhooksPage from '@/pages/tenant/Webhooks'
import TenantScimPushPage from '@/pages/tenant/ScimPush'
import TenantSettingsPage from '@/pages/tenant/Settings'
import TenantIdentityProvidersPage from '@/pages/tenant/IdentityProviders'
import CredentialStatusPage from '@/pages/tenant/CredentialStatus'
import RiskDashboardPage from '@/pages/tenant/RiskDashboard'
import ShieldDashboardPage from '@/pages/tenant/ShieldDashboard'
import VerifiedCredentialsPage from '@/pages/tenant/VerifiedCredentials'
import CredentialSchemaGeneratorPage from '@/pages/tenant/CredentialSchemaGenerator'
import CredentialAnalyticsPage from '@/pages/tenant/CredentialAnalytics'
import PolicySimulatePage from '@/pages/tenant/PolicySimulate'
import PolicyBatchSimulatePage from '@/pages/tenant/PolicyBatchSimulate'
import EidasPage from '@/pages/tenant/EidasPage'
import TenantGrantsPage from '@/pages/tenant/Grants'
import PolicyEditorPage from '@/pages/tenant/PolicyEditor'
import LoginIntelligencePage from '@/pages/tenant/LoginIntelligence'
import LockoutAdminPage from '@/pages/tenant/LockoutAdmin'
import StreamDevPage from '@/pages/tenant/StreamDev'
import SSFStreamsPage from '@/pages/tenant/SSFStreams'
import CAEMonitorPage from '@/pages/tenant/CAEMonitor'
import PasskeyPolicyPage from '@/pages/tenant/PasskeyPolicy'
import PasskeyExchangePage from '@/pages/tenant/PasskeyExchange'
import MDSCatalogPage from '@/pages/tenant/MDSCatalog'
import CredentialOffersPage from '@/pages/tenant/CredentialOffers'
import OnboardingWizardPage from '@/pages/tenant/OnboardingWizard'
import WalletVerifierPage from '@/pages/tenant/WalletVerifier'
import EidasRPMetadataPage from '@/pages/tenant/EidasRPMetadata'
import SCIMCompliancePage from '@/pages/tenant/SCIMCompliance'
import LifecycleRulesPage from '@/pages/tenant/LifecycleRules'
import AccessReviewsPage from '@/pages/tenant/AccessReviews'
import AIAssistantPage from '@/pages/tenant/AIAssistant'
import LoginFlowsPage from '@/pages/tenant/LoginFlows'
import IPRulesPage from '@/pages/tenant/IPRules'
import BreachedPasswordsPage from '@/pages/tenant/BreachedPasswords'
import ServiceAccountsPage from '@/pages/tenant/ServiceAccounts'
import AgentTokensPage from '@/pages/tenant/AgentTokens'
import APIKeysPage from '@/pages/tenant/APIKeys'
import KeyRotationPage from '@/pages/tenant/KeyRotation'
import ActionsV2Page from '@/pages/tenant/ActionsV2'
import WsFedRPsPage from '@/pages/tenant/WsFedRPs'
import AppFamiliesPage from '@/pages/tenant/AppFamilies'
import QTSPAssessmentPage from '@/pages/tenant/QTSPAssessment'
import PAMPage from '@/pages/tenant/PAM'
import FGAPage from '@/pages/tenant/FGA'
import AdminDelegationPage from '@/pages/tenant/AdminDelegation'
import EntityReviewPage from '@/pages/tenant/EntityReview'
import CrossOrgTrustPage from '@/pages/tenant/CrossOrgTrust'
import CompliancePage from '@/pages/tenant/Compliance'
import SecurityCenterPage from '@/pages/tenant/SecurityCenter'
import SPIDConfigPage from '@/pages/tenant/SPIDConfig'
import EnrichmentHookPage from '@/pages/tenant/EnrichmentHook'
import RateLimitsPage from '@/pages/tenant/RateLimits'
import EmailPolicyPage from '@/pages/tenant/EmailPolicy'
import LoginTemplatePage from '@/pages/tenant/LoginTemplate'
import AutoEnrollPage from '@/pages/tenant/AutoEnroll'
import LifecycleReportPage from '@/pages/tenant/LifecycleReport'
import AuditSinksPage from '@/pages/tenant/AuditSinks'
import SuperadminAPIKeysPage from '@/pages/superadmin/APIKeys'
import LicensePage from '@/pages/superadmin/License'
import SPIDInstanceConfigPage from '@/pages/admin/SPIDInstanceConfig'
import MarketplaceListingsPage from '@/pages/tenant/MarketplaceListings'

// IT Admin Self-Serve Portal
import PortalLayout from '@/layouts/PortalLayout'
import { SSOPortalPage, SCIMPortalPage, DomainsPortalPage, MFAPortalPage } from '@/pages/portal/SelfServePortal'
import { MyAgentGrantsPage } from '@/pages/portal/MyAgentGrants'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { authenticated, orgId, isSuperAdmin } = useAuthStore()
  if (!authenticated) return <Navigate to="/login" replace />
  if (!isSuperAdmin && !orgId) return null
  return <>{children}</>
}

function RequireSuperAdmin({ children }: { children: React.ReactNode }) {
  const { authenticated, isSuperAdmin } = useAuthStore()
  if (!authenticated) return <Navigate to="/login" replace />
  if (!isSuperAdmin) return <Navigate to="/admin" replace />
  return <>{children}</>
}

function SmartRedirect() {
  const { authenticated, isSuperAdmin, orgSlug } = useAuthStore()
  if (!authenticated) return <Navigate to="/login" replace />
  if (isSuperAdmin) return <Navigate to="/admin/orgs" replace />
  return <Navigate to={`/admin/${orgSlug}`} replace />
}

export default function App() {
  return (
    <ErrorBoundary>
    <BrowserRouter>
      <Toaster position="top-right" toastOptions={{ duration: 3500 }} />
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/comparison" element={<ComparisonPage />} />
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/credentials" element={<MarketplacePage />} />

        {/* Smart root redirect */}
        <Route path="/" element={<SmartRedirect />} />

        {/* Superadmin section */}
        <Route
          path="/admin"
          element={
            <RequireSuperAdmin>
              <SuperAdminLayout />
            </RequireSuperAdmin>
          }
        >
          <Route index element={<Navigate to="/admin/orgs" replace />} />
          <Route path="orgs" element={<OrgsPage />} />
          <Route path="orgs/:orgId" element={<OrgDetailPage />} />
          <Route path="orgs/:orgId/users" element={<OrgUsersPage />} />
          <Route path="orgs/:orgId/clients" element={<OrgClientsPage />} />
          <Route path="orgs/:orgId/branding" element={<OrgBrandingPage />} />
          <Route path="orgs/:orgId/audit" element={<OrgAuditPage />} />
          <Route path="orgs/:orgId/roles" element={<OrgRolesPage />} />
          <Route path="orgs/:orgId/captcha" element={<OrgCaptchaPage />} />
          <Route path="provision" element={<ProvisionOrgPage />} />
          <Route path="health" element={<HealthDashboardPage />} />
          <Route path="api-keys" element={<SuperadminAPIKeysPage />} />
          <Route path="signing-keys" element={<SuperadminSigningKeysPage />} />
          <Route path="license" element={<LicensePage />} />
          <Route path="spid-instance" element={<SPIDInstanceConfigPage />} />
        </Route>

        {/* Tenant admin section */}
        <Route
          path="/admin/:orgSlug"
          element={
            <RequireAuth>
              <TenantLayout />
            </RequireAuth>
          }
        >
          <Route index element={<TenantDashboard />} />
          <Route path="users" element={<TenantUsersPage />} />
          <Route path="roles" element={<TenantRolesPage />} />
          <Route path="groups" element={<TenantGroupsPage />} />
          <Route path="clients" element={<TenantClientsPage />} />
          <Route path="client-scopes" element={<TenantClientScopesPage />} />
          <Route path="branding" element={<TenantBrandingPage />} />
          <Route path="captcha" element={<TenantCaptchaPage />} />
          <Route path="audit" element={<TenantAuditPage />} />
          <Route path="ldap" element={<TenantLdapPage />} />
          <Route path="sessions" element={<TenantSessionsPage />} />
          <Route path="settings" element={<TenantSettingsPage />} />
          <Route path="webhooks" element={<TenantWebhooksPage />} />
          <Route path="scim-push" element={<TenantScimPushPage />} />
          <Route path="identity-providers" element={<TenantIdentityProvidersPage />} />
          <Route path="spid" element={<SPIDConfigPage />} />
          <Route path="credentials" element={<CredentialStatusPage />} />
          <Route path="risk-dashboard" element={<RiskDashboardPage />} />
          <Route path="security/breached-passwords" element={<BreachedPasswordsPage />} />
          <Route path="shield-dashboard" element={<ShieldDashboardPage />} />
          <Route path="verified-credentials" element={<VerifiedCredentialsPage />} />
          <Route path="marketplace" element={<MarketplaceListingsPage />} />
          <Route path="credential-schema-generator" element={<CredentialSchemaGeneratorPage />} />
          <Route path="credential-analytics" element={<CredentialAnalyticsPage />} />
          <Route path="policy-simulate" element={<PolicySimulatePage />} />
          <Route path="policy-batch-simulate" element={<PolicyBatchSimulatePage />} />
          <Route path="grants" element={<TenantGrantsPage />} />
          <Route path="eidas" element={<EidasPage />} />
          <Route path="policy-editor" element={<PolicyEditorPage />} />
          <Route path="login-intelligence" element={<LoginIntelligencePage />} />
          <Route path="lockout-admin" element={<LockoutAdminPage />} />
          <Route path="stream" element={<StreamDevPage />} />
          <Route path="ssf-streams" element={<SSFStreamsPage />} />
          <Route path="cae-monitor" element={<CAEMonitorPage />} />
          <Route path="passkey-policy" element={<PasskeyPolicyPage />} />
          <Route path="passkey-exchange" element={<PasskeyExchangePage />} />
          <Route path="mds-catalog" element={<MDSCatalogPage />} />
          <Route path="credential-offers" element={<CredentialOffersPage />} />
          <Route path="onboarding" element={<OnboardingWizardPage />} />
          <Route path="wallet-verifier" element={<WalletVerifierPage />} />
          <Route path="eidas-rp-metadata" element={<EidasRPMetadataPage />} />
          <Route path="scim-compliance" element={<SCIMCompliancePage />} />
          <Route path="lifecycle-rules" element={<LifecycleRulesPage />} />
          <Route path="access-reviews" element={<AccessReviewsPage />} />
          <Route path="login-flows" element={<LoginFlowsPage />} />
          <Route path="ai-assistant" element={<AIAssistantPage />} />
          <Route path="ip-rules" element={<IPRulesPage />} />
          <Route path="service-accounts" element={<ServiceAccountsPage />} />
          <Route path="agent-tokens" element={<AgentTokensPage />} />
          <Route path="api-keys" element={<APIKeysPage />} />
          <Route path="key-rotation" element={<KeyRotationPage />} />
          <Route path="actions" element={<ActionsV2Page />} />
          <Route path="wsfed-rps" element={<WsFedRPsPage />} />
          <Route path="app-families" element={<AppFamiliesPage />} />
          <Route path="qtsp-assessment" element={<QTSPAssessmentPage />} />
          <Route path="pam" element={<PAMPage />} />
          <Route path="fga" element={<FGAPage />} />
          <Route path="admin-delegation" element={<AdminDelegationPage />} />
          <Route path="entity-review" element={<EntityReviewPage />} />
          <Route path="cross-org-trust" element={<CrossOrgTrustPage />} />
          <Route path="compliance" element={<CompliancePage />} />
          <Route path="security-center" element={<SecurityCenterPage />} />
          <Route path="enrichment-hook" element={<EnrichmentHookPage />} />
          <Route path="rate-limits" element={<RateLimitsPage />} />
          <Route path="email-policy" element={<EmailPolicyPage />} />
          <Route path="login-template" element={<LoginTemplatePage />} />
          <Route path="auto-enroll" element={<AutoEnrollPage />} />
          <Route path="lifecycle-report" element={<LifecycleReportPage />} />
          <Route path="audit-sinks" element={<AuditSinksPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />

        {/* IT Admin Self-Serve Portal — simplified UI for ISV customers */}
        <Route
          path="/portal/:orgSlug"
          element={
            <RequireAuth>
              <PortalLayout />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="sso" replace />} />
          <Route path="sso"     element={<SSOPortalPage />}     />
          <Route path="scim"    element={<SCIMPortalPage />}    />
          <Route path="domains" element={<DomainsPortalPage />} />
          <Route path="mfa"     element={<MFAPortalPage />}     />
          <Route path="my-agents" element={<MyAgentGrantsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
    </ErrorBoundary>
  )
}
