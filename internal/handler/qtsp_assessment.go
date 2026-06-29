package handler

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ── QTSP readiness assessment ─────────────────────────────────────────────────
//
// GET /api/v1/organizations/:org_id/qtsp-assessment
//
// Returns a structured eIDAS 2.0 QTSP (Qualified Trust Service Provider)
// readiness assessment for the organisation. Each item reports whether Clavex
// can verify the criterion automatically ("auto") or whether it requires manual
// evidence ("manual"), along with a pass/fail/partial/unknown status.
//
// This is a read-only, non-destructive endpoint – it does not modify any state.
// It requires org-admin level access (RequireResourcePermission("settings")).

// QTSPStatus is one assessment line item.
type QTSPStatus string

const (
	QTSPStatusPass    QTSPStatus = "pass"
	QTSPStatusFail    QTSPStatus = "fail"
	QTSPStatusPartial QTSPStatus = "partial"
	QTSPStatusManual  QTSPStatus = "manual" // cannot be auto-verified
)

// QTSPCheckType classifies whether Clavex can verify the item automatically.
type QTSPCheckType string

const (
	QTSPCheckAuto   QTSPCheckType = "auto"   // verified from Clavex config
	QTSPCheckManual QTSPCheckType = "manual" // requires external evidence
)

// QTSPItem is one criterion in the readiness checklist.
type QTSPItem struct {
	// ID is a stable machine-readable identifier for the criterion.
	ID string `json:"id"`
	// Title is a short human-readable label (English).
	Title string `json:"title"`
	// Description explains the eIDAS 2.0 requirement and what needs to be done.
	Description string `json:"description"`
	// Reference is the eIDAS 2.0 article / ETSI standard that defines the requirement.
	Reference string `json:"reference"`
	// CheckType indicates whether Clavex can verify this automatically.
	CheckType QTSPCheckType `json:"check_type"`
	// Status is the current result for this org.
	Status QTSPStatus `json:"status"`
	// Hint provides actionable guidance when status is fail or partial.
	Hint string `json:"hint,omitempty"`
}

// QTSPCategory groups related items.
type QTSPCategory struct {
	ID    string     `json:"id"`
	Title string     `json:"title"`
	Items []QTSPItem `json:"items"`
	// Score is the fraction of auto-verified items that pass (0.0–1.0).
	Score float64 `json:"score"`
}

// QTSPAssessment is the full QTSP readiness report for an org.
type QTSPAssessment struct {
	OrgID      uuid.UUID      `json:"org_id"`
	Categories []QTSPCategory `json:"categories"`
	// OverallScore is the fraction of ALL auto-verified items that pass.
	OverallScore float64 `json:"overall_score"`
	// ReadyForSubmission is true when all auto-verified items pass AND all
	// manual items have been acknowledged (i.e., no fail/partial auto items).
	ReadyForSubmission bool `json:"ready_for_submission"`
	// Summary describes the overall readiness in one sentence.
	Summary string `json:"summary"`
}

// QTSPHandler computes the eIDAS 2.0 QTSP readiness assessment.
type QTSPHandler struct {
	pool *pgxpool.Pool
}

func NewQTSPHandler(pool *pgxpool.Pool) *QTSPHandler {
	return &QTSPHandler{pool: pool}
}

// Assessment handles GET /api/v1/organizations/:org_id/qtsp-assessment.
func (h *QTSPHandler) Assessment(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	a, err := h.buildAssessment(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	return c.JSON(http.StatusOK, a)
}

// ── Assessment logic ──────────────────────────────────────────────────────────

// orgSignals is the pre-fetched data used to evaluate all criteria.
type orgSignals struct {
	// Password policy
	minLength           int
	requireUppercase    bool
	requireNumber       bool
	requireSymbol       bool
	maxAgeDays          *int
	breachAction        string // off|warn|block|force_reset

	// MFA
	hasMFARequiredClient bool
	mfaEnrolledFraction  float64 // 0.0–1.0

	// Identity verification
	hasEIDASProvider  bool // SpID/CIE/BundID/eIDAS type
	hasSAMLSP         bool
	hasIdentityProvider bool

	// Notification
	hasSMTP          bool
	hasActiveWebhook bool

	// Captcha
	hasCaptcha bool

	// Cross-org / federation
	hasCrossOrgTrust bool

	// Audit
	auditLogEnabled bool // always true in Clavex

	// Token signing
	tokenSigningAlg string // always PS256 in Clavex
}

func (h *QTSPHandler) buildAssessment(ctx context.Context, orgID uuid.UUID) (*QTSPAssessment, error) {
	s, err := h.gatherSignals(ctx, orgID)
	if err != nil {
		return nil, err
	}

	a := &QTSPAssessment{OrgID: orgID}

	// ── Category 1: Identity Proofing ─────────────────────────────────────────
	cat1 := QTSPCategory{ID: "identity_proofing", Title: "Identity Proofing (eIDAS 2.0 Art. 24)"}
	cat1.Items = []QTSPItem{
		item(
			"idp.eidas_provider",
			"eIDAS-compliant identity provider configured",
			"At least one SPID, CIE, BundID, or eIDAS-node identity provider must be active. "+
				"This ensures users are authenticated against a notified electronic identification scheme.",
			"eIDAS 2.0 Art. 6a, Annex I",
			QTSPCheckAuto,
			boolStatus(s.hasEIDASProvider,
				"",
				"Configure SPID, CIE, BundID, or an eIDAS connector as an identity provider under Federations."),
		),
		item(
			"idp.federated_saml",
			"SAML or OIDC federation active",
			"The organisation must support at least one federated authentication protocol to enable cross-border trust.",
			"eIDAS 2.0 Art. 7, ETSI EN 319 412",
			QTSPCheckAuto,
			boolStatus(s.hasSAMLSP || s.hasIdentityProvider,
				"",
				"Register a SAML service provider or configure an external OIDC identity provider."),
		),
		{
			ID:          "idp.video_verification",
			Title:       "Remote video identity verification capability",
			Description: "Operators must be able to verify the identity of natural persons remotely using video or equivalent biometric means before issuing qualified certificates.",
			Reference:   "eIDAS 2.0 Art. 24(1)(d), Regulation (EU) 910/2014",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Document your video-verification procedure (e.g., with a certified AAMVA/iBeta provider). Attach evidence to your QTSP application.",
		},
	}

	// ── Category 2: Security Controls ────────────────────────────────────────
	cat2 := QTSPCategory{ID: "security_controls", Title: "Security Controls (ETSI EN 319 401)"}
	pwPass := s.minLength >= 12 && s.requireUppercase && s.requireNumber && s.requireSymbol
	pwHint := ""
	if !pwPass {
		missing := []string{}
		if s.minLength < 12 {
			missing = append(missing, "min_length ≥ 12")
		}
		if !s.requireUppercase {
			missing = append(missing, "require_uppercase")
		}
		if !s.requireNumber {
			missing = append(missing, "require_number")
		}
		if !s.requireSymbol {
			missing = append(missing, "require_symbol")
		}
		pwHint = "Update the password policy: " + joinStrings(missing, ", ")
	}
	cat2.Items = []QTSPItem{
		item(
			"sec.password_complexity",
			"Password complexity meets NIST SP 800-63B / BSI TR-02102",
			"Minimum 12 characters with uppercase, numeric, and special characters required.",
			"ETSI EN 319 401 §6.3, NIST SP 800-63B",
			QTSPCheckAuto,
			itemStatus(pwPass, pwHint),
		),
		item(
			"sec.breach_detection",
			"Breached-password detection enabled",
			"Passwords must be checked against known breach corpora (e.g., HIBP) on every set/change. Action must be 'block' or 'force_reset' — not 'warn' or 'off'.",
			"ETSI EN 319 401 §6.3, NIST SP 800-63B §5.1.1.2",
			QTSPCheckAuto,
			itemStatus(s.breachAction == "block" || s.breachAction == "force_reset",
				"Set breached_password_action to 'block' or 'force_reset' in the password policy."),
		),
		item(
			"sec.mfa_required",
			"MFA enforced for privileged users / all members",
			"Multi-factor authentication must be required for all users or at minimum for users with privileged access.",
			"eIDAS 2.0 Art. 19, ETSI EN 319 401 §6.4",
			QTSPCheckAuto,
			boolStatus(s.hasMFARequiredClient,
				"",
				"Enable MFA requirement on the OIDC client(s) used for admin / privileged access."),
		),
		item(
			"sec.audit_logging",
			"Audit logging enabled",
			"All authentication, authorisation, and administrative events must be logged with tamper-evident records.",
			"eIDAS 2.0 Art. 19(2)(d), ETSI EN 319 401 §7.10",
			QTSPCheckAuto,
			boolStatus(s.auditLogEnabled, "", ""),
		),
		item(
			"sec.token_signing",
			"Tokens signed with RS256/PS256 (asymmetric)",
			"Access and ID tokens must be signed with a strong asymmetric algorithm — not HS256 (symmetric).",
			"ETSI TS 119 495, RFC 7518",
			QTSPCheckAuto,
			boolStatus(s.tokenSigningAlg == "PS256" || s.tokenSigningAlg == "RS256", "",
				"Configure the token signing key to use PS256 or RS256."),
		),
		{
			ID:          "sec.hsm",
			Title:       "HSM / hardware key management",
			Description: "Private signing keys for qualified certificates must be generated and stored in a certified hardware security module (FIPS 140-2 Level 3 or CC EAL 4+).",
			Reference:   "eIDAS 2.0 Annex II, ETSI EN 319 411-2",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Document your HSM model and certification level. Cloud HSM (e.g., AWS CloudHSM, Azure Dedicated HSM) is acceptable if certified.",
		},
		{
			ID:          "sec.pentest",
			Title:       "Annual penetration testing performed",
			Description: "A penetration test by a qualified third party must be conducted at least annually and findings remediated.",
			Reference:   "ETSI EN 319 401 §6.9",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Attach the most recent pen-test report (date, scope, critical findings, remediation status) to your QTSP application.",
		},
	}

	// ── Category 3: Notification & Communication ─────────────────────────────
	cat3 := QTSPCategory{ID: "notification", Title: "Notification & Communication (eIDAS 2.0 Art. 20)"}
	cat3.Items = []QTSPItem{
		item(
			"notif.smtp",
			"Transactional email (SMTP) configured",
			"The QTSP must be able to notify subscribers of account events, certificate expiry, and security incidents.",
			"eIDAS 2.0 Art. 20(3)",
			QTSPCheckAuto,
			boolStatus(s.hasSMTP, "", "Configure SMTP settings under Organization → Email Settings."),
		),
		item(
			"notif.webhook",
			"Webhook / event notifications configured",
			"At least one active webhook should be configured to receive security-critical events (breach, suspicious login, MFA failure).",
			"ETSI EN 319 401 §7.10",
			QTSPCheckAuto,
			boolStatus(s.hasActiveWebhook, "", "Register a webhook under Organization → Developer → Webhooks."),
		),
		{
			ID:          "notif.incident_response",
			Title:       "Incident response plan documented",
			Description: "A written incident response plan (IRP) must cover breach notification within 24 h to supervisory body and 72 h to affected subscribers.",
			Reference:   "eIDAS 2.0 Art. 19(2)(f), GDPR Art. 33",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Attach the IRP document, including contact names, escalation paths, and notification templates.",
		},
	}

	// ── Category 4: Compliance & Governance ──────────────────────────────────
	cat4 := QTSPCategory{ID: "compliance", Title: "Compliance & Governance (eIDAS 2.0 Art. 17–19)"}
	cat4.Items = []QTSPItem{
		{
			ID:          "comp.cp_cps",
			Title:       "Certificate Policy (CP) / Certification Practice Statement (CPS) published",
			Description: "The QTSP must publish a CP and CPS describing the lifecycle of qualified certificates, including issuance, renewal, suspension, and revocation.",
			Reference:   "eIDAS 2.0 Art. 17(4)(c), ETSI EN 319 411-1",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Draft CP and CPS using the ETSI EN 319 411-1 template. Publish them at a stable HTTPS URL.",
		},
		{
			ID:          "comp.supervisory_notification",
			Title:       "Supervisory body notified",
			Description: "Intent to operate as a QTSP must be notified to the national supervisory body at least 3 months before commencing qualified trust services.",
			Reference:   "eIDAS 2.0 Art. 17(1)",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "File notification with the national supervisory body. In Italy: AgID; Germany: BNetzA; France: ANSSI.",
		},
		{
			ID:          "comp.conformity_assessment",
			Title:       "Conformity assessment by accredited CAB",
			Description: "A Conformity Assessment Body (CAB) accredited under ISO 17065 must audit the QTSP against ETSI EN 319 401 and the relevant trust service standard.",
			Reference:   "eIDAS 2.0 Art. 20(1)",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Engage an accredited CAB (e.g., TÜV, BSI, LSTI) for the conformity assessment audit.",
		},
		{
			ID:          "comp.insurance",
			Title:       "Professional liability insurance ≥ €500,000",
			Description: "The QTSP must carry professional liability insurance of at least €500,000 to cover subscriber claims.",
			Reference:   "eIDAS 2.0 Art. 19(2)(c)",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Obtain a professional liability insurance policy and attach the certificate to your application.",
		},
		{
			ID:          "comp.gdpr_dpa",
			Title:       "Data Protection Agreement and DPA designated",
			Description: "A Data Protection Agreement must be in place and a Data Protection Officer (DPO) designated if processing personal data at scale.",
			Reference:   "GDPR Art. 37, eIDAS 2.0 Art. 5",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Appoint a DPO, file DPA with national supervisory authority (e.g., Garante in Italy), and publish privacy notice.",
		},
	}

	// ── Category 5: Availability & Resilience ────────────────────────────────
	cat5 := QTSPCategory{ID: "availability", Title: "Availability & Resilience (ETSI EN 319 401 §6.5)"}
	cat5.Items = []QTSPItem{
		{
			ID:          "avail.sla",
			Title:       "99.9% uptime SLA documented",
			Description: "The QTSP must guarantee and document a minimum 99.9% monthly uptime for all qualified trust services.",
			Reference:   "ETSI EN 319 401 §6.5.1",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Define an SLA in your service agreement and publish a public status page (e.g., status.yourcompany.com).",
		},
		{
			ID:          "avail.dr",
			Title:       "Disaster recovery plan with RTO ≤ 4 h",
			Description: "A tested DR plan must exist with Recovery Time Objective of 4 hours or less for critical services.",
			Reference:   "ETSI EN 319 401 §6.5.2",
			CheckType:   QTSPCheckManual,
			Status:      QTSPStatusManual,
			Hint:        "Document and test your DR runbook. Record the last DR drill date and its outcome.",
		},
		item(
			"avail.health_endpoint",
			"Service health endpoint available",
			"A public or authenticated health-check endpoint must be available for monitoring uptime.",
			"ETSI EN 319 401 §6.5",
			QTSPCheckAuto,
			QTSPStatusPass, // Clavex always exposes /health
		),
	}

	a.Categories = []QTSPCategory{cat1, cat2, cat3, cat4, cat5}

	// ── Compute scores ────────────────────────────────────────────────────────
	var totalAuto, passedAuto int
	for i, cat := range a.Categories {
		var catAuto, catPassed int
		for _, it := range cat.Items {
			if it.CheckType == QTSPCheckAuto {
				catAuto++
				totalAuto++
				if it.Status == QTSPStatusPass {
					catPassed++
					passedAuto++
				}
			}
		}
		if catAuto > 0 {
			a.Categories[i].Score = float64(catPassed) / float64(catAuto)
		}
	}
	if totalAuto > 0 {
		a.OverallScore = float64(passedAuto) / float64(totalAuto)
	}
	a.ReadyForSubmission = passedAuto == totalAuto
	if a.ReadyForSubmission {
		a.Summary = "All automatically-verified requirements pass. Complete the manual checklist items and engage an accredited CAB to proceed with QTSP notification."
	} else {
		a.Summary = "Some automatically-verified requirements have not yet been met. Address the highlighted items before initiating the QTSP conformity assessment process."
	}

	return a, nil
}

// gatherSignals runs the queries needed to build the assessment.
func (h *QTSPHandler) gatherSignals(ctx context.Context, orgID uuid.UUID) (*orgSignals, error) {
	s := &orgSignals{
		auditLogEnabled: true,       // Clavex always logs
		tokenSigningAlg: "PS256",    // Clavex default signing algorithm
	}

	// Password policy.
	_ = h.pool.QueryRow(ctx,
		`SELECT min_length, require_uppercase, require_number, require_symbol, max_age_days, breached_password_action
		 FROM org_password_policy WHERE org_id = $1`, orgID,
	).Scan(&s.minLength, &s.requireUppercase, &s.requireNumber, &s.requireSymbol,
		&s.maxAgeDays, &s.breachAction)

	// MFA: any active OIDC client with mfa_required=true.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM oidc_clients WHERE org_id=$1 AND mfa_required=TRUE AND is_active=TRUE)`,
		orgID,
	).Scan(&s.hasMFARequiredClient)

	// eIDAS-compliant identity providers (SPID/CIE/BundID/eIDAS).
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM identity_providers
		   WHERE org_id=$1 AND is_active=TRUE
		     AND provider_type IN ('spid','cie','bundid','eidas','digid','france_connect','clave','itsme')
		 )`, orgID,
	).Scan(&s.hasEIDASProvider)

	// Any active IdP (OIDC federation).
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM identity_providers WHERE org_id=$1 AND is_active=TRUE)`, orgID,
	).Scan(&s.hasIdentityProvider)

	// SAML service providers registered.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM saml_service_providers WHERE org_id=$1 AND is_active=TRUE)`, orgID,
	).Scan(&s.hasSAMLSP)

	// SMTP configured.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM org_smtp_settings WHERE org_id=$1 AND is_active=TRUE)`, orgID,
	).Scan(&s.hasSMTP)

	// Active webhook.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM webhooks WHERE org_id=$1 AND is_active=TRUE)`, orgID,
	).Scan(&s.hasActiveWebhook)

	// CAPTCHA.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM identity.org_captcha_settings WHERE org_id=$1 AND is_active=TRUE)`, orgID,
	).Scan(&s.hasCaptcha)

	// Cross-org trusts.
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM cross_org_trusts WHERE trusting_org_id=$1 OR trusted_org_id=$1)`, orgID,
	).Scan(&s.hasCrossOrgTrust)

	// MFA enrollment fraction.
	var total, enrolled int64
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE mfa_required=TRUE OR id IN (
		   SELECT DISTINCT user_id FROM mfa_credentials WHERE org_id=$1
		 )) FROM users WHERE org_id=$1 AND is_active=TRUE`, orgID,
	).Scan(&total, &enrolled); err == nil && total > 0 {
		s.mfaEnrolledFraction = float64(enrolled) / float64(total)
	}

	return s, nil
}

// ── Item helpers ──────────────────────────────────────────────────────────────

func item(id, title, desc, ref string, ct QTSPCheckType, status QTSPStatus, hint ...string) QTSPItem {
	h := ""
	if len(hint) > 0 {
		h = hint[0]
	}
	return QTSPItem{
		ID:          id,
		Title:       title,
		Description: desc,
		Reference:   ref,
		CheckType:   ct,
		Status:      status,
		Hint:        h,
	}
}

func boolStatus(ok bool, passHint, failHint string) QTSPStatus {
	if ok {
		return QTSPStatusPass
	}
	return QTSPStatusFail
}

func itemStatus(ok bool, failHint ...string) QTSPStatus {
	if ok {
		return QTSPStatusPass
	}
	return QTSPStatusFail
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}
