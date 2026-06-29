package handler

import (
	"fmt"
	"net/http"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// VerifiedCatalogHandler seeds and manages the Clavex Verified credential
// catalog — training, qualification and badge credential types.
type VerifiedCatalogHandler struct {
	repo *repository.OID4WRepository
	orgs *repository.OrgRepository
	cfg  baseURLProvider
}

// NewVerifiedCatalogHandler creates a new VerifiedCatalogHandler.
func NewVerifiedCatalogHandler(pool *pgxpool.Pool, cfg baseURLProvider) *VerifiedCatalogHandler {
	return &VerifiedCatalogHandler{
		repo: repository.NewOID4WRepository(pool),
		orgs: repository.NewOrgRepository(pool),
		cfg:  cfg,
	}
}

// verifiedCatalogEntry is one entry in the standard Clavex Verified catalog.
type verifiedCatalogEntry struct {
	category     string
	displayName  string
	description  string
	vctSuffix    string // appended to <baseURL>/<slug>/credentials/
	ttlSeconds   int
	schemaFields []models.SchemaFieldDef
}

// standardCatalog is the set of credential types Clavex Verified ships out-of-box.
var standardCatalog = []verifiedCatalogEntry{
	{
		category:    "training",
		displayName: "Training Completion Certificate",
		description: "Verifiable attestation that a person has completed a training course.",
		vctSuffix:   "training-completion/v1",
		ttlSeconds:  3 * 365 * 24 * 3600, // 3 years
		schemaFields: []models.SchemaFieldDef{
			{Name: "course_name", Label: "Course Name", Type: "string", Mandatory: true},
			{Name: "completion_date", Label: "Completion Date", Type: "date", Mandatory: true},
			{Name: "issuer_name", Label: "Issuing Institution", Type: "string", Mandatory: true},
			{Name: "score", Label: "Score / Grade", Type: "string", Mandatory: false},
			{Name: "course_hours", Label: "Duration (hours)", Type: "number", Mandatory: false},
			{Name: "certificate_id", Label: "Certificate ID", Type: "string", Mandatory: false},
		},
	},
	{
		category:    "qualification",
		displayName: "Professional Qualification",
		description: "eIDAS 2.0 qualified attestation of professional title, licence or certification.",
		vctSuffix:   "professional-qualification/v1",
		ttlSeconds:  5 * 365 * 24 * 3600, // 5 years
		schemaFields: []models.SchemaFieldDef{
			{Name: "qualification_name", Label: "Qualification Name", Type: "string", Mandatory: true},
			{Name: "awarding_body", Label: "Awarding Body", Type: "string", Mandatory: true},
			{Name: "valid_from", Label: "Valid From", Type: "date", Mandatory: true},
			{Name: "valid_until", Label: "Valid Until", Type: "date", Mandatory: false},
			{Name: "level", Label: "EQF / NQF Level", Type: "string", Mandatory: false},
			{Name: "regulation", Label: "Regulation Reference", Type: "string", Mandatory: false},
			{Name: "registration_number", Label: "Registration Number", Type: "string", Mandatory: false},
		},
	},
	{
		category:    "badge",
		displayName: "Competency Badge",
		description: "Digital open badge attesting mastery of a specific skill or competency.",
		vctSuffix:   "competency-badge/v1",
		ttlSeconds:  2 * 365 * 24 * 3600, // 2 years
		schemaFields: []models.SchemaFieldDef{
			{Name: "badge_name", Label: "Badge Name", Type: "string", Mandatory: true},
			{Name: "skill", Label: "Skill / Competency", Type: "string", Mandatory: true},
			{Name: "issued_by", Label: "Issued By", Type: "string", Mandatory: true},
			{Name: "evidence_url", Label: "Evidence URL", Type: "url", Mandatory: false},
			{Name: "criteria", Label: "Criteria Description", Type: "string", Mandatory: false},
		},
	},
	{
		// eIDAS 2.0 use-case: employer-issued employment attestation (OID4VCI).
		// Issued by HR systems via OID4VCI; presented by employees to banks
		// (mortgage applications), PA (welfare contributions), and insurers
		// (income proof) via OID4VP — no paper certificate required.
		category:    "employment",
		displayName: "Employment Attestation",
		description: "eIDAS 2.0 employer-issued verifiable credential attesting current employment status, role, and start date. Issued via OID4VCI; presentable to banks, PA, and insurers via OID4VP.",
		vctSuffix:   "employment-attestation/v1",
		ttlSeconds:  365 * 24 * 3600, // 1 year — re-issue annually or on role change
		schemaFields: []models.SchemaFieldDef{
			{Name: "employer_name", Label: "Employer Name", Type: "string", Mandatory: true},
			{Name: "employer_vat", Label: "Employer VAT / Tax ID", Type: "string", Mandatory: false},
			{Name: "employee_name", Label: "Employee Full Name", Type: "string", Mandatory: true},
			{Name: "employee_id", Label: "Employee ID", Type: "string", Mandatory: false},
			{Name: "job_title", Label: "Job Title / Role", Type: "string", Mandatory: true},
			{Name: "employment_type", Label: "Employment Type", Type: "string", Mandatory: true}, // full-time, part-time, contractor
			{Name: "start_date", Label: "Employment Start Date", Type: "date", Mandatory: true},
			{Name: "end_date", Label: "Employment End Date", Type: "date", Mandatory: false},     // nil = currently employed
			{Name: "department", Label: "Department / Business Unit", Type: "string", Mandatory: false},
			{Name: "gross_annual_salary", Label: "Gross Annual Salary (EUR)", Type: "number", Mandatory: false},
			{Name: "currency", Label: "Currency (ISO 4217)", Type: "string", Mandatory: false},
			{Name: "workplace_country", Label: "Country of Employment (ISO 3166)", Type: "string", Mandatory: false},
			{Name: "contract_reference", Label: "Contract Reference", Type: "string", Mandatory: false},
		},
	},
}

// SeedCatalog handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed
//
// Idempotent: inserts missing credential configs for the three standard Clavex
// Verified types. Existing configs are left untouched (ON CONFLICT DO NOTHING
// semantics — enforced by catching the duplicate-VCT error and continuing).
//
// Returns the full list of Verified credential configs after seeding.
func (h *VerifiedCatalogHandler) SeedCatalog(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	baseURL := h.cfg.BaseURL()
	var seeded, skipped int

	for _, entry := range standardCatalog {
		vct := fmt.Sprintf("%s/%s/credentials/%s", baseURL, org.Slug, entry.vctSuffix)
		desc := entry.description
		_, err := h.repo.CreateCredentialConfig(
			ctx, orgID, vct, entry.displayName, &desc,
			map[string]interface{}{}, // no user-attribute mapping for Verified types
			entry.ttlSeconds,
			entry.category,
			entry.schemaFields,
		)
		if err != nil {
			// Already exists — skip gracefully.
			skipped++
			continue
		}
		seeded++
	}

	// Return the current Verified configs for this org.
	all, err := h.repo.ListCredentialConfigs(ctx, orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	verified := make([]models.CredentialConfig, 0)
	for _, cfg := range all {
		if cfg.Category != "identity" {
			verified = append(verified, cfg)
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"seeded":  seeded,
		"skipped": skipped,
		"configs": verified,
	})
}

// GetCatalog handles GET /api/v1/organizations/:org_id/oid4vci/catalog
// Returns all non-identity credential configs for this org.
func (h *VerifiedCatalogHandler) GetCatalog(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	all, err := h.repo.ListCredentialConfigs(c.Request().Context(), orgID)
	if err != nil {
		return echo.ErrInternalServerError
	}
	verified := make([]models.CredentialConfig, 0)
	for _, cfg := range all {
		if cfg.Category != "identity" {
			verified = append(verified, cfg)
		}
	}
	return c.JSON(http.StatusOK, verified)
}

// uuidParam is shared across handlers in the package; resolve org_id from path.
// (declared in handler.go — referenced here for documentation purposes only)
var _ = uuid.Nil

// ── Identity credential presets ───────────────────────────────────────────────

// SeedSpidPreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-spid
//
// Creates (idempotent) a pre-configured SD-JWT-VC credential config for Italian
// SPID. The config has source_idp_type = "spid" so that after a SPID L2 login
// Clavex automatically creates a pre-authorized offer with fiscalNumber,
// familyName, name and dateOfBirth — all SPID-verified claims.
func (h *VerifiedCatalogHandler) SeedSpidPreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	baseURL := h.cfg.BaseURL()
	vct := fmt.Sprintf("%s/%s/credentials/spid-identity/v1", baseURL, org.Slug)
	desc := "SD-JWT-VC credential with SPID-verified fiscal code, name and date of birth. " +
		"Auto-issued after SPID L2 login (AgID SPID Next Generation / eIDAS 2.0 EUDIW flow)."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, vct,
		"SPID Identity Credential",
		&desc,
		// ClaimsMapping: mdoc-style element IDs → user metadata field paths.
		// The metadata.spid_* fields are populated automatically after each SPID login.
		map[string]interface{}{
			"fiscalNumber": "metadata.spid_fiscal_number",
			"familyName":   "metadata.spid_family_name",
			"name":         "metadata.spid_name",
			"dateOfBirth":  "metadata.spid_date_of_birth",
			"placeOfBirth": "metadata.spid_place_of_birth",
			"email":        "metadata.spid_email",
		},
		365*24*3600, // 1 year TTL
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		// Already exists — return the existing config.
		return c.JSON(http.StatusOK, map[string]any{
			"status": "already_exists",
			"vct":    vct,
		})
	}

	// Link to SPID so auto-offer triggers on every SPID login.
	spidType := "spid"
	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &spidType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":        "created",
		"config_id":     cfg.ID,
		"vct":           vct,
		"source_idp":    "spid",
		"claims_mapping": cfg.ClaimsMapping,
	})
}

// SeedCiePreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-cie
//
// Creates (idempotent) a pre-configured SD-JWT-VC credential config for Italian
// CIE (Carta d'Identità Elettronica). The config has source_idp_type = "cie" so
// that after a CIE login Clavex automatically creates a pre-authorized offer.
func (h *VerifiedCatalogHandler) SeedCiePreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	org, err := h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	baseURL := h.cfg.BaseURL()
	vct := fmt.Sprintf("%s/%s/credentials/cie-identity/v1", baseURL, org.Slug)
	desc := "SD-JWT-VC credential with CIE-verified fiscal code, name and date of birth. " +
		"Auto-issued after CIE (eIDAS High) login (AgID / eIDAS 2.0 EUDIW flow)."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, vct,
		"CIE Identity Credential",
		&desc,
		map[string]interface{}{
			"fiscalNumber": "metadata.cie_fiscal_number",
			"familyName":   "metadata.cie_family_name",
			"name":         "metadata.cie_name",
			"dateOfBirth":  "metadata.cie_date_of_birth",
			"gender":       "metadata.cie_gender",
			"email":        "metadata.cie_email",
		},
		365*24*3600,
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status": "already_exists",
			"vct":    vct,
		})
	}

	cieType := "cie"
	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &cieType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":        "created",
		"config_id":     cfg.ID,
		"vct":           vct,
		"source_idp":    "cie",
		"claims_mapping": cfg.ClaimsMapping,
	})
}

// SeedItWalletPreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-it-wallet
//
// Creates (idempotent) a pre-configured SD-JWT-VC credential config aligned with the
// EUDIW PID namespace (eu.europa.ec.eudi.pid.1) and the Italian IT-Wallet national profile.
//
// source_idp_type = "spid" — after every SPID L2 (or higher) login Clavex automatically
// creates a pre-authorized OID4VCI offer for the EU PID credential.  The IT-Wallet client
// can then redeem the offer via the standard OID4VCI pre-authorized code flow.
//
// Claims mapping (SPID verified attributes → EU PID claims):
//
//	family_name       ← metadata.spid_family_name   (cognome)
//	given_name        ← metadata.spid_name           (nome)
//	birth_date        ← metadata.spid_date_of_birth  (data di nascita)
//	birth_place       ← metadata.spid_place_of_birth (luogo di nascita)
//	tax_id_code       ← metadata.spid_fiscal_number  (codice fiscale)
//	personal_identifier ← metadata.spid_fiscal_number (same — TINIT-<CF> format)
//	email             ← metadata.spid_email           (indirizzo e-mail)
func (h *VerifiedCatalogHandler) SeedItWalletPreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	_, err = h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	// vct follows the EUDIW PID namespace.  IT-Wallet clients discover it from the
	// credential_configurations_supported metadata published at
	// GET /.well-known/openid-credential-issuer.
	const itWalletVCT = "eu.europa.ec.eudi.pid.1"

	desc := "EUDIW EU PID credential (eu.europa.ec.eudi.pid.1) aligned with the Italian " +
		"IT-Wallet national profile. Auto-issued as a pre-authorized OID4VCI offer after " +
		"SPID L2 login — no additional user action required. Claims are mapped from " +
		"AgID SPID verified attributes (codice fiscale, nome, cognome, data di nascita)."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, itWalletVCT,
		"EU Personal Identification Data (IT-Wallet / EUDIW)",
		&desc,
		// EUDIW ARF §6.3 mandatory + Italian IT-Wallet national profile optional claims.
		// Values are user metadata paths populated automatically by the SPID callback.
		map[string]interface{}{
			// Mandatory EU PID claims
			"family_name":         "metadata.spid_family_name",
			"given_name":          "metadata.spid_name",
			"birth_date":          "metadata.spid_date_of_birth",
			// Italian national profile: codice fiscale as personal identifier
			"tax_id_code":         "metadata.spid_fiscal_number",
			"personal_identifier": "metadata.spid_fiscal_number",
			// Optional EU PID claims available from SPID Level 2+
			"birth_place":         "metadata.spid_place_of_birth",
			"email":               "metadata.spid_email",
			// Note: issuing_country ("IT") and issuing_authority ("IPZS") are static
			// values that should be injected by the pre-issuance webhook or a claims-
			// enrichment hook.  They are not mapped here because they are not user
			// attributes — they are fixed for every Italian IT-Wallet PID.
		},
		2*365*24*3600, // 2 years — EUDIW PID standard validity (ARF §6.3.3)
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status": "already_exists",
			"vct":    itWalletVCT,
		})
	}

	// Link to SPID so createIdpCredentialOffers fires on every SPID login.
	spidType := "spid"
	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &spidType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":          "created",
		"config_id":       cfg.ID,
		"vct":             itWalletVCT,
		"source_idp":      "spid",
		"claims_mapping":  cfg.ClaimsMapping,
		"next_step":       "Static claims (issuing_country=IT, issuing_authority=IPZS) should be injected via a pre-issuance webhook or enrichment hook.",
	})
}

// SeedCieItWalletPreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-cie-wallet
//
// Creates (idempotent) a pre-configured SD-JWT-VC credential config aligned with the
// EUDIW PID namespace (eu.europa.ec.eudi.pid.1) backed by CIE (eIDAS High assurance).
//
// CIE is the preferred PID issuance source per AgID IT-Wallet spec because it provides
// eIDAS High assurance level — one step above SPID L2. After every CIE login Clavex
// automatically creates a pre-authorized OID4VCI offer for the EU PID credential.
//
// Claims mapping (CIE verified attributes → EU PID claims):
//
//	family_name         ← metadata.cie_family_name   (cognome)
//	given_name          ← metadata.cie_name           (nome)
//	birth_date          ← metadata.cie_date_of_birth  (data di nascita)
//	tax_id_code         ← metadata.cie_fiscal_number  (codice fiscale)
//	personal_identifier ← metadata.cie_fiscal_number  (same — TINIT-<CF> format)
//	email               ← metadata.cie_email           (indirizzo e-mail)
func (h *VerifiedCatalogHandler) SeedCieItWalletPreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	_, err = h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	const itWalletVCT = "eu.europa.ec.eudi.pid.1"

	desc := "EUDIW EU PID credential (eu.europa.ec.eudi.pid.1) backed by CIE (eIDAS High). " +
		"Auto-issued as a pre-authorized OID4VCI offer after CIE login — no additional user action required. " +
		"Claims are mapped from CIE verified attributes (codice fiscale, nome, cognome, data di nascita). " +
		"CIE is the preferred PID issuance source per AgID IT-Wallet specification."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, itWalletVCT,
		"EU Personal Identification Data — CIE (IT-Wallet / EUDIW)",
		&desc,
		map[string]interface{}{
			// Mandatory EU PID claims
			"family_name":         "metadata.cie_family_name",
			"given_name":          "metadata.cie_name",
			"birth_date":          "metadata.cie_date_of_birth",
			// Italian national profile: codice fiscale as personal identifier
			"tax_id_code":         "metadata.cie_fiscal_number",
			"personal_identifier": "metadata.cie_fiscal_number",
			// Optional — only present when CIE has a verified e-mail
			"email": "metadata.cie_email",
		},
		2*365*24*3600, // 2 years — EUDIW PID standard validity (ARF §6.3.3)
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status": "already_exists",
			"vct":    itWalletVCT,
		})
	}

	// Link to CIE so createIdpCredentialOffers fires on every CIE login.
	cieType := "cie"
	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &cieType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":         "created",
		"config_id":      cfg.ID,
		"vct":            itWalletVCT,
		"source_idp":     "cie",
		"claims_mapping": cfg.ClaimsMapping,
		"next_step":      "Static claims (issuing_country=IT, issuing_authority=IPZS) should be injected via a pre-issuance webhook or enrichment hook.",
	})
}

// SeedMdlPreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-mdl
//
// Creates (idempotent) a pre-configured mso_mdoc credential config for the ISO
// 18013-5 mobile Driving Licence (mDL). The docType is "org.iso.18013.5.1.mDL"
// and the claims mapping covers the standard mDL namespace attributes.
//
// The PA still needs to call POST /mdoc/issuers/generate to create the DS
// keypair — this endpoint only registers the credential config schema.
func (h *VerifiedCatalogHandler) SeedMdlPreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	_, err = h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	// For mso_mdoc, VCT == docType (OID4VCI §E.3).
	vct := mdoc.DocTypeMdl
	desc := "ISO 18013-5 mobile Driving Licence (mDL) — eIDAS 2.0 mdoc format. " +
		"Issued via OID4VCI (mso_mdoc); presentable via ISO 18013-5 proximity or OID4VP. " +
		"Requires a DS keypair: POST /mdoc/issuers/generate after seeding."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, vct,
		"Mobile Driving Licence (mDL)",
		&desc,
		// Standard ISO 18013-5 mDL attribute namespace: org.iso.18013.5.1
		// mapped from user profile / SPID / CIE metadata fields.
		map[string]interface{}{
			"family_name":        "last_name",
			"given_name":         "first_name",
			"birth_date":         "metadata.spid_date_of_birth",
			"document_number":    "metadata.mdl_document_number",
			"issue_date":         "metadata.mdl_issue_date",
			"expiry_date":        "metadata.mdl_expiry_date",
			"issuing_country":    "metadata.mdl_issuing_country",
			"issuing_authority":  "metadata.mdl_issuing_authority",
			"portrait":           "metadata.mdl_portrait",
			"driving_privileges": "metadata.mdl_driving_privileges",
			"age_over_18":        "metadata.mdl_age_over_18",
			"age_in_years":       "metadata.mdl_age_in_years",
			"resident_address":   "metadata.spid_address",
		},
		3*365*24*3600, // 3 years — matches a typical driving licence validity
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "already_exists",
			"doctype": vct,
		})
	}

	// Set credential_format = "mso_mdoc" so the OID4VCI issuer knows to build
	// an ISO 18013-5 IssuerSigned CBOR rather than an SD-JWT-VC.
	if err := h.repo.SetCredentialFormat(ctx, cfg.ID, orgID, "mso_mdoc"); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":            "created",
		"config_id":         cfg.ID,
		"doctype":           vct,
		"credential_format": "mso_mdoc",
		"namespace":         mdoc.NSMdl,
		"next_step":         "POST /admin/mdoc/issuers/generate with {\"doc_type\": \"" + vct + "\"} to create the DS signing keypair",
	})
}

// SeedSpidMdlPreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-spid-mdl
//
// Creates (idempotent) a pre-configured mso_mdoc credential config for the ISO
// 18013-5 mobile Driving Licence (mDL) with SPID auto-offer enabled.
//
// source_idp_type = "spid" — after every SPID login Clavex automatically creates
// a pre-authorized OID4VCI offer for the mDL credential.  The IT-Wallet client
// redeems the offer via the standard OID4VCI pre-authorized code flow.
//
// This implements the MIT (Italian Ministry of Infrastructure and Transport) use case
// described in the AgID IT-Wallet national plan: SPID L3 login → digital driving
// licence issuance as ISO 18013-5 mdoc.
//
// Claims mapping (SPID + mDL metadata → ISO 18013-5 mDL namespace):
//
//	family_name        ← last_name                   (from user profile)
//	given_name         ← first_name                  (from user profile)
//	birth_date         ← metadata.spid_date_of_birth
//	document_number    ← metadata.mdl_document_number
//	issue_date         ← metadata.mdl_issue_date
//	expiry_date        ← metadata.mdl_expiry_date
//	issuing_country    ← metadata.mdl_issuing_country
//	issuing_authority  ← metadata.mdl_issuing_authority
//	portrait           ← metadata.mdl_portrait
//	driving_privileges ← metadata.mdl_driving_privileges
//	age_over_18        ← metadata.mdl_age_over_18
//
// mdl_* fields are populated by the pre-issuance webhook or an enrichment hook
// that queries the MIT national driving licence registry (MCTC).
func (h *VerifiedCatalogHandler) SeedSpidMdlPreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	_, err = h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	vct := mdoc.DocTypeMdl
	desc := "ISO 18013-5 mobile Driving Licence (mDL) — IT-Wallet auto-offer via SPID. " +
		"Auto-issued as a pre-authorized OID4VCI offer after SPID login. " +
		"Implements the MIT IT-Wallet use case for digital driving licences. " +
		"mdl_* metadata fields must be populated via pre-issuance webhook from the MCTC registry."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, vct,
		"Mobile Driving Licence — IT-Wallet (SPID)",
		&desc,
		map[string]interface{}{
			// Identity claims from SPID (available after authentication)
			"family_name": "last_name",
			"given_name":  "first_name",
			"birth_date":  "metadata.spid_date_of_birth",
			// mDL-specific claims — populated by pre-issuance webhook from MCTC registry
			"document_number":    "metadata.mdl_document_number",
			"issue_date":         "metadata.mdl_issue_date",
			"expiry_date":        "metadata.mdl_expiry_date",
			"issuing_country":    "metadata.mdl_issuing_country",
			"issuing_authority":  "metadata.mdl_issuing_authority",
			"portrait":           "metadata.mdl_portrait",
			"driving_privileges": "metadata.mdl_driving_privileges",
			"age_over_18":        "metadata.mdl_age_over_18",
		},
		3*365*24*3600, // 3 years — typical driving licence validity
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "already_exists",
			"doctype": vct,
		})
	}

	if err := h.repo.SetCredentialFormat(ctx, cfg.ID, orgID, "mso_mdoc"); err != nil {
		return echo.ErrInternalServerError
	}

	// Link to SPID so createIdpCredentialOffers fires on every SPID login.
	spidType := "spid"
	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &spidType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":            "created",
		"config_id":         cfg.ID,
		"doctype":           vct,
		"credential_format": "mso_mdoc",
		"source_idp":        "spid",
		"next_step":         "POST /admin/mdoc/issuers/generate with {\"doc_type\": \"" + vct + "\"} to create the DS signing keypair, then configure the pre-issuance webhook to populate mdl_* metadata from the MCTC registry.",
	})
}

// SeedAgePreset handles POST /api/v1/organizations/:org_id/oid4vci/catalog/seed-age-over-18
//
// Creates (idempotent) an anonymous age attestation credential config. The issued
// SD-JWT-VC contains only one claim: age_over_18: true. No name, no fiscal code,
// no birth date, no linkable identifier — pure cryptographic proof of majority.
//
// Flow:
//  1. User authenticates via SPID/CIE (configured by `source` body field).
//  2. Clavex auto-creates a pre-authorized OID4VCI offer for this credential.
//  3. Wallet redeems the offer via the standard OID4VCI pre-auth code flow.
//  4. Clavex derives age from the IdP-verified birth date and issues the SD-JWT.
//  5. Wallet presents age_over_18 = true to a verifier (e-commerce age gate,
//     nightclub, etc.) without revealing any personal data.
//
// GDPR Art.5(1)(c): birth date is used locally for computation and NEVER written
// to the credential. The SD-JWT subject is a pairwise pseudonymous identifier.
//
// Body (optional JSON):
//
//	{"source": "spid"} — derive from SPID (default)
//	{"source": "cie"}  — derive from CIE (eIDAS High — preferred for higher assurance)
//
// To cover both IdPs: call this endpoint twice, once with "spid" and once with "cie".
func (h *VerifiedCatalogHandler) SeedAgePreset(c echo.Context) error {
	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	_, err = h.orgs.GetByID(ctx, orgID)
	if err != nil {
		return echo.ErrNotFound
	}

	var body struct {
		Source string `json:"source"`
	}
	_ = c.Bind(&body)
	if body.Source == "" {
		body.Source = "spid"
	}
	if body.Source != "spid" && body.Source != "cie" {
		return echo.NewHTTPError(http.StatusBadRequest, "source must be 'spid' or 'cie'")
	}

	// VCT: EUDIW namespace for the age-over-18 attestation type.
	// Using the EU ARF-aligned URN so wallets that understand the EU PID namespace
	// can automatically recognise and handle this credential type.
	const ageVCT = "urn:eu.europa.ec:eudiw:age_over_18:1"

	// Birth date attribute path in user metadata, populated by the IdP callback.
	var (
		birthdateAttr string
		sourceIdpType string
		displaySource string
	)
	switch body.Source {
	case "cie":
		birthdateAttr = "metadata.cie_date_of_birth"
		sourceIdpType = "cie"
		displaySource = "CIE (eIDAS High)"
	default: // "spid"
		birthdateAttr = "metadata.spid_date_of_birth"
		sourceIdpType = "spid"
		displaySource = "SPID"
	}

	desc := "Anonymous age attestation (SD-JWT-VC). Contains only age_over_18: true — no name, " +
		"no fiscal code, no birth date, no linkable identifier. Derived from " + displaySource + " verified " +
		"date of birth. Complies with GDPR Art.5(1)(c) data minimization at maximum level. " +
		"The SD-JWT subject is a pairwise pseudonymous identifier unlinkable across verifiers."

	cfg, createErr := h.repo.CreateCredentialConfig(
		ctx, orgID, ageVCT,
		"Age Attestation — Anonymous (age_over_18)",
		&desc,
		// claims_mapping: output claim → source attribute.
		// The issuance pipeline detects that all output claims are age-derived and
		// routes to IssueAgeCredential (pseudonymous sub, no org_id, no birth date).
		map[string]interface{}{
			"age_over_18": birthdateAttr,
		},
		90*24*3600, // 90-day TTL: long enough to be practical, short enough to stay accurate
		"identity",
		[]models.SchemaFieldDef{},
	)
	if createErr != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status":      "already_exists",
			"vct":         ageVCT,
			"source_idp":  sourceIdpType,
		})
	}

	if err := h.repo.SetSourceIdpType(ctx, cfg.ID, orgID, &sourceIdpType); err != nil {
		return echo.ErrInternalServerError
	}

	return c.JSON(http.StatusCreated, map[string]any{
		"status":     "created",
		"config_id":  cfg.ID,
		"vct":        ageVCT,
		"source_idp": sourceIdpType,
		"claims":     []string{"age_over_18"},
		"privacy":    "GDPR Art.5(1)(c) — birth date computed locally, never written to credential. Pseudonymous sub.",
	})
}
