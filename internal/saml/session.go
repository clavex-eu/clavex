package saml

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/clavex-eu/clavex/internal/session"
	"github.com/google/uuid"
)

// SAMLLoginSession stores in-flight SAML authn state in Redis.
type SAMLLoginSession struct {
	ID         string    `json:"id"`
	OrgSlug    string    `json:"org_slug"`
	OrgID      string    `json:"org_id"`
	RequestID  string    `json:"request_id"`
	RelayState string    `json:"relay_state"`
	ACSURL     string    `json:"acs_url"`
	CreatedAt  time.Time `json:"created_at"`
}

// GetID satisfies the session.Store.SaveSAMLLoginSession interface requirement.
func (s *SAMLLoginSession) GetID() string { return s.ID }

// LoginSessionProvider implements saml.SessionProvider.
// When no live session exists it renders the login form and returns nil;
// the handler will call ServeSSO again after the user authenticates.
type LoginSessionProvider struct {
	OrgSlug   string
	OrgID     uuid.UUID
	OrgName   string
	LogoURL   *string
	Store     *session.Store
	Users     *repository.UserRepository
	LoginTmpl *template.Template
	Nonce     string // per-request CSP nonce (set by handler from echo context)
}

// GetSession is called by crewjam/saml on every SSO request.
// It must either return a populated *saml.Session or complete the HTTP
// response itself (redirect to login / render form) and return nil.
func (p *LoginSessionProvider) GetSession(
	w http.ResponseWriter,
	r *http.Request,
	req *saml.IdpAuthnRequest,
) *saml.Session {
	ctx := r.Context()

	// Check if this is a POST from the login form.
	if r.Method == http.MethodPost {
		sessID := r.FormValue("saml_login_session_id")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if sessID != "" && email != "" && password != "" {
			raw, err := p.Store.GetSAMLLoginSession(ctx, sessID)
			if err == nil && raw != nil {
				var loginSess SAMLLoginSession
				if json.Unmarshal(raw, &loginSess) == nil {
					user, err := p.Users.GetByEmail(ctx, p.OrgID, email)
					if err == nil && user.IsActive &&
						user.PasswordHash != nil &&
						p.Users.CheckPassword(*user.PasswordHash, password) {

						_ = p.Store.DeleteSAMLLoginSession(ctx, sessID)

						roles, _ := p.Users.ListRolesByUser(ctx, user.ID)
						groups := make([]string, 0, len(roles))
						for _, ro := range roles {
							groups = append(groups, ro.Name)
						}

						return &saml.Session{
							ID:            uuid.NewString(),
							CreateTime:    time.Now(),
							ExpireTime:    time.Now().Add(8 * time.Hour),
							Index:         uuid.NewString(),
							NameID:        user.Email,
							NameIDFormat:  "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress",
							UserName:      user.Email,
							UserEmail:     user.Email,
							UserGivenName: safeStr(user.FirstName),
							UserSurname:   safeStr(user.LastName),
							Groups:        groups,
						}
					}
				}
			}
			// Invalid credentials — re-render form with error
			p.renderLoginForm(w, r, sessID, email, "Invalid email or password.")
			return nil
		}
	}

	// No session yet — save the in-flight SAML state and render login form.
	sessID := uuid.NewString()
	loginSess := &SAMLLoginSession{
		ID:         sessID,
		OrgSlug:    p.OrgSlug,
		OrgID:      p.OrgID.String(),
		RequestID:  req.Request.ID,
		RelayState: req.RelayState,
		CreatedAt:  time.Now(),
	}
	_ = p.Store.SaveSAMLLoginSession(ctx, loginSess, 10*time.Minute)

	p.renderLoginForm(w, r, sessID, "", "")
	return nil
}

type samlLoginData struct {
	OrgName       string
	LogoURL       *string
	SAMLSessionID string
	Email         string
	Error         string
	Nonce         string // CSP nonce
}

func (p *LoginSessionProvider) renderLoginForm(w http.ResponseWriter, r *http.Request, sessID, email, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = p.LoginTmpl.Execute(w, samlLoginData{
		OrgName:       p.OrgName,
		LogoURL:       p.LogoURL,
		SAMLSessionID: sessID,
		Email:         email,
		Error:         errMsg,
		Nonce:         p.Nonce,
	})
}

// ── SLO helper ────────────────────────────────────────────────────────────────

// BuildLogoutResponse constructs the redirect URL for a SAML SLO response.
func BuildLogoutResponse(sloURL, relayState string) string {
	u, _ := url.Parse(sloURL)
	if relayState != "" {
		q := u.Query()
		q.Set("RelayState", relayState)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
