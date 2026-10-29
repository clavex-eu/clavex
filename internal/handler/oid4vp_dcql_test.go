package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/oid4w"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func dcqlSession(t *testing.T, f cibaWalletFixture, query map[string]interface{}) (*models.PresentationSession, string) {
	t.Helper()
	session, auth := f.request(t, false)
	encoded, err := json.Marshal(query)
	require.NoError(t, err)
	_, err = f.pool.Exec(context.Background(), `UPDATE identity.presentation_sessions SET dcql_query=$2 WHERE request_id=$1`, session.RequestID, encoded)
	require.NoError(t, err)
	session.DCQLQuery = query
	return session, auth
}
func submitDCQL(t *testing.T, f cibaWalletFixture, session *models.PresentationSession, envelope map[string][]string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(envelope)
	require.NoError(t, err)
	form := url.Values{"state": {session.RequestID}, "vp_token": {string(encoded)}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	e := echo.New()
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("org_slug")
	c.SetParamValues(f.org.Slug)
	if err := f.h.Response(c); err != nil {
		e.HTTPErrorHandler(err, c)
	}
	return rec
}
func twoCredentialQuery(vct string, multiple bool) map[string]interface{} {
	first := map[string]any{"id": "first", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{vct}}}
	if multiple {
		first["multiple"] = true
		return map[string]interface{}{"credentials": []any{first}}
	}
	second := map[string]any{"id": "second", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{vct}}}
	return map[string]interface{}{"credentials": []any{first, second}}
}
func TestDCQLCIBAAllCredentialsAccountStatusAndProjection(t *testing.T) {
	for _, scenario := range []string{"same_account", "missing_second", "second_revoked", "different_account", "untrusted_second", "multiple_instances", "multiple_bad_instance"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCibaWalletFixture(t)
			ctx := context.Background()
			_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{}' WHERE id=$1`, f.org.ID)
			require.NoError(t, err)
			raw1, key1, _ := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
			subject := f.user.ID
			if scenario == "different_account" {
				other, err := f.vciIssuanceFixture.h.users.Create(ctx, f.org.ID, "different@example.test", nil, nil)
				require.NoError(t, err)
				subject = other.ID
			}
			raw2, key2, record2 := issueStatusCredential(t, f.vciIssuanceFixture, &subject)
			if scenario == "second_revoked" || scenario == "multiple_bad_instance" {
				require.NoError(t, f.vciIssuanceFixture.h.repo.RevokeIssuedCredential(ctx, record2.ID, "test"))
			}
			multiple := strings.HasPrefix(scenario, "multiple_")
			session, auth := dcqlSession(t, f, twoCredentialQuery(f.cfg.VCT, multiple))
			p1 := presentStatusCredential(t, raw1, key1, session.Nonce, session.ClientID, false)
			p2 := presentStatusCredential(t, raw2, key2, session.Nonce, session.ClientID, false)
			if scenario == "untrusted_second" {
				p2 = accountVP(t, f.vciIssuanceFixture.h.keys.PrivateKey(), "https://untrusted.example", f.user.ID.String(), f.cfg.VCT, session.Nonce, session.ClientID, nil, true)
			}
			envelope := map[string][]string{"first": {p1}, "second": {p2}}
			if multiple {
				envelope = map[string][]string{"first": {p1, p2}}
			}
			if scenario == "missing_second" {
				delete(envelope, "second")
			}
			rec := submitDCQL(t, f, session, envelope)
			approved, err := f.ciba.Get(ctx, auth)
			require.NoError(t, err)
			if scenario != "same_account" && scenario != "multiple_instances" {
				require.Equal(t, 400, rec.Code, rec.Body.String())
				require.Equal(t, "pending", approved.Status)
				return
			}
			require.Equal(t, 200, rec.Code, rec.Body.String())
			require.Equal(t, "approved", approved.Status)
			require.NotContains(t, approved.VPClaims, "given_name", "attributes must remain namespaced instead of last-writer-wins")
			entries, ok := approved.VPClaims["_clavex_presentations"].([]interface{})
			require.True(t, ok)
			require.Len(t, entries, 2)
			require.Equal(t, "per_credential", approved.VPClaims["_clavex_credential_status"])
			rec = submitDCQL(t, f, session, envelope)
			require.Equal(t, 400, rec.Code)
		})
	}
}

func TestDCQLCredentialSetsOptionalBadCredentialStillRejected(t *testing.T) {
	for _, includeBad := range []bool{false, true} {
		t.Run(map[bool]string{false: "optional_omitted", true: "optional_revoked"}[includeBad], func(t *testing.T) {
			f := newCibaWalletFixture(t)
			ctx := context.Background()
			_, err := f.pool.Exec(ctx, `UPDATE identity.organizations SET settings='{}' WHERE id=$1`, f.org.ID)
			require.NoError(t, err)
			good, key, _ := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
			bad, badKey, record := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
			require.NoError(t, f.vciIssuanceFixture.h.repo.RevokeIssuedCredential(ctx, record.ID, "test"))
			q := twoCredentialQuery(f.cfg.VCT, false)
			optional := map[string]any{"id": "optional", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{f.cfg.VCT}}}
			q["credentials"] = append(q["credentials"].([]any), optional)
			q["credential_sets"] = []any{map[string]any{"options": [][]string{{"first"}, {"second"}}}, map[string]any{"required": false, "options": [][]string{{"optional"}}}}
			session, auth := dcqlSession(t, f, q)
			envelope := map[string][]string{"second": {presentStatusCredential(t, good, key, session.Nonce, session.ClientID, false)}}
			if includeBad {
				envelope["optional"] = []string{presentStatusCredential(t, bad, badKey, session.Nonce, session.ClientID, false)}
			}
			rec := submitDCQL(t, f, session, envelope)
			approved, err := f.ciba.Get(ctx, auth)
			require.NoError(t, err)
			if includeBad {
				require.Equal(t, 400, rec.Code, rec.Body.String())
				require.Equal(t, "pending", approved.Status)
			} else {
				require.Equal(t, 200, rec.Code, rec.Body.String())
				require.Equal(t, "approved", approved.Status)
			}
		})
	}
}

func TestDCQLMixedMdocAndSDJWTRequireAccountBindingForBoth(t *testing.T) {
	f := newCibaWalletFixture(t)
	ctx := context.Background()
	raw, key, _ := issueStatusCredential(t, f.vciIssuanceFixture, &f.user.ID)
	query := twoCredentialQuery(f.cfg.VCT, false)
	query["credentials"].([]any)[1] = map[string]any{"id": "mdoc", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}}
	session, auth := dcqlSession(t, f, query)
	encoded, root := verifierMdoc(t, session, map[string]interface{}{"test_stable_id": "synthetic-mixed-subject"})
	_, err := f.h.iacaRepo.Create(ctx, f.org.ID, "mixed IACA", root, []string{mdoc.DocTypeEuPid}, nil)
	require.NoError(t, err)
	var envelope map[string][]string
	require.NoError(t, json.Unmarshal([]byte(encoded), &envelope))
	single := *session
	single.DCQLQuery = map[string]interface{}{"credentials": []any{map[string]any{"id": "identity", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}}}}
	verified, err := f.h.verifyMdocDCQLVPToken(ctx, encoded, &single, session.ClientID)
	require.NoError(t, err)
	profile := oid4w.WalletIdentityProfile{Format: "mso_mdoc", Issuer: verified.Identity.Issuer, CredentialType: mdoc.DocTypeEuPid, ClaimPath: []string{mdoc.NSEuPid, "test_stable_id"}}
	settings, err := json.Marshal(map[string]any{"wallet_status_required": false, "wallet_certificate_revocation_required": false, "wallet_identity_profiles": []any{profile}})
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE identity.organizations SET settings=$2 WHERE id=$1`, f.org.ID, settings)
	require.NoError(t, err)
	presented := map[string][]string{"first": {presentStatusCredential(t, raw, key, session.Nonce, session.ClientID, false)}, "mdoc": envelope["identity"]}
	// A perfectly valid mdoc cannot approve an account before its independently
	// verified identifier is linked, even though the SD-JWT matches the account.
	combined, err := json.Marshal(presented)
	require.NoError(t, err)
	result, err := f.h.verifyDCQLResponse(ctx, string(combined), session, session.ClientID)
	require.NoError(t, err)
	require.ErrorIs(t, f.h.completeBoundCIBA(ctx, session.RequestID, f.org.ID, result), errWalletIdentityMismatch)
	digest, err := profile.Digest(f.org.ID.String(), "synthetic-mixed-subject")
	require.NoError(t, err)
	_, err = repository.NewWalletIdentityRepository(f.pool).Create(ctx, repository.WalletIdentityLink{OrgID: f.org.ID, UserID: f.user.ID, Format: profile.Format, Issuer: profile.Issuer, CredentialType: profile.CredentialType, ClaimPath: profile.ClaimPath, SubjectDigest: digest})
	require.NoError(t, err)
	rec := submitDCQL(t, f, session, presented)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	approved, err := f.ciba.Get(ctx, auth)
	require.NoError(t, err)
	require.Equal(t, "approved", approved.Status)
}
