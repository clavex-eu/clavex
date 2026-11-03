package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestStatusListUsesConfiguredCertificateAndNeverFallsBackOnFailure(t *testing.T) {
	f := vciFixture(t)
	issuance, tx, err := f.h.beginCredentialIssuance(context.Background(), nil, "")
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	id, _, err := issuance.repo.AllocateCredentialStatus(context.Background(), f.org.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(context.Background()))
	request := func() *httptest.ResponseRecorder {
		e := echo.New()
		r := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), r)
		c.SetParamNames("org_slug", "list_id")
		c.SetParamValues(f.org.Slug, id.String())
		if err := f.h.StatusList(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return r
	}
	r := request()
	require.Equal(t, 200, r.Code)
	legacy, err := jws.Parse(r.Body.Bytes())
	require.NoError(t, err)
	require.NotNil(t, legacy.Signatures()[0].ProtectedHeaders().JWK())
	chain, key := testWalletCertificateFiles(t)
	f.h.WithCredentialSigningFiles(chain, key)
	require.NoError(t, f.h.credentialSigningErr)
	r = request()
	require.Equal(t, 200, r.Code)
	message, err := jws.Parse(r.Body.Bytes())
	require.NoError(t, err)
	require.Equal(t, 1, message.Signatures()[0].ProtectedHeaders().X509CertChain().Len())
	require.NotEqual(t, f.h.keys.KID(), message.Signatures()[0].ProtectedHeaders().KeyID())
	_, err = jwt.Parse(r.Body.Bytes(), jwt.WithKey(f.h.credentialSigner.Algorithm(), f.h.credentialSigner.CryptoSigner().Public()))
	require.NoError(t, err)
	previous := f.h.cfg
	f.h.cfg = StaticBaseURL("https://wrong.example")
	r = request()
	require.Equal(t, 503, r.Code, "certificate must cover the configured issuer host")
	f.h.cfg = previous
	f.h.WithCredentialSigningFiles("/missing/certificate", "/missing/key")
	r = request()
	require.Equal(t, 503, r.Code)
}
