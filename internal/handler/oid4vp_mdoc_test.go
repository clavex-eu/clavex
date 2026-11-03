package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/mdoc"
	"github.com/clavex-eu/clavex/internal/models"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func verifierMdoc(t *testing.T, session *models.PresentationSession, extra ...map[string]interface{}) (string, string) {
	t.Helper()
	rootKey, dsKey, device := vciTestHolder(t), vciTestHolder(t), vciTestHolder(t)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	dsTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, root, &dsKey.PublicKey, rootKey)
	require.NoError(t, err)
	attributes := map[string]interface{}{"given_name": "Alice"}
	for _, values := range extra {
		for k, v := range values {
			attributes[k] = v
		}
	}
	issued, err := mdoc.IssueMdoc(mdoc.IssuanceParams{DocType: mdoc.DocTypeEuPid, Namespace: mdoc.NSEuPid, Attributes: attributes, DSKey: dsKey, DSCertDER: dsDER, DevicePublicKey: &device.PublicKey})
	require.NoError(t, err)
	var issuerSigned mdoc.IssuerSigned
	require.NoError(t, cbor.Unmarshal(issued, &issuerSigned))
	doc := mdoc.Document{DocType: mdoc.DocTypeEuPid, IssuerSigned: issuerSigned}
	namespaces, err := cbor.Marshal(map[string]any{})
	require.NoError(t, err)
	doc.DeviceSigned.NameSpaces, err = cbor.Marshal(cbor.Tag{Number: 24, Content: namespaces})
	require.NoError(t, err)
	transcript, err := mdoc.BuildRedirectSessionTranscript(session.ClientID, session.ResponseURI, session.Nonce, session.ResponseKeyThumbprint)
	require.NoError(t, err)
	// Independent construction of the detached payload used by a wallet.
	auth, err := cbor.Marshal([]any{"DeviceAuthentication", cbor.RawMessage(transcript), doc.DocType, doc.DeviceSigned.NameSpaces})
	require.NoError(t, err)
	authBytes, err := cbor.Marshal(cbor.Tag{Number: 24, Content: auth})
	require.NoError(t, err)
	protected, err := cbor.Marshal(map[int]int{1: -7})
	require.NoError(t, err)
	structure, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, authBytes})
	require.NoError(t, err)
	digest := sha256.Sum256(structure)
	r, s, err := ecdsa.Sign(rand.Reader, device, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	doc.DeviceSigned.DeviceAuth.DeviceSignature, err = cbor.Marshal([]any{protected, map[int]any{}, nil, signature})
	require.NoError(t, err)
	response, err := cbor.Marshal(mdoc.DeviceResponse{Version: "1.0", Documents: []mdoc.Document{doc}})
	require.NoError(t, err)
	envelope, err := json.Marshal(map[string][]string{"identity": {base64.RawURLEncoding.EncodeToString(response)}})
	require.NoError(t, err)
	return string(envelope), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
}

func TestMdocVerifierHTTPRequiresTenantRootQueryAndDeviceBinding(t *testing.T) {
	f := vciFixture(t)
	h := NewOID4VPHandler(f.pool, f.h.keys, f.h.cfg, nil, true, nil, "", "")
	query := map[string]interface{}{"credentials": []any{map[string]any{"id": "identity", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}, "claims": []any{map[string]any{"path": []string{mdoc.NSEuPid, "given_name"}}}}}}
	requestID := uuid.NewString()
	session, err := h.repo.CreatePresentationSession(context.Background(), f.org.ID, requestID, nil, query, "https://verifier.example/response", nil, nil, "challenge", time.Now().Add(time.Minute), nil, "redirect_uri:https://verifier.example/response")
	require.NoError(t, err)
	encoded, root := verifierMdoc(t, session)
	_, err = h.verifyMdocDCQLVPToken(context.Background(), encoded, session, session.ClientID)
	require.Error(t, err, "no implicit trust in supplied certificates")
	configured, err := h.iacaRepo.Create(context.Background(), f.org.ID, "Test IACA", root, []string{"different-document"}, nil)
	require.NoError(t, err)
	_, err = h.verifyMdocDCQLVPToken(context.Background(), encoded, session, session.ClientID)
	require.Error(t, err, "root policy must permit this document type")
	_, err = f.pool.Exec(context.Background(), `UPDATE org_iaca_roots SET doc_types=$1 WHERE id=$2`, []string{mdoc.DocTypeEuPid}, configured.ID)
	require.NoError(t, err)
	_, err = h.verifyMdocDCQLVPToken(context.Background(), encoded, session, session.ClientID)
	require.NoError(t, err)
	copy := *session
	copy.Nonce = "other-session"
	_, err = h.verifyMdocDCQLVPToken(context.Background(), encoded, &copy, copy.ClientID)
	require.Error(t, err)
	invoke := func() *httptest.ResponseRecorder {
		e := echo.New()
		rec := httptest.NewRecorder()
		form := url.Values{"vp_token": {encoded}, "state": {requestID}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		c := e.NewContext(req, rec)
		c.SetParamNames("org_slug")
		c.SetParamValues(f.org.Slug)
		if err := h.Response(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		return rec
	}
	rec := invoke()
	require.Equal(t, 200, rec.Code, rec.Body.String())
	rec = invoke()
	require.Equal(t, 400, rec.Code, rec.Body.String())
	copy = *session
	copy.DCQLQuery = map[string]interface{}{"credentials": []any{map[string]any{"id": "identity", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": mdoc.DocTypeEuPid}, "claims": []any{map[string]any{"path": []string{mdoc.NSEuPid, "missing_required_claim"}}}}}}
	_, err = h.verifyMdocDCQLVPToken(context.Background(), encoded, &copy, copy.ClientID)
	require.Error(t, err)
}
