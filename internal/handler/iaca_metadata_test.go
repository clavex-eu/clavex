package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clavex-eu/clavex/internal/models"
	"github.com/clavex-eu/clavex/internal/trustcatalog"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestIACAMetadataDoesNotExposeLegacyTrailingMaterial(t *testing.T) {
	catalog, err := trustcatalog.Reference()
	require.NoError(t, err)
	a := catalog.Entries[0]
	raw := a.PEM + "-----BEGIN PRIVATE KEY-----\nlegacy-private-material\n-----END PRIVATE KEY-----\n"
	root := &models.OrgIACARoot{PEM: raw, SHA256Fingerprint: a.SHA256Fingerprint, IsActive: true}
	view := iacaResponse(root)
	require.True(t, view.CertificateWarning)
	require.False(t, view.CertificateError)
	require.NotNil(t, view.NotAfter)
	require.Equal(t, a.PEM, view.PEM)
	require.Equal(t, raw, root.PEM, "formatting a response must not mutate tenant records")
	body, err := json.Marshal(view)
	require.NoError(t, err)
	require.NotContains(t, string(body), "PRIVATE KEY")
	require.NotContains(t, string(body), "legacy-private-material")
	root.PEM = "invalid stored material"
	view = iacaResponse(root)
	require.True(t, view.CertificateError)
	require.Empty(t, view.PEM)
	// Fingerprint corruption is visible without being silently corrected.
	root.PEM = a.PEM
	hash := sha256.Sum256([]byte("wrong"))
	root.SHA256Fingerprint = hex.EncodeToString(hash[:])
	require.True(t, iacaResponse(root).CertificateError)
}

func TestIACACatalogReadRequiresAnOrgAndDoesNotUseTheDatabase(t *testing.T) {
	e := echo.New()
	h := NewIACAHandler(nil)
	req := httptest.NewRequest("GET", "/catalog", nil)
	response := httptest.NewRecorder()
	c := e.NewContext(req, response)
	c.SetParamNames("org_id")
	c.SetParamValues(uuid.NewString())
	require.NoError(t, h.Catalog(c))
	require.Equal(t, 200, response.Code)
	var catalog trustcatalog.Catalog
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &catalog))
	require.Equal(t, "test", catalog.Environment)
	require.Len(t, catalog.Entries, 7)
	require.NotContains(t, response.Body.String(), "PRIVATE KEY")
	c.SetParamValues(strings.Repeat("x", 36))
	require.Error(t, h.Catalog(c))
}
