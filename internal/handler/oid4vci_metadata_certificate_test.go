package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestConfiguredMetadataCertificateFailsClosedBeforeDatabaseAccess(t *testing.T) {
	for _, accept := range []string{"application/jwt", "application/json", ""} {
		e := echo.New()
		h := NewOID4VCIHandler(nil, nil, nil).WithMetadataSigningFiles("missing-certificate", "missing-key")
		req := httptest.NewRequest(http.MethodGet, "/metadata", nil)
		req.Header.Set("Accept", accept)
		err := h.IssuerMetadata(e.NewContext(req, httptest.NewRecorder()))
		var httpErr *echo.HTTPError
		require.ErrorAs(t, err, &httpErr)
		require.Equal(t, http.StatusServiceUnavailable, httpErr.Code)
		require.Equal(t, "issuer metadata signing is misconfigured", httpErr.Message)
	}
}
