package handler

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"

	"github.com/clavex-eu/clavex/internal/models"
)

type iacaRootResponse struct {
	*models.OrgIACARoot
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	CertificateWarning bool       `json:"certificate_warning,omitempty"`
	CertificateError   bool       `json:"certificate_error,omitempty"`
}

func iacaResponse(root *models.OrgIACARoot) iacaRootResponse {
	copyRoot := *root
	// Existing records may predate strict upload validation. Never echo extra
	// PEM blocks, private material or arbitrary text stored with a certificate.
	copyRoot.PEM = ""
	view := iacaRootResponse{OrgIACARoot: &copyRoot}
	block, rest := pem.Decode([]byte(root.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		view.CertificateError = true
		return view
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		view.CertificateError = true
		return view
	}
	copyRoot.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	view.CertificateWarning = len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || !bytes.HasPrefix(bytes.TrimSpace([]byte(root.PEM)), []byte("-----BEGIN CERTIFICATE-----"))
	hash := sha256.Sum256(cert.Raw)
	view.CertificateError = root.SHA256Fingerprint != hex.EncodeToString(hash[:]) || !cert.IsCA
	view.NotBefore, view.NotAfter = &cert.NotBefore, &cert.NotAfter
	return view
}
