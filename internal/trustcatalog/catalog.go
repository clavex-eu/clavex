// Package trustcatalog contains public, pinned development trust material.
// Reading this catalogue never installs trust anchors or fetches remote keys.
package trustcatalog

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed eudi-reference-test.json
var referenceData []byte

type Authority struct {
	ID                string    `json:"id"`
	Label             string    `json:"label"`
	Country           string    `json:"country"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
	PEM               string    `json:"pem"`
	DocTypes          []string  `json:"doc_types"`
	SourceURL         string    `json:"source_url"`
	SubjectDN         string    `json:"subject_dn"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

type Catalog struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Environment     string      `json:"environment"`
	ReferenceCommit string      `json:"reference_commit"`
	Entries         []Authority `json:"entries"`
}

var (
	once    sync.Once
	cached  Catalog
	loadErr error
)

// Reference returns a copy of the bundled catalogue. This is a development
// reference profile, not a national production trust list or certification.
func Reference() (Catalog, error) {
	once.Do(func() { cached, loadErr = parse(referenceData) })
	if loadErr != nil {
		return Catalog{}, loadErr
	}
	out := cached
	out.Entries = append([]Authority(nil), cached.Entries...)
	for i := range out.Entries {
		out.Entries[i].DocTypes = append([]string(nil), out.Entries[i].DocTypes...)
	}
	return out, nil
}

func parse(raw []byte) (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return Catalog{}, err
	}
	if c.ID != "eudi-reference-test" || c.Environment != "test" || len(c.ReferenceCommit) != 40 || len(c.Entries) == 0 || len(c.Entries) > 64 {
		return Catalog{}, fmt.Errorf("invalid development trust catalogue")
	}
	seen := map[string]bool{}
	for i := range c.Entries {
		a := &c.Entries[i]
		block, rest := pem.Decode([]byte(a.PEM))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return Catalog{}, fmt.Errorf("invalid catalogue certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) != nil {
			return Catalog{}, fmt.Errorf("invalid catalogue authority")
		}
		hash := sha256.Sum256(cert.Raw)
		if a.SHA256Fingerprint != hex.EncodeToString(hash[:]) || seen[a.SHA256Fingerprint] || a.ID == "" || seen[a.ID] {
			return Catalog{}, fmt.Errorf("catalogue identity or fingerprint mismatch")
		}
		seen[a.ID], seen[a.SHA256Fingerprint] = true, true
		prefix := "https://github.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/blob/" + c.ReferenceCommit + "/resources-logic/src/main/res/raw/"
		if !strings.HasPrefix(a.SourceURL, prefix) || len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != a.Country || len(a.DocTypes) == 0 {
			return Catalog{}, fmt.Errorf("catalogue provenance or scope mismatch")
		}
		for _, kind := range a.DocTypes {
			if kind != "org.iso.18013.5.1.mDL" && kind != "eu.europa.ec.eudi.pid.1" {
				return Catalog{}, fmt.Errorf("unsupported catalogue document scope")
			}
		}
		a.SubjectDN, a.NotBefore, a.NotAfter = cert.Subject.String(), cert.NotBefore, cert.NotAfter
	}
	return c, nil
}
