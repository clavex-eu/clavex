package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

func TestIssueMdocMdlDigestsAndMandatory(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "clavex-ds"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	dsCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &dsKey.PublicKey, dsKey)
	if err != nil {
		t.Fatal(err)
	}

	attrs := map[string]interface{}{
		"family_name": "User",
		"given_name":  "Test",
		"birth_date":  "1990-01-01",
	}
	FillMdlMandatory(attrs)

	out, err := IssueMdoc(IssuanceParams{
		DocType:    DocTypeMdl,
		Namespace:  NSMdl,
		Attributes: attrs,
		DSKey:      dsKey,
		DSCertDER:  dsCertDER,
	})
	if err != nil {
		t.Fatal(err)
	}

	var is IssuerSigned
	if err := cbor.Unmarshal(out, &is); err != nil {
		t.Fatalf("decode IssuerSigned: %v", err)
	}

	// Decode MSO out of issuerAuth COSE_Sign1: [prot, unprot, payload(bstr), sig].
	var cose []cbor.RawMessage
	if err := cbor.Unmarshal(is.IssuerAuth, &cose); err != nil {
		t.Fatalf("decode COSE_Sign1: %v", err)
	}
	var payloadBstr []byte // = tag24(bstr(MSO)) bytes
	if err := cbor.Unmarshal(cose[2], &payloadBstr); err != nil {
		t.Fatalf("decode payload bstr: %v", err)
	}
	var taggedMSO cbor.Tag
	if err := cbor.Unmarshal(payloadBstr, &taggedMSO); err != nil {
		t.Fatalf("decode tag24 MSO: %v", err)
	}
	msoBytes, _ := taggedMSO.Content.([]byte)
	var mso MSO
	if err := cbor.Unmarshal(msoBytes, &mso); err != nil {
		t.Fatalf("decode MSO: %v", err)
	}

	// validityInfo must have parsed as tdate (would error above if bare ints
	// were unparseable into time.Time — they decode, but assert sanity).
	if mso.ValidityInfo.ValidUntil.Before(mso.ValidityInfo.ValidFrom) {
		t.Fatalf("validUntil before validFrom")
	}

	// Every emitted IssuerSignedItem must hash to a digest present in the MSO.
	dm := mso.ValueDigests[NSMdl]
	if len(dm) == 0 {
		t.Fatal("no digests for mDL namespace")
	}
	digestSet := map[[32]byte]bool{}
	for _, d := range dm {
		var k [32]byte
		copy(k[:], d)
		digestSet[k] = true
	}
	present := map[string]bool{}
	for _, raw := range is.NameSpaces[NSMdl] {
		h := sha256.Sum256(raw) // raw = #6.24(bstr) IssuerSignedItemBytes
		if !digestSet[h] {
			t.Fatalf("emitted item digest not found in MSO")
		}
		// decode element identifier for presence check
		var tag cbor.Tag
		if err := cbor.Unmarshal(raw, &tag); err != nil {
			t.Fatal(err)
		}
		inner, _ := tag.Content.([]byte)
		var item IssuerSignedItem
		if err := cbor.Unmarshal(inner, &item); err != nil {
			t.Fatal(err)
		}
		present[item.ElementIdentifier] = true
	}

	mandatory := []string{
		"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
		"issuing_country", "issuing_authority", "document_number", "portrait",
		"driving_privileges", "un_distinguishing_sign",
	}
	for _, m := range mandatory {
		if !present[m] {
			t.Errorf("mandatory element missing: %s", m)
		}
	}
}
