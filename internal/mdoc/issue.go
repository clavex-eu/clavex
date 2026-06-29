package mdoc

// issue.go implements the ISO 18013-5 mdoc issuance pipeline.
//
// High-level flow:
//
//  1. For each attribute, build an IssuerSignedItem with random salt.
//  2. Compute DigestMap: digestID → SHA-256(CBOR(bstr(itemCBOR))).
//  3. Build the MSO (Mobile Security Object) embedding the DigestMap,
//     DeviceKeyInfo (holder's public key), docType, and validity.
//  4. Sign the MSO as COSE_Sign1 with the Document Signer (DS) private key.
//  5. Assemble IssuerSigned = {nameSpaces, issuerAuth}.
//  6. Return the CBOR-encoded IssuerSigned bytes.
//
// The returned bytes are used directly as the "credential" field in the
// OID4VCI credential response when format = "mso_mdoc".

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

// mdocEncMode encodes time.Time as an ISO 8601 tdate (#6.0(tstr), RFC 3339)
// rather than fxamacker's default bare Unix integer. ISO 18013-5 §9.1.2.4
// requires MSO ValidityInfo (signed/validFrom/validUntil) to be tdate; a bare
// integer fails parsers expecting getAsDateTimeString (e.g. multipaz).
var mdocEncMode, _ = cbor.EncOptions{
	Time:    cbor.TimeRFC3339,
	TimeTag: cbor.EncTagRequired,
}.EncMode()

// IssuanceParams contains everything needed to issue an mdoc credential.
type IssuanceParams struct {
	// DocType identifies the credential type.
	// e.g. "org.iso.18013.5.1.mDL" or "eu.europa.ec.eudi.pid.1".
	DocType string
	// Namespace is the primary attribute namespace.
	// e.g. "org.iso.18013.5.1" for mDL, "eu.europa.ec.eudi.pid.1" for PID.
	Namespace string
	// Attributes maps element identifiers to Go values.
	// Values are CBOR-encoded using fxamacker defaults (strings, ints, bools,
	// time.Time → tdate, []byte → bstr, etc.).
	Attributes map[string]interface{}
	// DSKey is the Document Signer ECDSA private key (P-256 recommended).
	DSKey *ecdsa.PrivateKey
	// DSCertDER is the DER-encoded Document Signer certificate.
	// It is embedded in the IssuerAuth COSE_Sign1 x5chain protected header.
	DSCertDER []byte
	// DevicePublicKey is the wallet holder's EC public key extracted from the
	// OID4VCI proof JWT "jwk" header. It is bound into the MSO DeviceKeyInfo
	// so the wallet can prove possession during proximity presentation.
	// Pass nil to skip key binding (useful for test/batch issuance).
	DevicePublicKey *ecdsa.PublicKey
	// ValidityHours is the MSO validity window (default 720 = 30 days).
	ValidityHours int
}

// IssueMdoc builds and returns the CBOR-encoded IssuerSigned bytes for one mdoc.
// These bytes are base64url-encoded and returned as the OID4VCI "credential" field.
func IssueMdoc(p IssuanceParams) ([]byte, error) {
	if p.ValidityHours <= 0 {
		p.ValidityHours = 720
	}
	// Truncate to hour boundary — RFC 9901 §10.1 linkability prevention.
	now := time.Now().UTC().Truncate(time.Hour)
	validUntil := now.Add(time.Duration(p.ValidityHours) * time.Hour)

	// ── 1. Build IssuerSignedItems ────────────────────────────────────────────
	type itemEntry struct {
		digestID uint
		// taggedBytes is the IssuerSignedItemBytes = #6.24(bstr .cbor
		// IssuerSignedItem). Per ISO 18013-5 §9.1.2.5 the MSO digest is computed
		// over exactly these bytes, and these same bytes are emitted in
		// nameSpaces — so digest input and transmitted item must be identical.
		taggedBytes []byte
	}
	entries := make([]itemEntry, 0, len(p.Attributes))
	digestID := uint(0)
	for name, val := range p.Attributes {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("mdoc issue: random salt: %w", err)
		}
		valueCBOR, err := mdocEncMode.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("mdoc issue: marshal attribute %q: %w", name, err)
		}
		item := IssuerSignedItem{
			DigestID:          digestID,
			Random:            salt,
			ElementIdentifier: name,
			ElementValue:      cbor.RawMessage(valueCBOR),
		}
		itemCBOR, err := cbor.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("mdoc issue: encode IssuerSignedItem %q: %w", name, err)
		}
		// Wrap as #6.24(bstr(itemCBOR)) — the IssuerSignedItemBytes.
		bstrCBOR, err := cbor.Marshal(itemCBOR)
		if err != nil {
			return nil, fmt.Errorf("mdoc issue: bstr-wrap item %q: %w", name, err)
		}
		tagged, err := cbor.Marshal(cbor.RawTag{Number: tagCBORByteString, Content: bstrCBOR})
		if err != nil {
			return nil, fmt.Errorf("mdoc issue: tag-24 item %q: %w", name, err)
		}
		entries = append(entries, itemEntry{digestID, tagged})
		digestID++
	}

	// ── 2. Build DigestMap ────────────────────────────────────────────────────
	// Per ISO 18013-5 §9.1.2.5 each digest covers the IssuerSignedItemBytes
	// (#6.24-tagged), i.e. the exact bytes emitted in nameSpaces:
	// digest = SHA-256(IssuerSignedItemBytes).
	digestMap := make(DigestMap, len(entries))
	for _, e := range entries {
		h := sha256.Sum256(e.taggedBytes)
		digestMap[e.digestID] = h[:]
	}

	// ── 3. Build DeviceKeyInfo ────────────────────────────────────────────────
	var deviceKeyInfo DeviceKeyInfo
	if p.DevicePublicKey != nil {
		coseKey, err := ecPublicKeyToCOSE(p.DevicePublicKey)
		if err != nil {
			return nil, fmt.Errorf("mdoc issue: encode device key: %w", err)
		}
		deviceKeyInfo.DeviceKey = coseKey
	}

	// ── 4. Build and sign MSO ─────────────────────────────────────────────────
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]DigestMap{p.Namespace: digestMap},
		DeviceKeyInfo:   deviceKeyInfo,
		DocType:         p.DocType,
		ValidityInfo: ValidityInfo{
			Signed:    now,
			ValidFrom: now,
			ValidUntil: validUntil,
		},
	}
	msoCBOR, err := mdocEncMode.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("mdoc issue: encode MSO: %w", err)
	}
	issuerAuth, err := signMSO(msoCBOR, p.DSKey, p.DSCertDER)
	if err != nil {
		return nil, fmt.Errorf("mdoc issue: sign MSO: %w", err)
	}

	// ── 5. Build nameSpaces array ─────────────────────────────────────────────
	// Each element is #6.24(bstr(IssuerSignedItem CBOR)) per ISO 18013-5 §9.1.2.
	rawItems := make([]cbor.RawMessage, len(entries))
	for i, e := range entries {
		rawItems[i] = cbor.RawMessage(e.taggedBytes)
	}

	// ── 6. Assemble IssuerSigned ──────────────────────────────────────────────
	is := struct {
		NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
		IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
	}{
		NameSpaces: map[string][]cbor.RawMessage{p.Namespace: rawItems},
		IssuerAuth: cbor.RawMessage(issuerAuth),
	}
	return cbor.Marshal(is)
}

// fullDate wraps a YYYY-MM-DD string as an ISO 18013-5 full-date (#6.1004(tstr)).
func fullDate(s string) cbor.Tag {
	return cbor.Tag{Number: tagFullDate, Content: s}
}

// FillMdlMandatory ensures the issued attribute set contains every data element
// ISO 18013-5 §7.2.1 marks mandatory for the org.iso.18013.5.1 (mDL) namespace,
// adding ISO-typed defaults for any that are missing. Date elements present as
// plain "YYYY-MM-DD" strings are coerced to full-date (#6.1004(tstr)) so they
// serialize with the correct CBOR type.
//
// Call this only when issuing the mDL docType. It mutates attrs in place.
func FillMdlMandatory(attrs map[string]interface{}) {
	if attrs == nil {
		return
	}
	// Coerce known date elements supplied as bare strings to full-date.
	for _, k := range []string{"birth_date", "issue_date", "expiry_date"} {
		if s, ok := attrs[k].(string); ok {
			attrs[k] = fullDate(s)
		}
	}
	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	expiry := now.AddDate(10, 0, 0).Format("2006-01-02")

	setIf := func(k string, v interface{}) {
		if _, ok := attrs[k]; !ok {
			attrs[k] = v
		}
	}
	setIf("family_name", "Doe")
	setIf("given_name", "John")
	setIf("birth_date", fullDate(now.AddDate(-30, 0, 0).Format("2006-01-02")))
	setIf("issue_date", fullDate(today))
	setIf("expiry_date", fullDate(expiry))
	setIf("issuing_country", "IT")             // ISO 3166-1 alpha-2
	setIf("issuing_authority", "Clavex")       // tstr
	setIf("document_number", "CLVX-000001")    // tstr
	setIf("un_distinguishing_sign", "I")       // distinguishing sign (Italy)
	setIf("portrait", []byte{0xFF, 0xD8, 0xFF, 0xD9}) // bstr (minimal JPEG)
	setIf("driving_privileges", []interface{}{ // array of driving-privilege maps
		map[string]interface{}{
			"vehicle_category_code": "B",
			"issue_date":            fullDate(today),
			"expiry_date":           fullDate(expiry),
		},
	})
}

// signMSO signs the CBOR-encoded MSO bytes as a COSE_Sign1 structure.
// Returns the raw CBOR bytes of the untagged COSE_Sign1 array.
//
// ISO 18013-5 §9.1.2.4 requires:
//   - Protected header: {1: alg} only
//   - Unprotected header: {33: x5chain} (DS cert)
//
// The multipaz library (used by the conformance suite) calls
// DataItem.getAsCoseSign1() → CoseSign1.fromDataItem() which requires the
// issuerAuth DataItem to be a bare CborArray, NOT a tag-18 Tagged item.
// Emitting tag 18 here would cause fromDataItem to fail with "Failed requirement".
func signMSO(msoCBOR []byte, dsKey *ecdsa.PrivateKey, dsCertDER []byte) ([]byte, error) {
	// Protected header: {1: -7} — alg = ES256 only.
	protHdrBytes, err := cbor.Marshal(map[interface{}]interface{}{
		int64(1): int64(-7),
	})
	if err != nil {
		return nil, fmt.Errorf("signMSO: protected header: %w", err)
	}

	// Unprotected header: {33: dsCertDER} — x5chain per ISO 18013-5 §9.1.2.4.
	unprotHdrBytes, err := cbor.Marshal(map[interface{}]interface{}{
		int64(33): dsCertDER,
	})
	if err != nil {
		return nil, fmt.Errorf("signMSO: unprotected header: %w", err)
	}

	// Payload: bstr(MobileSecurityObjectBytes) where
	// MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
	// per ISO 18013-5 §9.1.2.4. The COSE_Sign1 payload must be the Tag-24
	// encoded MSO, not the bare MSO map; otherwise verifiers calling
	// getAsTaggedEncodedCbor on the payload fail to locate the MSO.
	bstrMSO, err := cbor.Marshal(msoCBOR)
	if err != nil {
		return nil, fmt.Errorf("signMSO: bstr-wrap MSO: %w", err)
	}
	taggedMSO, err := cbor.Marshal(cbor.RawTag{Number: tagCBORByteString, Content: bstrMSO})
	if err != nil {
		return nil, fmt.Errorf("signMSO: tag-24 MSO: %w", err)
	}
	payloadBstrCBOR, err := cbor.Marshal(taggedMSO)
	if err != nil {
		return nil, fmt.Errorf("signMSO: payload bstr: %w", err)
	}

	// Sig_Structure for COSE_Sign1 (RFC 9052 §4.4).
	sigStruct, err := cbor.Marshal([]interface{}{
		"Signature1",
		protHdrBytes,                     // []byte → CBOR bstr
		[]byte{},                         // empty external_aad → CBOR bstr
		cbor.RawMessage(payloadBstrCBOR), // already a CBOR bstr, embed as-is
	})
	if err != nil {
		return nil, fmt.Errorf("signMSO: Sig_Structure: %w", err)
	}

	digest := sha256.Sum256(sigStruct)
	r, s, err := ecdsa.Sign(rand.Reader, dsKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signMSO: ECDSA sign: %w", err)
	}
	curveSize := (dsKey.Params().N.BitLen() + 7) / 8
	sig := make([]byte, 2*curveSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[curveSize-len(rBytes):curveSize], rBytes)
	copy(sig[2*curveSize-len(sBytes):], sBytes)

	sign1 := coseSig1{
		Protected:   protHdrBytes,
		Unprotected: cbor.RawMessage(unprotHdrBytes),
		Payload:     cbor.RawMessage(payloadBstrCBOR),
		Signature:   sig,
	}
	return cbor.Marshal(sign1)
}

// ecPublicKeyToCOSE converts an ECDSA public key to a COSEKey (EC2, kty=2).
func ecPublicKeyToCOSE(pub *ecdsa.PublicKey) (COSEKey, error) {
	var crv int
	switch pub.Params().Name {
	case "P-256":
		crv = 1
	case "P-384":
		crv = 2
	case "P-521":
		crv = 3
	default:
		return COSEKey{}, fmt.Errorf("unsupported EC curve: %s", pub.Params().Name)
	}
	// Use PublicKey.Bytes() (uncompressed: 0x04 || X || Y) to avoid deprecated
	// big.Int coordinate access (Go 1.26+).
	coordSize := (pub.Params().BitSize + 7) / 8
	uncompressed, err := pub.ECDH()
	if err != nil {
		return COSEKey{}, fmt.Errorf("ecPublicKeyToCOSE: ECDH key: %w", err)
	}
	raw := uncompressed.Bytes() // uncompressed: 0x04 || X || Y
	// raw[0] is 0x04; X occupies [1:1+coordSize], Y occupies [1+coordSize:]
	x := padLeft(raw[1:1+coordSize], coordSize)
	y := padLeft(raw[1+coordSize:], coordSize)
	return COSEKey{
		KeyType: 2,    // EC2
		Curve:   crv,
		X:       x,
		Y:       y,
	}, nil
}

// padLeft pads a byte slice with leading zeros to the requested length.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}


// ECPublicKeyFromCOSE converts a COSEKey back to *ecdsa.PublicKey.
// Exported for use by the OID4VCI holder-key extraction.
func ECPublicKeyFromCOSE(k COSEKey) (*ecdsa.PublicKey, error) {
	return coseKeyToECDSA(k)
}

// GenerateMdocIssuerKeys generates a fresh ECDSA P-256 key pair and a
// self-signed DS certificate suitable for mdoc issuance in test environments.
//
// In production, the DS certificate should be signed by the org's IACA CA.
// Returns (dsKeyPEM, dsCertPEM, error).
func GenerateMdocIssuerKeys(orgName, docType string) (dsKeyPEM, dsCertPEM string, err error) {
	return generateECDSACertPair(orgName, docType)
}
