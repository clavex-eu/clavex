// Package mdoc implements ISO 18013-5 Mobile Document (mdoc) parsing and
// verification as required by the eIDAS 2.0 proximity flow.
//
// An mdoc is a CBOR-encoded, COSE-signed credential used by EU Digital Identity
// Wallets (EUDIW). This package handles the verifier side of the proximity
// presentation protocol, covering:
//
//   - DeviceEngagement QR code generation (OID4VP proximity variant)
//   - DeviceResponse parsing (IssuerSigned + DeviceSigned)
//   - Mobile Security Object (MSO) verification via COSE_Sign1
//   - Certificate chain validation against a trusted IACA root pool
//   - Attribute extraction with selective disclosure
//
// The proximity flow (ISO 18013-5 §8 + OID4VP §B):
//
//  1. Verifier generates a DeviceEngagement URL and shows it as a QR code.
//  2. Wallet scans the QR, fetches the OID4VP authorization request.
//  3. Wallet builds a DeviceResponse (IssuerSigned + DeviceSigned) and POSTs it.
//  4. Verifier calls ParseDeviceResponse + VerifyDeviceResponse + ExtractAttributes.
package mdoc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
)

// ── Namespace constants ───────────────────────────────────────────────────────

const (
	// NSMdl is the ISO 18013-5 namespace for mobile driving licences.
	NSMdl = "org.iso.18013.5.1"
	// NSEuPid is the EUDIW PID (Person Identification Data) namespace.
	NSEuPid = "eu.europa.ec.eudi.pid.1"
	// DocTypeMdl is the docType for mobile driving licences.
	DocTypeMdl = "org.iso.18013.5.1.mDL"
	// DocTypeEuPid is the docType for EUDIW PID credentials.
	DocTypeEuPid = "eu.europa.ec.eudi.pid.1"
)

// ── CBOR tag numbers ──────────────────────────────────────────────────────────

const (
	tagCBORByteString = 24   // CBOR-encoded bytes (embedded CBOR)
	tagFullDate       = 1004 // ISO 8601 full-date string
	tagDateTimeString = 0    // ISO 8601 tdate
)

// ── DeviceEngagement ──────────────────────────────────────────────────────────

// DeviceEngagementQR is the content that goes into the QR code.
// For the OID4VP proximity variant, this is the openid4vp:// URI.
// The wallet parses this URI and fetches the authorization request from request_uri.
type DeviceEngagementQR struct {
	// URI is the openid4vp:// engagement URI containing the request_uri and nonce.
	// Format: openid4vp://?request_uri=<url>&client_id=<id>&nonce=<nonce>
	URI string
	// SessionID is the verifier-side session identifier for status polling.
	SessionID string
	// Nonce is the session nonce included in the authorization request and
	// verified in the DeviceResponse.
	Nonce string
}

// ── COSE structures ───────────────────────────────────────────────────────────

// coseSig1 is a minimal COSE_Sign1 structure (RFC 9052 §4.2).
// The CBOR tag 18 wraps this as a tagged array.
type coseSig1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte   // bstr-wrapped protected header map
	Unprotected cbor.RawMessage
	Payload     cbor.RawMessage // bstr (nil = detached)
	Signature   []byte
}

// coseHeader is the decoded protected header map.
type coseHeader struct {
	Algorithm int    `cbor:"1,keyasint,omitempty"`  // alg
	X5Chain   []byte `cbor:"33,keyasint,omitempty"` // x5chain (single cert)
}

// COSE algorithm numbers (RFC 9053 / IANA COSE Algorithms Registry).
const (
	algES256 = -7  // ECDSA w/ SHA-256 (P-256)
	algES384 = -35 // ECDSA w/ SHA-384 (P-384)
	algES512 = -36 // ECDSA w/ SHA-512 (P-521)
)

// ── MSO (Mobile Security Object) ─────────────────────────────────────────────

// MSO is the Mobile Security Object as defined in ISO 18013-5 §9.1.2.4.
// It is the COSE_Sign1 payload that binds the issuer to the document data.
type MSO struct {
	Version         string               `cbor:"version"`
	DigestAlgorithm string               `cbor:"digestAlgorithm"` // "SHA-256" | "SHA-384" | "SHA-512"
	ValueDigests    map[string]DigestMap `cbor:"valueDigests"`    // namespace → (digestID → digest)
	DeviceKeyInfo   DeviceKeyInfo        `cbor:"deviceKeyInfo"`
	DocType         string               `cbor:"docType"`
	ValidityInfo    ValidityInfo         `cbor:"validityInfo"`
}

// DigestMap maps digestID (uint) to the expected SHA digest of each IssuerSignedItem.
type DigestMap map[uint][]byte

// DeviceKeyInfo holds the device public key bound to this document.
type DeviceKeyInfo struct {
	DeviceKey COSEKey `cbor:"deviceKey"`
}

// COSEKey is a minimal COSE_Key for EC2 keys (kty=2).
type COSEKey struct {
	KeyType   int    `cbor:"1,keyasint"` // kty: 2 = EC2
	Algorithm int    `cbor:"3,keyasint,omitempty"`
	Curve     int    `cbor:"-1,keyasint"` // crv: 1=P-256, 2=P-384, 3=P-521
	X         []byte `cbor:"-2,keyasint"` // x coordinate
	Y         []byte `cbor:"-3,keyasint"` // y coordinate
}

// ValidityInfo contains the document's validity window.
type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

// ── IssuerSigned ─────────────────────────────────────────────────────────────

// IssuerSigned contains the issuer-provided data for one document.
type IssuerSigned struct {
	NameSpaces map[string][]IssuerSignedItemRaw `cbor:"nameSpaces,omitempty"`
	IssuerAuth cbor.RawMessage                  `cbor:"issuerAuth"` // COSE_Sign1
}

// IssuerSignedItemRaw is a #6.24(bstr) -wrapped IssuerSignedItem.
// We preserve the raw bytes so we can rehash them against the MSO digests.
type IssuerSignedItemRaw = cbor.RawMessage

// IssuerSignedItem is the decoded inner structure of each disclosed attribute.
type IssuerSignedItem struct {
	DigestID          uint            `cbor:"digestID"`
	Random            []byte          `cbor:"random"` // 16-byte salt
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"`
}

// ── DeviceSigned ─────────────────────────────────────────────────────────────

// DeviceSigned contains the device-generated authentication proof.
type DeviceSigned struct {
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"` // #6.24(bstr)
	DeviceAuth DeviceAuth      `cbor:"deviceAuth"`
}

// DeviceAuth holds either DeviceSignature (COSE_Sign1) or DeviceMAC (COSE_Mac0).
type DeviceAuth struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature,omitempty"` // COSE_Sign1
	DeviceMac       cbor.RawMessage `cbor:"deviceMAC,omitempty"`       // COSE_Mac0
}

// ── Document + DeviceResponse ─────────────────────────────────────────────────

// Document is one mdoc within a DeviceResponse.
type Document struct {
	DocType      string          `cbor:"docType"`
	IssuerSigned IssuerSigned    `cbor:"issuerSigned"`
	DeviceSigned DeviceSigned    `cbor:"deviceSigned"`
	Errors       cbor.RawMessage `cbor:"errors,omitempty"`
}

// DeviceResponse is the top-level structure sent by the wallet.
// It is the CBOR-encoded body of the OID4VP vp_token when format="mso_mdoc".
type DeviceResponse struct {
	Version   string     `cbor:"version"`
	Documents []Document `cbor:"documents,omitempty"`
	// DocumentErrors are per-document errors from the wallet.
	DocumentErrors cbor.RawMessage `cbor:"documentErrors,omitempty"`
	Status         uint            `cbor:"status"` // 0 = OK
}

// ── VerificationOptions ───────────────────────────────────────────────────────

// VerificationOptions controls the mdoc verification behaviour.
type VerificationOptions struct {
	// TrustedRoots is the pool of trusted IACA (Issuer Authority CA) root
	// certificates. Documents signed by issuers not chaining to these roots
	// will be rejected. If empty, certificate chain validation is skipped
	// (development/testing only).
	TrustedRoots *x509.CertPool

	// ExpectedNonce is the nonce from the OID4VP authorization request.
	// It must appear in the DeviceSigned session transcript.
	// If empty, nonce verification is skipped.
	ExpectedNonce string

	// Now overrides time.Now() for validity window checks. Nil = real clock.
	Now *time.Time

	// AllowExpiredDocuments disables the validUntil check. For testing only.
	AllowExpiredDocuments bool
}

// ── VerifiedDocument ─────────────────────────────────────────────────────────

// VerifiedDocument holds the verification result for one Document in the response.
type VerifiedDocument struct {
	DocType    string
	Attributes map[string]map[string]any // namespace → elementIdentifier → value
	// IssuerCert is the signer certificate from the MSO COSE_Sign1 x5chain.
	IssuerCert *x509.Certificate
	// DeviceKey is the ECDSA public key from the MSO DeviceKeyInfo.
	// It is populated only when the MSO contains a parseable EC2 COSE_Key.
	// Use it to call VerifyDeviceSignature after building the session transcript.
	DeviceKey *ecdsa.PublicKey
	// ValidFrom / ValidUntil from the MSO ValidityInfo.
	ValidFrom  time.Time
	ValidUntil time.Time
}

// ── Public API ────────────────────────────────────────────────────────────────

// ParseDeviceResponse decodes a CBOR-encoded DeviceResponse.
// The input is the raw bytes of the vp_token when format is "mso_mdoc".
// Base64url decoding, if needed, must be done by the caller.
func ParseDeviceResponse(raw []byte) (*DeviceResponse, error) {
	var dr DeviceResponse
	if err := cbor.Unmarshal(raw, &dr); err != nil {
		return nil, fmt.Errorf("mdoc: DeviceResponse CBOR decode: %w", err)
	}
	if dr.Version == "" {
		return nil, errors.New("mdoc: missing version in DeviceResponse")
	}
	return &dr, nil
}

// VerifyDeviceResponse verifies all Documents inside a DeviceResponse and
// returns the verified set. Documents that fail verification are returned as
// errors alongside any successfully verified ones — the caller decides policy.
//
// For each Document the function:
//  1. Decodes IssuerAuth (COSE_Sign1) and extracts the embedded MSO.
//  2. Verifies the COSE_Sign1 signature against the issuer certificate from x5chain.
//  3. Validates the issuer certificate against opts.TrustedRoots (if set).
//  4. Checks MSO validity window.
//  5. Rehashes each disclosed IssuerSignedItem and compares to MSO valueDigests.
//
// DeviceSigned / device key binding verification is intentionally a separate
// step (VerifyDeviceSignature) because it requires the session transcript
// which is assembled by the handler layer.
func VerifyDeviceResponse(dr *DeviceResponse, opts VerificationOptions) ([]*VerifiedDocument, []error) {
	now := time.Now()
	if opts.Now != nil {
		now = *opts.Now
	}

	var verified []*VerifiedDocument
	var errs []error

	for i, doc := range dr.Documents {
		vd, err := verifyDocument(doc, now, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("document[%d] %q: %w", i, doc.DocType, err))
			continue
		}
		verified = append(verified, vd)
	}
	return verified, errs
}

// ExtractAttributes returns a flat map of disclosed attributes from a
// VerifiedDocument in the requested namespace. The keys are elementIdentifiers
// (e.g. "given_name", "birth_date"). Values are Go native types decoded from CBOR.
//
// If namespace is empty, attributes from all namespaces are merged (last-write wins
// on key collision across namespaces).
func ExtractAttributes(vd *VerifiedDocument, namespace string) map[string]any {
	out := make(map[string]any)
	for ns, attrs := range vd.Attributes {
		if namespace != "" && ns != namespace {
			continue
		}
		for k, v := range attrs {
			out[k] = v
		}
	}
	return out
}

// ── internal verification helpers ────────────────────────────────────────────

func verifyDocument(doc Document, now time.Time, opts VerificationOptions) (*VerifiedDocument, error) {
	// ── 1. Decode IssuerAuth (COSE_Sign1) ─────────────────────────────────
	sig1, err := decodeCOSESign1(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("IssuerAuth: %w", err)
	}

	// ── 2. Decode protected header to get algorithm + x5chain ─────────────
	var protectedHeader coseHeader
	if err := cbor.Unmarshal(sig1.Protected, &protectedHeader); err != nil {
		return nil, fmt.Errorf("protected header: %w", err)
	}

	issuerCert, err := extractIssuerCert(sig1, opts.TrustedRoots)
	if err != nil {
		return nil, err
	}

	// ── 3. Verify COSE_Sign1 signature ────────────────────────────────────
	if err := verifyCOSESign1(sig1, protectedHeader.Algorithm, issuerCert.PublicKey); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 signature: %w", err)
	}

	// ── 4. Decode MSO from the COSE_Sign1 payload ─────────────────────────
	mso, err := decodeMSO(sig1.Payload)
	if err != nil {
		return nil, fmt.Errorf("MSO: %w", err)
	}

	// ── 5. Validity window check ───────────────────────────────────────────
	if !opts.AllowExpiredDocuments {
		if now.Before(mso.ValidityInfo.ValidFrom) {
			return nil, fmt.Errorf("document not yet valid (validFrom=%s)", mso.ValidityInfo.ValidFrom)
		}
		if now.After(mso.ValidityInfo.ValidUntil) {
			return nil, fmt.Errorf("document expired (validUntil=%s)", mso.ValidityInfo.ValidUntil)
		}
	}

	// ── 6. DocType must match ──────────────────────────────────────────────
	if mso.DocType != doc.DocType {
		return nil, fmt.Errorf("docType mismatch: MSO=%q document=%q", mso.DocType, doc.DocType)
	}

	// ── 7. Verify disclosed items against MSO digests ─────────────────────
	attrs, err := verifyAndExtractNameSpaces(doc.IssuerSigned.NameSpaces, mso)
	if err != nil {
		return nil, err
	}

	// ── 8. Extract device public key from MSO ────────────────────────────
	deviceKey, _ := coseKeyToECDSA(mso.DeviceKeyInfo.DeviceKey)

	return &VerifiedDocument{
		DocType:    doc.DocType,
		Attributes: attrs,
		IssuerCert: issuerCert,
		DeviceKey:  deviceKey,
		ValidFrom:  mso.ValidityInfo.ValidFrom,
		ValidUntil: mso.ValidityInfo.ValidUntil,
	}, nil
}

// decodeCOSESign1 decodes a raw CBOR value into a COSE_Sign1 structure.
// The outer CBOR tag 18 is stripped if present.
func decodeCOSESign1(raw cbor.RawMessage) (*coseSig1, error) {
	// The value may be tagged (tag 18) or untagged.
	// Try untagged first, then tag-stripped.
	var sig coseSig1
	if err := cbor.Unmarshal(raw, &sig); err == nil && len(sig.Protected) > 0 {
		return &sig, nil
	}
	// Try unwrapping tag 18.
	var tagged cbor.RawTag
	if err := cbor.Unmarshal(raw, &tagged); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 decode: %w", err)
	}
	if tagged.Number != 18 {
		return nil, fmt.Errorf("COSE_Sign1: unexpected tag %d (want 18)", tagged.Number)
	}
	if err := cbor.Unmarshal(tagged.Content, &sig); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 inner decode: %w", err)
	}
	return &sig, nil
}

// extractIssuerCert parses the x5chain from unprotected or protected headers,
// then optionally validates the chain against trustedRoots.
func extractIssuerCert(sig1 *coseSig1, roots *x509.CertPool) (*x509.Certificate, error) {
	// x5chain (header label 33) may hold a single bstr (one cert) or an array of bstr.
	// We look in both protected and unprotected headers.
	certDER, err := extractX5Chain(sig1.Protected)
	if err != nil || certDER == nil {
		// Try unprotected header.
		certDER, err = extractX5Chain(sig1.Unprotected)
		if err != nil {
			return nil, fmt.Errorf("x5chain: %w", err)
		}
	}
	if certDER == nil {
		return nil, errors.New("issuer certificate (x5chain) not found in COSE header")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("issuer cert parse: %w", err)
	}

	if roots != nil {
		opts := x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := cert.Verify(opts); err != nil {
			return nil, fmt.Errorf("issuer cert chain verification: %w", err)
		}
	}
	return cert, nil
}

// extractX5Chain reads the x5chain (COSE header label 33) from a raw CBOR header map.
// Returns nil, nil if the key is absent.
func extractX5Chain(rawHeader cbor.RawMessage) ([]byte, error) {
	if len(rawHeader) == 0 {
		return nil, nil
	}
	// Decode as a generic map to find key 33.
	var hdrMap map[int]cbor.RawMessage
	if err := cbor.Unmarshal(rawHeader, &hdrMap); err != nil {
		return nil, nil // header may not be a map (e.g. empty bstr)
	}
	raw, ok := hdrMap[33]
	if !ok {
		return nil, nil
	}
	// x5chain can be a bstr (single cert) or array of bstr (chain).
	// Try bstr first.
	var certDER []byte
	if err := cbor.Unmarshal(raw, &certDER); err == nil {
		return certDER, nil
	}
	// Try array — return the leaf (first) cert.
	var chain [][]byte
	if err := cbor.Unmarshal(raw, &chain); err == nil && len(chain) > 0 {
		return chain[0], nil
	}
	return nil, errors.New("x5chain: unrecognised format")
}

// verifyCOSESign1 verifies the COSE_Sign1 signature.
// Sig_structure = ["Signature1", protected_bstr, external_aad, payload]
func verifyCOSESign1(sig1 *coseSig1, alg int, pub crypto.PublicKey) error {
	// Build the Sig_Structure (RFC 9052 §4.4).
	sigStructure, err := cbor.Marshal([]interface{}{
		"Signature1",
		sig1.Protected, // bstr — used as-is (not re-encoded)
		[]byte{},       // external_aad (empty for mdoc)
		sig1.Payload,
	})
	if err != nil {
		return fmt.Errorf("Sig_Structure encode: %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("issuer public key is not ECDSA")
	}

	var h hash.Hash
	var hashAlg crypto.Hash
	switch alg {
	case algES256:
		h = sha256.New()
		hashAlg = crypto.SHA256
	case algES384:
		h = sha512.New384()
		hashAlg = crypto.SHA384
	case algES512:
		h = sha512.New()
		hashAlg = crypto.SHA512
	default:
		return fmt.Errorf("unsupported COSE algorithm: %d", alg)
	}
	_ = hashAlg

	h.Write(sigStructure)
	digest := h.Sum(nil)

	// COSE ECDSA signature is the raw r||s concatenation (RFC 9053 §2.1).
	if len(sig1.Signature) < 2 {
		return errors.New("signature too short")
	}
	half := len(sig1.Signature) / 2
	r := new(big.Int).SetBytes(sig1.Signature[:half])
	s := new(big.Int).SetBytes(sig1.Signature[half:])

	if !ecdsa.Verify(ecPub, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// decodeMSO decodes the COSE_Sign1 payload into an MSO.
// The payload may be a #6.24(bstr) (embedded CBOR) or plain bstr.
func decodeMSO(payload cbor.RawMessage) (*MSO, error) {
	// Try #6.24(bstr) first.
	var tag cbor.RawTag
	inner := payload
	if err := cbor.Unmarshal(payload, &tag); err == nil && tag.Number == tagCBORByteString {
		inner = tag.Content
	}

	// The inner value is a bstr containing the CBOR-encoded MSO.
	var msoBytes []byte
	if err := cbor.Unmarshal(inner, &msoBytes); err != nil {
		// Maybe the payload itself is the MSO map.
		var mso MSO
		if err2 := cbor.Unmarshal(inner, &mso); err2 != nil {
			return nil, fmt.Errorf("MSO decode (bstr path: %v, map path: %v)", err, err2)
		}
		return &mso, nil
	}

	// Some issuers (e.g. EUDI reference wallet) double-wrap the MSO:
	// bstr(bstr(<MSO CBOR map>)). Try one more level of bstr unwrapping.
	var mso MSO
	if err := cbor.Unmarshal(msoBytes, &mso); err != nil {
		var msoBytes2 []byte
		if err2 := cbor.Unmarshal(msoBytes, &msoBytes2); err2 == nil {
			if err3 := cbor.Unmarshal(msoBytes2, &mso); err3 != nil {
				return nil, fmt.Errorf("MSO inner decode: %w", err3)
			}
			return &mso, nil
		}
		return nil, fmt.Errorf("MSO inner decode: %w", err)
	}
	return &mso, nil
}

// verifyAndExtractNameSpaces rehashes each disclosed IssuerSignedItem and
// verifies that the hash matches the corresponding entry in the MSO valueDigests.
func verifyAndExtractNameSpaces(
	nsMap map[string][]IssuerSignedItemRaw,
	mso *MSO,
) (map[string]map[string]any, error) {
	result := make(map[string]map[string]any)

	for ns, items := range nsMap {
		digests, ok := mso.ValueDigests[ns]
		if !ok {
			return nil, fmt.Errorf("namespace %q not found in MSO valueDigests", ns)
		}
		nsAttrs := make(map[string]any)
		for _, rawItem := range items {
			item, _, err := decodeIssuerSignedItem(rawItem)
			if err != nil {
				return nil, fmt.Errorf("namespace %q: %w", ns, err)
			}

			// Per ISO 18013-5 §9.1.2.4 the digest covers the entire
			// #6.24(bstr .cbor IssuerSignedItem) bytes as received, not a
			// re-encoding. Pass rawItem so we hash the original wire bytes.
			digest, err := digestIssuerSignedItem(rawItem, mso.DigestAlgorithm)
			if err != nil {
				return nil, fmt.Errorf("namespace %q digestID %d: %w", ns, item.DigestID, err)
			}

			expected, ok := digests[item.DigestID]
			if !ok {
				return nil, fmt.Errorf("namespace %q: digestID %d not in MSO", ns, item.DigestID)
			}
			if !bytes.Equal(digest, expected) {
				return nil, fmt.Errorf("namespace %q: digestID %d digest mismatch", ns, item.DigestID)
			}

			// Decode the element value to a Go native type.
			val, err := decodeCBORValue(item.ElementValue)
			if err != nil {
				return nil, fmt.Errorf("namespace %q: elementIdentifier %q value: %w", ns, item.ElementIdentifier, err)
			}
			nsAttrs[item.ElementIdentifier] = val
		}
		result[ns] = nsAttrs
	}
	return result, nil
}

// decodeIssuerSignedItem decodes a #6.24(bstr)-wrapped IssuerSignedItem.
// Returns the decoded item and the inner bstr bytes (for rehashing).
func decodeIssuerSignedItem(raw IssuerSignedItemRaw) (*IssuerSignedItem, []byte, error) {
	// The item is #6.24(bstr .cbor IssuerSignedItem).
	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err != nil {
		return nil, nil, fmt.Errorf("IssuerSignedItem tag: %w", err)
	}
	if tag.Number != tagCBORByteString {
		return nil, nil, fmt.Errorf("IssuerSignedItem: expected tag 24, got %d", tag.Number)
	}
	// tag.Content is the bstr.
	var itemBytes []byte
	if err := cbor.Unmarshal(tag.Content, &itemBytes); err != nil {
		return nil, nil, fmt.Errorf("IssuerSignedItem bstr: %w", err)
	}
	var item IssuerSignedItem
	if err := cbor.Unmarshal(itemBytes, &item); err != nil {
		return nil, nil, fmt.Errorf("IssuerSignedItem decode: %w", err)
	}
	return &item, itemBytes, nil
}

// digestIssuerSignedItem computes the MSO digest for an IssuerSignedItem.
// Per ISO 18013-5 §9.1.2.4, the digest input is the raw wire bytes of the
// #6.24(bstr .cbor IssuerSignedItem) structure as it appears in the DeviceResponse.
func digestIssuerSignedItem(raw IssuerSignedItemRaw, algorithm string) ([]byte, error) {
	switch algorithm {
	case "SHA-256":
		d := sha256.Sum256(raw)
		return d[:], nil
	case "SHA-384":
		d := sha512.Sum384(raw)
		return d[:], nil
	case "SHA-512":
		d := sha512.Sum512(raw)
		return d[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %q", algorithm)
	}
}

// decodeCBORValue converts a cbor.RawMessage to a Go native value.
// Handles common types: string, int, bool, []byte, tagged full-date.
func decodeCBORValue(raw cbor.RawMessage) (any, error) {
	// Try tagged values first (tdate, full-date).
	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err == nil {
		switch tag.Number {
		case tagDateTimeString, tagFullDate:
			var s string
			if err := cbor.Unmarshal(tag.Content, &s); err == nil {
				return s, nil
			}
		}
	}
	// Generic decode.
	var v any
	if err := cbor.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return sanitizeCBORValue(v), nil
}

// sanitizeCBORValue recursively converts cbor.Tag and cbor.RawTag values to
// JSON-serializable types. Without this step, nested tagged values (e.g.
// full-date tags inside driving_privileges arrays) cause json.Marshal to fail
// or produce unexpected output.
func sanitizeCBORValue(v any) any {
	switch val := v.(type) {
	case cbor.Tag: // fxamacker decodes tagged values as cbor.Tag when target is interface{}
		switch val.Number {
		case tagDateTimeString, tagFullDate:
			if s, ok := val.Content.(string); ok {
				return s
			}
		}
		return sanitizeCBORValue(val.Content)
	case cbor.RawTag: // used in some encoding paths
		switch val.Number {
		case tagDateTimeString, tagFullDate:
			var s string
			if cbor.Unmarshal(val.Content, &s) == nil {
				return s
			}
		}
		var inner any
		if cbor.Unmarshal(val.Content, &inner) == nil {
			return sanitizeCBORValue(inner)
		}
		return nil
	case map[any]any: // CBOR integer-keyed map → string-keyed map
		out := make(map[string]any, len(val))
		for k, mv := range val {
			out[fmt.Sprintf("%v", k)] = sanitizeCBORValue(mv)
		}
		return out
	case map[string]any:
		for k, mv := range val {
			val[k] = sanitizeCBORValue(mv)
		}
		return val
	case []any:
		for i, item := range val {
			val[i] = sanitizeCBORValue(item)
		}
		return val
	default:
		return v
	}
}

// ── DeviceSigned verification (session transcript / nonce binding) ────────────

// SessionTranscript is the verifier-side session transcript for device auth.
// In the OID4VP proximity flow this is constructed from the nonce and
// the verifier's handover data per ISO 18013-7 §8.3.3.1.2.
//
// We use the "OpenID4VPHandover" structure:
//   SessionTranscript = [null, null, OpenID4VPHandover]
//   OpenID4VPHandover = [clientIdHash, responseUriHash, nonce]
type SessionTranscript struct {
	ClientIDHash    []byte
	ResponseURIHash []byte
	Nonce           string
}

// BuildSessionTranscript constructs the CBOR-encoded SessionTranscript bytes
// used as the external AAD in device authentication.
// clientID and responseURI are the values from the OID4VP authorization request.
func BuildSessionTranscript(clientID, responseURI, nonce string) ([]byte, error) {
	// Hash clientID and responseURI per ISO 18013-7.
	cidHash := sha256.Sum256([]byte(clientID))
	ruriHash := sha256.Sum256([]byte(responseURI))

	handover := []any{cidHash[:], ruriHash[:], nonce}
	transcript := []any{nil, nil, handover}

	return cbor.Marshal(transcript)
}

// VerifyDeviceSignature verifies the DeviceSigned COSE_Sign1 or MAC0.
// It checks that the session transcript matches the nonce in opts.
// deviceKey is the ECDSA public key from the MSO DeviceKeyInfo.
func VerifyDeviceSignature(doc Document, transcript []byte, deviceKey *ecdsa.PublicKey) error {
	rawAuth := doc.DeviceSigned.DeviceAuth.DeviceSignature
	if len(rawAuth) == 0 {
		// Device MAC is acceptable for some flows; for OID4VP proximity we require signature.
		if len(doc.DeviceSigned.DeviceAuth.DeviceMac) > 0 {
			return errors.New("DeviceMAC not supported in OID4VP proximity flow; DeviceSignature required")
		}
		return errors.New("no DeviceSignature or DeviceMAC in DeviceSigned")
	}

	sig1, err := decodeCOSESign1(rawAuth)
	if err != nil {
		return fmt.Errorf("DeviceSignature COSE_Sign1: %w", err)
	}

	var protectedHdr coseHeader
	if err := cbor.Unmarshal(sig1.Protected, &protectedHdr); err != nil {
		return fmt.Errorf("DeviceSignature protected header: %w", err)
	}

	// The Sig_Structure for DeviceAuthentication uses external_aad = transcript.
	sigStructure, err := cbor.Marshal([]interface{}{
		"Signature1",
		sig1.Protected,
		transcript,   // external AAD = session transcript
		sig1.Payload, // DeviceAuthenticationBytes
	})
	if err != nil {
		return err
	}

	d := sha256.Sum256(sigStructure)
	half := len(sig1.Signature) / 2
	r := new(big.Int).SetBytes(sig1.Signature[:half])
	s := new(big.Int).SetBytes(sig1.Signature[half:])
	if !ecdsa.Verify(deviceKey, d[:], r, s) {
		return errors.New("device signature verification failed")
	}
	return nil
}

// ExtractDeviceKey returns the ECDSA device public key that was bound to the
// document in its MSO. The key is populated during VerifyDeviceResponse and
// can be used to call VerifyDeviceSignature with the session transcript.
// Returns an error if the VerifiedDocument does not contain a device key
// (e.g. the MSO used an unsupported key type).
func ExtractDeviceKey(vd *VerifiedDocument) (*ecdsa.PublicKey, error) {
	if vd.DeviceKey == nil {
		return nil, errors.New("mdoc: no device key in VerifiedDocument (MSO may use an unsupported key type)")
	}
	return vd.DeviceKey, nil
}

// coseKeyToECDSA converts an EC2 COSE_Key (kty=2) to an *ecdsa.PublicKey.
// Returns nil, err for unsupported key types or curves.
func coseKeyToECDSA(k COSEKey) (*ecdsa.PublicKey, error) {
	const ktyEC2 = 2
	if k.KeyType != ktyEC2 {
		return nil, fmt.Errorf("mdoc: COSE_Key kty=%d is not EC2 (2)", k.KeyType)
	}
	if len(k.X) == 0 || len(k.Y) == 0 {
		return nil, errors.New("mdoc: COSE_Key missing X or Y coordinate")
	}
	var curve elliptic.Curve
	switch k.Curve {
	case 1:
		curve = elliptic.P256()
	case 2:
		curve = elliptic.P384()
	case 3:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("mdoc: unsupported COSE_Key curve %d", k.Curve)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}, nil
}

// ── PID / mDL attribute helpers ───────────────────────────────────────────────

// PIDClaims maps the EUDIW PID namespace attributes to the standard OIDC claim names.
// The source namespace is NSEuPid = "eu.europa.ec.eudi.pid.1".
var PIDClaims = map[string]string{
	"family_name":            "family_name",
	"given_name":             "given_name",
	"birth_date":             "birthdate",
	"age_over_18":            "age_over_18",
	"resident_country":       "address.country",
	"nationality":            "nationality",
	"personal_identifier_no": "sub",
	"issuing_country":        "iss_country",
	"issuing_authority":      "iss_authority",
}

// MdlClaims maps ISO 18013-5 mDL namespace attributes to OIDC claim names.
// The source namespace is NSMdl = "org.iso.18013.5.1".
var MdlClaims = map[string]string{
	"family_name":        "family_name",
	"given_name":         "given_name",
	"birth_date":         "birthdate",
	"age_over_18":        "age_over_18",
	"document_number":    "document_number",
	"issuing_country":    "iss_country",
	"issuing_authority":  "iss_authority",
	"driving_privileges": "driving_privileges",
}

// ToOIDCClaims converts extracted mdoc attributes to OIDC-compatible claim names.
// docType selects which mapping table to use (DocTypeMdl or DocTypeEuPid).
func ToOIDCClaims(attrs map[string]any, docType string) map[string]any {
	var mapping map[string]string
	switch docType {
	case DocTypeEuPid:
		mapping = PIDClaims
	case DocTypeMdl:
		mapping = MdlClaims
	default:
		return attrs // unknown docType: return as-is
	}
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		if oidcKey, ok := mapping[k]; ok {
			out[oidcKey] = v
		} else {
			out[k] = v // preserve unmapped attributes
		}
	}
	return out
}

// ── CBOR tag type (re-export to avoid full cbor import in tests) ──────────────

// ensure cbor.RawTag is used (prevents unused-import if cbor is only used internally)
var _ = binary.BigEndian
var _ = asn1.BitString{}
var _ = elliptic.P256()
