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
	"encoding/json"
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
	Status          cbor.RawMessage      `cbor:"status,omitempty"`
	StatusList      cbor.RawMessage      `cbor:"status_list,omitempty"`
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

	// Deprecated: a nonce alone cannot define device authentication. Non-empty
	// ExpectedNonce is rejected; supply the exact request's SessionTranscript.
	ExpectedNonce string

	// SessionTranscript is the expected CBOR transcript built from the request.
	SessionTranscript    []byte
	RequireTrustedIssuer bool
	RequireDeviceAuth    bool

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
	ValidFrom      time.Time
	ValidUntil     time.Time
	VerifiedChains [][]*x509.Certificate
	Status         json.RawMessage
	IssuerAuthHash string
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

	if dr == nil || dr.Status != 0 || dr.Version != "1.0" || len(dr.Documents) == 0 || len(dr.DocumentErrors) > 0 {
		return nil, []error{errors.New("mdoc: invalid or unsuccessful DeviceResponse")}
	}
	if opts.RequireTrustedIssuer && opts.TrustedRoots == nil {
		return nil, []error{errors.New("mdoc: trusted issuer roots are required")}
	}
	if opts.ExpectedNonce != "" {
		return nil, []error{errors.New("mdoc: use SessionTranscript instead of ExpectedNonce")}
	}
	if opts.RequireDeviceAuth && len(opts.SessionTranscript) == 0 {
		return nil, []error{errors.New("mdoc: expected session transcript is required")}
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
	if len(doc.Errors) > 0 {
		return nil, errors.New("mdoc: document contains errors")
	}
	// ── 1. Decode IssuerAuth (COSE_Sign1) ─────────────────────────────────
	sig1, err := decodeCOSESign1(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, fmt.Errorf("IssuerAuth: %w", err)
	}

	// ── 2. Decode protected header to get algorithm + x5chain ─────────────
	algorithm, err := protectedAlgorithm(sig1.Protected)
	if err != nil {
		return nil, err
	}

	issuerCert, verifiedChains, err := extractIssuerCert(sig1, opts.TrustedRoots, now)
	if err != nil {
		return nil, err
	}

	// ── 3. Verify COSE_Sign1 signature ────────────────────────────────────
	if err := verifyCOSESign1(sig1, algorithm, issuerCert.PublicKey); err != nil {
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

	if mso.Version != "1.0" || mso.ValidityInfo.Signed.IsZero() || mso.ValidityInfo.ValidFrom.IsZero() ||
		mso.ValidityInfo.ValidUntil.IsZero() || mso.ValidityInfo.ValidUntil.Before(mso.ValidityInfo.ValidFrom) ||
		mso.ValidityInfo.Signed.After(now.Add(time.Minute)) || mso.ValidityInfo.Signed.After(mso.ValidityInfo.ValidUntil) {
		return nil, errors.New("mdoc: invalid MSO validity information")
	}
	deviceKey, keyErr := coseKeyToECDSA(mso.DeviceKeyInfo.DeviceKey)
	if opts.RequireDeviceAuth || len(opts.SessionTranscript) > 0 {
		if keyErr != nil {
			return nil, keyErr
		}
		if err := VerifyDeviceSignature(doc, opts.SessionTranscript, deviceKey); err != nil {
			return nil, err
		}
	}

	status, statusErr := msoStatusReference(mso)
	if statusErr != nil {
		return nil, statusErr
	}
	authHash, hashErr := IssuerAuthenticationHash(doc.IssuerSigned.IssuerAuth)
	if hashErr != nil {
		return nil, hashErr
	}
	return &VerifiedDocument{
		DocType:        doc.DocType,
		Attributes:     attrs,
		IssuerCert:     issuerCert,
		DeviceKey:      deviceKey,
		ValidFrom:      mso.ValidityInfo.ValidFrom,
		ValidUntil:     mso.ValidityInfo.ValidUntil,
		VerifiedChains: verifiedChains, Status: status, IssuerAuthHash: authHash,
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

// extractIssuerCert validates the complete supplied certificate chain against
// configured roots; supplied intermediates never become trust anchors.
func extractIssuerCert(sig1 *coseSig1, roots *x509.CertPool, now time.Time) (*x509.Certificate, [][]*x509.Certificate, error) {
	chain, err := extractX5ChainCerts(sig1.Protected)
	if err != nil {
		return nil, nil, err
	}
	other, err := extractX5ChainCerts(sig1.Unprotected)
	if err != nil {
		return nil, nil, err
	}
	if len(chain) > 0 && len(other) > 0 {
		return nil, nil, errors.New("mdoc: ambiguous x5chain")
	}
	if len(chain) == 0 {
		chain = other
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("mdoc: issuer x5chain is required")
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, err
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) || cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, errors.New("mdoc: invalid document signer certificate")
	}
	var verifiedChains [][]*x509.Certificate
	if roots != nil {
		intermediates := x509.NewCertPool()
		for _, der := range chain[1:] {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, nil, err
			}
			intermediates.AddCert(c)
		}
		chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		if err != nil {
			return nil, nil, fmt.Errorf("mdoc: issuer certificate trust: %w", err)
		}
		verifiedChains = chains
	}
	return cert, verifiedChains, nil
}

func extractX5ChainCerts(raw cbor.RawMessage) ([][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var headers map[int]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &headers); err != nil {
		return nil, fmt.Errorf("mdoc: malformed COSE headers: %w", err)
	}
	value, ok := headers[33]
	if !ok {
		return nil, nil
	}
	var single []byte
	if err := cbor.Unmarshal(value, &single); err == nil && len(single) > 0 {
		return [][]byte{single}, nil
	}
	var chain [][]byte
	if err := cbor.Unmarshal(value, &chain); err != nil || len(chain) == 0 || len(chain) > 10 {
		return nil, errors.New("mdoc: invalid x5chain")
	}
	for _, der := range chain {
		if len(der) == 0 {
			return nil, errors.New("mdoc: empty x5chain certificate")
		}
	}
	return chain, nil
}

func protectedAlgorithm(raw []byte) (int, error) {
	var headers map[int]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &headers); err != nil {
		return 0, err
	}
	if _, ok := headers[2]; ok {
		return 0, errors.New("mdoc: unsupported critical COSE headers")
	}
	var algorithm int
	if err := cbor.Unmarshal(headers[1], &algorithm); err != nil {
		return 0, errors.New("mdoc: protected algorithm is required")
	}
	return algorithm, nil
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
	if !ok || ecPub == nil {
		return errors.New("issuer public key is not ECDSA")
	}

	var h hash.Hash
	var expectedCurve elliptic.Curve
	switch alg {
	case algES256:
		h = sha256.New()
		expectedCurve = elliptic.P256()
	case algES384:
		h = sha512.New384()
		expectedCurve = elliptic.P384()
	case algES512:
		h = sha512.New()
		expectedCurve = elliptic.P521()
	default:
		return fmt.Errorf("unsupported COSE algorithm: %d", alg)
	}
	if ecPub.Curve != expectedCurve || len(sig1.Signature) != 2*((expectedCurve.Params().BitSize+7)/8) {
		return errors.New("mdoc: invalid ECDSA key, curve or signature length")
	}

	// Bytes validates the public point using the supported ECDSA API.
	if _, err := ecPub.Bytes(); err != nil {
		return fmt.Errorf("mdoc: invalid issuer public point: %w", err)
	}

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
		seenDigests := map[uint]bool{}
		for _, rawItem := range items {
			item, _, err := decodeIssuerSignedItem(rawItem)
			if err != nil {
				return nil, fmt.Errorf("namespace %q: %w", ns, err)
			}

			if seenDigests[item.DigestID] {
				return nil, errors.New("mdoc: duplicate disclosed digest ID")
			}
			if _, exists := nsAttrs[item.ElementIdentifier]; exists {
				return nil, errors.New("mdoc: duplicate disclosed element")
			}
			seenDigests[item.DigestID] = true
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

// BuildSessionTranscript builds the Final OID4VP redirect handover for an
// unencrypted response. Encrypted profiles must use the key-bound variant.
func BuildSessionTranscript(clientID, responseURI, nonce string) ([]byte, error) {
	return BuildRedirectSessionTranscript(clientID, responseURI, nonce, nil)
}

func BuildRedirectSessionTranscript(clientID, responseURI, nonce string, keyThumbprint []byte) ([]byte, error) {
	if clientID == "" || responseURI == "" || nonce == "" {
		return nil, errors.New("mdoc: incomplete session parameters")
	}
	var thumbprint any
	if keyThumbprint != nil {
		if len(keyThumbprint) != 32 {
			return nil, errors.New("mdoc: invalid encryption key thumbprint")
		}
		thumbprint = keyThumbprint
	}
	info, err := cbor.Marshal([]any{clientID, nonce, thumbprint, responseURI})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(info)
	return cbor.Marshal([]any{nil, nil, []any{"OpenID4VPHandover", digest[:]}})
}

// DeviceAuthenticationBytes is tag 24 wrapping the expected device
// authentication, used as detached COSE payload with EMPTY external AAD.
func DeviceAuthenticationBytes(doc Document, transcript []byte) ([]byte, error) {
	var session []cbor.RawMessage
	if err := cbor.Unmarshal(transcript, &session); err != nil || len(session) != 3 {
		return nil, errors.New("mdoc: invalid expected transcript")
	}
	var namespaces cbor.RawTag
	if err := cbor.Unmarshal(doc.DeviceSigned.NameSpaces, &namespaces); err != nil || namespaces.Number != 24 {
		return nil, errors.New("mdoc: DeviceNameSpacesBytes is required")
	}
	var nsBytes []byte
	if err := cbor.Unmarshal(namespaces.Content, &nsBytes); err != nil {
		return nil, err
	}
	var nsMap map[string]cbor.RawMessage
	if err := cbor.Unmarshal(nsBytes, &nsMap); err != nil {
		return nil, errors.New("mdoc: invalid device namespaces")
	}
	auth, err := cbor.Marshal([]any{"DeviceAuthentication", cbor.RawMessage(transcript), doc.DocType, doc.DeviceSigned.NameSpaces})
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: 24, Content: auth})
}

func VerifyDeviceSignature(doc Document, transcript []byte, deviceKey *ecdsa.PublicKey) error {
	if deviceKey == nil {
		return errors.New("mdoc: device key is required")
	}
	if len(doc.DeviceSigned.DeviceAuth.DeviceMac) > 0 {
		return errors.New("mdoc: DeviceMAC is not supported for this profile")
	}
	if len(doc.DeviceSigned.DeviceAuth.DeviceSignature) == 0 {
		return errors.New("mdoc: DeviceSignature is required")
	}
	sig, err := decodeCOSESign1(doc.DeviceSigned.DeviceAuth.DeviceSignature)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig.Payload, []byte{0xf6}) {
		return errors.New("mdoc: device signature must use a detached payload")
	}
	algorithm, err := protectedAlgorithm(sig.Protected)
	if err != nil {
		return err
	}
	auth, err := DeviceAuthenticationBytes(doc, transcript)
	if err != nil {
		return err
	}
	sig.Payload, err = cbor.Marshal(auth)
	if err != nil {
		return err
	}
	if err := verifyCOSESign1(sig, algorithm, deviceKey); err != nil {
		return fmt.Errorf("mdoc: device authentication: %w", err)
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
	if len(k.X) != (curve.Params().BitSize+7)/8 || len(k.Y) != (curve.Params().BitSize+7)/8 {
		return nil, errors.New("mdoc: invalid device public point")
	}
	point := make([]byte, 1+len(k.X)+len(k.Y))
	point[0] = 4 // SEC 1 uncompressed point.
	copy(point[1:], k.X)
	copy(point[1+len(k.X):], k.Y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("mdoc: invalid device public point: %w", err)
	}
	return pub, nil
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
