// Package analytics — blindtoken.go
//
// RSA blind signature scheme for privacy-preserving credential analytics.
// Based on Chaum (1982) — US Patent 4,759,063, now expired.
//
// Privacy guarantee
// -----------------
// The issuer signs a *blinded* token: it sees m_blind = m * r^e mod n but
// never m itself.  The wallet unblinds to get s = m^d mod n.  When the wallet
// later redeems (m, s), the issuer can verify s^e ≡ SHA-256(m) (mod n) — the
// token is valid — but cannot correlate this redemption with the issuance
// event because it never saw m.  Unlinkability is therefore cryptographic,
// not a policy promise.
//
// Protocol
// --------
//  Wallet (before presentation):
//    1. Generate random 32-byte msg.
//    2. Compute m = SHA-256(msg) mod n.
//    3. Pick random r coprime to n; compute m_blind = m · r^e mod n.
//    4. POST /analytics/token { "blinded": hex(m_blind) } → s_blind hex.
//    5. Compute s = s_blind · r⁻¹ mod n  (unblind).
//    6. Store (msg, s) as a single-use analytics token.
//
//  Wallet (when presenting credential to a verifier):
//    7. POST /analytics/report { token_msg, token_sig, vct, purpose_hint, country_hint }.
//
//  Issuer analytics endpoint:
//    8. Verify s^e ≡ SHA-256(msg) (mod n).
//    9. Check msg not already redeemed (spent-token table).
//   10. Increment aggregate counter for (vct, day, purpose_hint, country_hint).
package analytics

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// SignBlind is the server-side blind-signing operation.
// It computes s_blind = m_blind^d mod n and returns it as a hex string.
// The server never sees the actual token message.
func SignBlind(blindedHex string, priv *rsa.PrivateKey) (string, error) {
	b, err := hex.DecodeString(blindedHex)
	if err != nil {
		return "", fmt.Errorf("blindtoken: decode blinded: %w", err)
	}
	mBlind := new(big.Int).SetBytes(b)
	if mBlind.Sign() <= 0 || mBlind.Cmp(priv.N) >= 0 {
		return "", fmt.Errorf("blindtoken: blinded value out of range")
	}
	sBlind := new(big.Int).Exp(mBlind, priv.D, priv.N)
	// Zero-pad to exactly len(N) bytes so the wallet can parse it unambiguously.
	nBytes := (priv.N.BitLen() + 7) / 8
	out := make([]byte, nBytes)
	sBlind.FillBytes(out)
	return hex.EncodeToString(out), nil
}

// Verify checks that sigHex is a valid RSA blind signature on msgHex.
// Specifically: sig^e ≡ SHA-256(msg) (mod n).
func Verify(msgHex, sigHex string, pub *rsa.PublicKey) bool {
	msgBytes, err := hex.DecodeString(msgHex)
	if err != nil {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	n := pub.N
	e := big.NewInt(int64(pub.E))

	// expected = SHA-256(msg) mod n
	h := sha256.Sum256(msgBytes)
	expected := new(big.Int).SetBytes(h[:])
	expected.Mod(expected, n)

	// actual = sig^e mod n
	sig := new(big.Int).SetBytes(sigBytes)
	if sig.Sign() <= 0 || sig.Cmp(n) >= 0 {
		return false
	}
	actual := new(big.Int).Exp(sig, e, n)
	actual.Mod(actual, n)

	return expected.Cmp(actual) == 0
}

// TokenHash returns SHA-256(hex.Decode(msgHex)) as a hex string.
// Used as the primary key in the spent-token table.
func TokenHash(msgHex string) (string, error) {
	b, err := hex.DecodeString(msgHex)
	if err != nil {
		return "", fmt.Errorf("blindtoken: decode msg: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// GenerateKeyPair creates a fresh RSA-2048 key pair for analytics signing.
// This is called once per org and the result is persisted in analytics_keys.
func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// ValidateBlinded checks basic sanity of a blinded message before signing:
// it must be a valid hex string whose decoded value is in [1, n-1].
func ValidateBlinded(blindedHex string, pub *rsa.PublicKey) error {
	b, err := hex.DecodeString(blindedHex)
	if err != nil {
		return fmt.Errorf("blindtoken: invalid hex: %w", err)
	}
	v := new(big.Int).SetBytes(b)
	if v.Sign() <= 0 || v.Cmp(pub.N) >= 0 {
		return fmt.Errorf("blindtoken: blinded value must be in (0, n)")
	}
	return nil
}
