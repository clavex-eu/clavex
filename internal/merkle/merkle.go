// Package merkle implements an incremental SHA-256 Merkle tree for the
// audit log, providing cryptographic immutability proofs compatible with
// NIS2, GDPR, and enterprise finance compliance requirements.
//
// # How it works
//
//  1. Every CHECKPOINT_SIZE audit_log rows (per org), the sealer fetches
//     the canonical JSON payload for each row in the batch.
//  2. Each row is hashed individually (leaf = SHA-256(row_json)).
//  3. Pairs of leaf hashes are recursively hashed: parent = SHA-256(left||right).
//     Odd-length levels repeat the last node.
//  4. The Merkle root, the hash of the previous checkpoint's root, and the
//     resulting chain hash are signed with the server's RS256 key.
//  5. The checkpoint is stored in audit_merkle_checkpoints.
//
// # Verification
//
// An auditor can:
//  1. Export audit rows in JSON (ordered by id).
//  2. Recompute leaf hashes locally.
//  3. Rebuild the Merkle tree.
//  4. Compare the root against the stored checkpoint.
//  5. Verify the RS256 signature with the server's public JWKS key.
//  6. Walk the chain_hash chain to detect deletions or insertions.
package merkle

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha256" // ensure SHA-256 is registered
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CheckpointSize is the default number of audit rows per Merkle batch.
// Can be overridden via Sealer options.
const CheckpointSize = 100

// LeafHash computes the SHA-256 hash of a single audit log row, given its
// canonical JSON representation.  The canonical form is produced by
// AuditRepository.CanonicalJSON.
func LeafHash(rowJSON []byte) []byte {
	h := sha256.Sum256(rowJSON)
	return h[:]
}

// Root computes the Merkle root of a list of leaf hashes.
// Returns an empty slice if leaves is empty.
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // duplicate last node for odd-length levels
			if i+1 < len(level) {
				right = level[i+1]
			}
			parent := hashPair(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}

// Proof holds the data for a single Merkle checkpoint.
type Proof struct {
	OrgID      string `json:"org_id"`
	FirstLogID int64  `json:"first_log_id"`
	LastLogID  int64  `json:"last_log_id"`
	LogCount   int    `json:"log_count"`
	// MerkleRoot is the hex-encoded SHA-256 Merkle root.
	MerkleRoot string `json:"merkle_root"`
	// PrevRoot is the hex-encoded Merkle root of the previous checkpoint
	// (empty string for the first checkpoint in an org).
	PrevRoot string `json:"prev_root"`
	// ChainHash is SHA-256(prev_root || merkle_root), hex-encoded.
	// Walking the chain detects insertions, deletions, and reordering.
	ChainHash string `json:"chain_hash"`
	// Signature is the RS256 signature over ChainHash (base64url-encoded).
	Signature string `json:"signature"`
	// KID identifies the signing key (matches JWKS kid).
	KID string `json:"kid"`
}

// Sign computes the chain hash and creates an RS256 signature over it.
// prevRoot must be the hex-encoded Merkle root of the previous checkpoint,
// or "" for the very first checkpoint.
func Sign(root []byte, prevRoot string, key *rsa.PrivateKey, kid string, orgID string,
	firstID, lastID int64, count int) (*Proof, error) {

	rootHex := hex.EncodeToString(root)
	chainInput := prevRoot + rootHex
	chainHashBytes := sha256.Sum256([]byte(chainInput))
	chainHex := hex.EncodeToString(chainHashBytes[:])

	// RS256: sign the chain hash digest.
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, chainHashBytes[:])
	if err != nil {
		return nil, fmt.Errorf("merkle sign: %w", err)
	}

	return &Proof{
		OrgID:      orgID,
		FirstLogID: firstID,
		LastLogID:  lastID,
		LogCount:   count,
		MerkleRoot: rootHex,
		PrevRoot:   prevRoot,
		ChainHash:  chainHex,
		Signature:  base64.RawURLEncoding.EncodeToString(sig),
		KID:        kid,
	}, nil
}

// Verify checks the chain hash and RS256 signature of a proof.
func Verify(p *Proof, pubKey *rsa.PublicKey) error {
	chainInput := p.PrevRoot + p.MerkleRoot
	chainHashBytes := sha256.Sum256([]byte(chainInput))

	if hex.EncodeToString(chainHashBytes[:]) != p.ChainHash {
		return fmt.Errorf("merkle: chain hash mismatch")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("merkle: signature base64: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, chainHashBytes[:], sigBytes); err != nil {
		return fmt.Errorf("merkle: signature invalid: %w", err)
	}
	return nil
}

// VerifyChain verifies a sequence of proofs forms a valid chain.
// proofs must be ordered by first_log_id ASC.
func VerifyChain(proofs []*Proof, pubKey *rsa.PublicKey) error {
	for i, p := range proofs {
		if err := Verify(p, pubKey); err != nil {
			return fmt.Errorf("merkle: checkpoint[%d]: %w", i, err)
		}
		if i > 0 && p.PrevRoot != proofs[i-1].MerkleRoot {
			return fmt.Errorf("merkle: chain broken at checkpoint[%d]: prev_root mismatch", i)
		}
	}
	return nil
}

// RebuildRoot recomputes the Merkle root from a list of raw row JSON payloads.
// rowJSONs must be in ascending id order, matching the original batch.
func RebuildRoot(rowJSONs [][]byte) []byte {
	leaves := make([][]byte, len(rowJSONs))
	for i, j := range rowJSONs {
		leaves[i] = LeafHash(j)
	}
	return Root(leaves)
}

// CanonicalAuditJSON returns the deterministic JSON used as leaf input.
// Only the fields that cannot be retroactively changed are included.
func CanonicalAuditJSON(id int64, eventID, orgID, action, status string, createdAt string) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"id":         id,
		"event_id":   eventID,
		"org_id":     orgID,
		"action":     action,
		"status":     status,
		"created_at": createdAt,
	})
}

// hashPair returns SHA-256(left || right).
func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
