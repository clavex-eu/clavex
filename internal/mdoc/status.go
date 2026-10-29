package mdoc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Read only the signed MSO extension, not similarly named disclosed attributes.
// The supported layouts are MSO.status.status_list and MSO.status_list; an
// ambiguous combination is rejected. Ecosystem/profile selection is explicit
// at issuance; neither layout is claimed as universal ISO conformance.
func msoStatusReference(mso *MSO) (json.RawMessage, error) {
	if len(mso.Status) == 0 && len(mso.StatusList) == 0 {
		return nil, nil
	}
	if len(mso.Status) > 0 && len(mso.StatusList) > 0 {
		return nil, fmt.Errorf("mdoc: ambiguous status extensions")
	}
	value := mso.StatusList
	if len(mso.Status) > 0 {
		var mechanisms map[string]cbor.RawMessage
		if cbor.Unmarshal(mso.Status, &mechanisms) != nil || len(mechanisms) != 1 {
			return nil, fmt.Errorf("mdoc: unsupported status mechanism")
		}
		value = mechanisms["status_list"]
	}
	var ref struct {
		Index *uint64 `cbor:"idx"`
		URI   *string `cbor:"uri"`
	}
	if cbor.Unmarshal(value, &ref) != nil || ref.Index == nil || *ref.Index > 2147483647 || ref.URI == nil {
		return nil, fmt.Errorf("mdoc: invalid status reference")
	}
	return json.Marshal(map[string]any{"status_list": map[string]any{"idx": *ref.Index, "uri": *ref.URI}})
}

// Signature input fields remain stable across selective disclosure and changes
// to unprotected chain packaging. Unprotected headers are not identity evidence.
func IssuerAuthenticationHash(raw cbor.RawMessage) (string, error) {
	signed, err := decodeCOSESign1(raw)
	if err != nil {
		return "", err
	}
	canonical, err := cbor.Marshal([]any{signed.Protected, []byte(signed.Payload), signed.Signature})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}
