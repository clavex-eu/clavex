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
// ambiguous combination is rejected. A status object is extensible: select its
// status_list even when another mechanism (e.g. identifier_list) is advertised.
// This extracts a reference, not a positive status decision: the caller must
// authenticate and check the selected list. Other mechanisms are not evaluated.
func msoStatusReference(mso *MSO) (json.RawMessage, error) {
	if len(mso.Status) == 0 && len(mso.StatusList) == 0 {
		return nil, nil
	}
	if len(mso.Status) > 0 && len(mso.StatusList) > 0 {
		return nil, fmt.Errorf("mdoc: ambiguous status extensions")
	}
	value := mso.StatusList
	decoder, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return nil, fmt.Errorf("mdoc: invalid status decoder")
	}
	if len(mso.Status) > 0 {
		var mechanisms map[string]cbor.RawMessage
		if decoder.Unmarshal(mso.Status, &mechanisms) != nil {
			return nil, fmt.Errorf("mdoc: unsupported status mechanism")
		}
		var found bool
		value, found = mechanisms["status_list"]
		if !found {
			return nil, fmt.Errorf("mdoc: unsupported status mechanism")
		}
	}
	var ref struct {
		Index *uint64 `cbor:"idx"`
		URI   *string `cbor:"uri"`
	}
	if decoder.Unmarshal(value, &ref) != nil || ref.Index == nil || *ref.Index > 2147483647 || ref.URI == nil {
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
