package mdoc

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func statusCBOR(t *testing.T, value any) cbor.RawMessage {
	t.Helper()
	raw, err := cbor.Marshal(value)
	require.NoError(t, err)
	return raw
}

func TestMSOStatusMechanismSelection(t *testing.T) {
	ref := map[string]any{"idx": uint64(17), "uri": "https://status.example/list/1"}
	// The reference issuer advertises both mechanisms. The identifier is a
	// byte string for mdoc; it must not accidentally replace the list index.
	both := map[string]any{
		"status_list":     ref,
		"identifier_list": map[string]any{"id": []byte("123"), "uri": "https://status.example/identifiers/1"},
	}
	for _, tc := range []struct {
		name string
		mso  MSO
	}{
		{"top level", MSO{StatusList: statusCBOR(t, ref)}},
		{"nested", MSO{Status: statusCBOR(t, map[string]any{"status_list": ref})}},
		{"multiple mechanisms", MSO{Status: statusCBOR(t, both)}},
		{"future sibling", MSO{Status: statusCBOR(t, map[string]any{"status_list": ref, "future_mechanism": true})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := msoStatusReference(&tc.mso)
			require.NoError(t, err)
			require.JSONEq(t, `{"status_list":{"idx":17,"uri":"https://status.example/list/1"}}`, string(raw))
		})
	}
	raw, err := msoStatusReference(&MSO{})
	require.NoError(t, err)
	require.Nil(t, raw)
}

func TestMSOStatusMalformedReferencesFailClosed(t *testing.T) {
	ref := map[string]any{"idx": 0, "uri": "https://status.example/list/1"}
	valid := statusCBOR(t, ref)
	// Construct duplicate keys directly; Go maps cannot represent them.
	duplicateMechanism := append(cbor.RawMessage{0xa2}, statusCBOR(t, "status_list")...)
	duplicateMechanism = append(duplicateMechanism, valid...)
	duplicateMechanism = append(duplicateMechanism, statusCBOR(t, "status_list")...)
	duplicateMechanism = append(duplicateMechanism, valid...)
	duplicateIndex := append(cbor.RawMessage{0xa3, 0x63, 'i', 'd', 'x', 0x00, 0x63, 'i', 'd', 'x', 0x01}, statusCBOR(t, "uri")...)
	duplicateIndex = append(duplicateIndex, statusCBOR(t, "https://status.example/list/1")...)
	for _, tc := range []struct {
		name string
		mso  MSO
	}{
		{"ambiguous layouts", MSO{Status: statusCBOR(t, map[string]any{"status_list": ref}), StatusList: valid}},
		{"identifier only", MSO{Status: statusCBOR(t, map[string]any{"identifier_list": ref})}},
		{"empty mechanisms", MSO{Status: statusCBOR(t, map[string]any{})}},
		{"null mechanisms", MSO{Status: statusCBOR(t, nil)}},
		{"malformed mechanisms", MSO{Status: cbor.RawMessage{0xff}}},
		{"duplicate mechanisms", MSO{Status: duplicateMechanism}},
		{"duplicate index", MSO{StatusList: duplicateIndex}},
		{"missing list with extension", MSO{Status: statusCBOR(t, map[string]any{"identifier_list": ref, "other": true})}},
		{"null list with extension", MSO{Status: statusCBOR(t, map[string]any{"status_list": nil, "identifier_list": ref})}},
		{"missing index", MSO{StatusList: statusCBOR(t, map[string]any{"uri": "https://status.example/list/1"})}},
		{"negative index", MSO{StatusList: statusCBOR(t, map[string]any{"idx": -1, "uri": "https://status.example/list/1"})}},
		{"overflow index", MSO{StatusList: statusCBOR(t, map[string]any{"idx": uint64(2147483648), "uri": "https://status.example/list/1"})}},
		{"missing URI", MSO{StatusList: statusCBOR(t, map[string]any{"idx": 0})}},
		{"wrong URI type", MSO{StatusList: statusCBOR(t, map[string]any{"idx": 0, "uri": []byte("https://status.example/list/1")})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := msoStatusReference(&tc.mso)
			require.Error(t, err)
			require.Nil(t, raw)
		})
	}
}

func TestMdocSignedMultipleStatusMechanismsPreserveDeviceBinding(t *testing.T) {
	response, roots, transcript, _ := testTrustedMdocWithMSO(t, func(mso *MSO) {
		mso.Status = statusCBOR(t, map[string]any{
			"status_list":     map[string]any{"idx": 17, "uri": "https://status.example/list/1"},
			"identifier_list": map[string]any{"id": []byte("17"), "uri": "https://status.example/identifiers/1"},
		})
	})
	opts := VerificationOptions{TrustedRoots: roots, RequireTrustedIssuer: true, RequireDeviceAuth: true, SessionTranscript: transcript}
	verified, errs := VerifyDeviceResponse(response, opts)
	require.Empty(t, errs)
	require.Len(t, verified, 1)
	var selected map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(verified[0].Status, &selected))
	require.Len(t, selected, 1)
	require.JSONEq(t, `{"idx":17,"uri":"https://status.example/list/1"}`, string(selected["status_list"]))
	// An extensible status object cannot bypass the existing device proof.
	response.Documents[0].DeviceSigned.DeviceAuth.DeviceSignature = nil
	_, errs = VerifyDeviceResponse(response, opts)
	require.NotEmpty(t, errs)
}
