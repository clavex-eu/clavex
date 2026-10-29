package oid4w

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func multiQuery(t *testing.T, raw string) *DCQLQuery {
	t.Helper()
	var query map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(raw), &query))
	parsed, err := ParseDCQL(query)
	require.NoError(t, err)
	return parsed
}
func TestDCQLMultipleAndCredentialSets(t *testing.T) {
	q := multiQuery(t, `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"multiple":true},{"id":"b","format":"dc+sd-jwt","meta":{}},{"id":"c","format":"mso_mdoc","meta":{"doctype_value":"pid"}}],"credential_sets":[{"options":[["a","b"],["c"]]},{"required":false,"options":[["a","c"]]}]}`)
	for _, raw := range []string{`{"a":["one","two"],"b":["three"]}`, `{"c":["mdoc"]}`, `{"a":["one"],"b":["two"],"c":["mdoc"]}`} {
		_, err := q.ParsePresentations(raw)
		require.NoError(t, err, raw)
	}
	for _, raw := range []string{`{"a":["one"]}`, `{"b":["one","two"]}`, `{"extra":["one"],"c":["mdoc"]}`, `{"a":["one","one"],"b":["two"]}`, `{"c":[]}`, `{"c":["first"],"c":["second"]}`, `{"c":["mdoc"]} {}`, `{}`, `null`} {
		_, err := q.ParsePresentations(raw)
		require.Error(t, err, raw)
	}
}
func TestDCQLMissingRequiredQueriesAndInvalidPolicy(t *testing.T) {
	q := multiQuery(t, `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},{"id":"b","format":"dc+sd-jwt","meta":{}}]}`)
	_, err := q.ParsePresentations(`{"a":["one"]}`)
	require.Error(t, err)
	for _, raw := range []string{
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},{"id":"a","format":"dc+sd-jwt","meta":{}}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"multiple":null}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"multiple":"yes"}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"require_cryptographic_holder_binding":null}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt"}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[["unknown"]]}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[["a","a"]]}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[["a"]],"required":null}]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}],"credential_sets":[]}`,
		`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"claims":[]}]}`,
	} {
		var query map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(raw), &query))
		_, err := ParseDCQL(query)
		require.Error(t, err, raw)
	}
}
