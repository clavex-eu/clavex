package trustcatalog

import (
	"encoding/json"
	"testing"
)

func TestReferenceCatalogueIsPinnedDevelopmentMaterial(t *testing.T) {
	c, err := Reference()
	if err != nil {
		t.Fatal(err)
	}
	if c.Environment != "test" || len(c.Entries) != 7 {
		t.Fatal("unexpected catalogue profile")
	}
	for _, a := range c.Entries {
		if a.NotBefore.IsZero() || !a.NotAfter.After(a.NotBefore) || a.SubjectDN == "" {
			t.Fatal("missing public certificate metadata")
		}
		if a.Country == "LU" && a.SHA256Fingerprint != "7d8713f9aeaa821244a22e3559e095e5bb84cce6d732840a9d371055a3059178" {
			t.Fatal("the independently verified LU test anchor changed")
		}
	}
	c.Entries[0].DocTypes[0] = "unrelated"
	fresh, err := Reference()
	if err != nil || fresh.Entries[0].DocTypes[0] == "unrelated" {
		t.Fatal("callers can mutate shared catalogue scope")
	}
}

func TestCatalogueRejectsTamperedTrustMaterial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Catalog)
	}{
		{"production claim", func(c *Catalog) { c.Environment = "production" }},
		{"changed certificate pin", func(c *Catalog) { c.Entries[0].SHA256Fingerprint = "wrong" }},
		{"duplicate anchor", func(c *Catalog) { c.Entries[1] = c.Entries[0] }},
		{"foreign source", func(c *Catalog) { c.Entries[0].SourceURL = "https://example.com/root.pem" }},
		{"extra PEM", func(c *Catalog) { c.Entries[0].PEM += c.Entries[1].PEM }},
		{"country mismatch", func(c *Catalog) { c.Entries[0].Country = "XX" }},
		{"scope expansion", func(c *Catalog) { c.Entries[0].DocTypes = []string{"unrelated"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Catalog
			if err := json.Unmarshal(referenceData, &c); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&c)
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parse(raw); err == nil {
				t.Fatal("accepted modified trust policy")
			}
		})
	}
}
