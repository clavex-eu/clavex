package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixturesGenerateIndependentKeysAndRetainMaterial(t *testing.T) {
	templates := t.TempDir()
	dir := t.TempDir()
	raw := `{"alias":"offline","server":{"url":"${BACKEND_ORIGIN}/conformance"},"client":{"key":"${JWK:wallet1}"},"client2":{"key":"${JWK:wallet2}"},"credential":{"trust_anchor_pem":"${PEM:issuer-root-cert}"}}`
	if err := os.WriteFile(filepath.Join(templates, "offline-plan.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepare(dir, templates, "https://issuer.example", "https://suite.example"); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, ".local", "fixture-material.json")
	before, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var m material
	if err = json.Unmarshal(before, &m); err != nil {
		t.Fatal(err)
	}
	one := m.Values["JWK:wallet1"].(map[string]any)
	two := m.Values["JWK:wallet2"].(map[string]any)
	if one["d"] == two["d"] {
		t.Fatal("wallets share a private key")
	}
	b, err := os.ReadFile(filepath.Join(dir, "offline-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "${") || !strings.Contains(string(b), "https://issuer.example/conformance") {
		t.Fatal("unresolved template")
	}
	if err = prepare(dir, templates, "https://issuer.example", "https://suite.example"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("fixture keys rotated implicitly")
	}
	if err = prepare(dir, templates, "https://different.example", "https://suite.example"); err == nil {
		t.Fatal("changed origin accepted")
	}
	if err = os.Chmod(cache, 0644); err != nil {
		t.Fatal(err)
	}
	if err = prepare(dir, templates, "https://issuer.example", "https://suite.example"); err == nil {
		t.Fatal("public private-key permissions accepted")
	}
}
func TestFixtureOriginsAndOutputSymlinks(t *testing.T) {
	for _, u := range []string{"http://issuer.example", "https://user:pass@issuer.example", "https://issuer.example/path", "https://issuer.example?secret=1"} {
		if _, err := origin(u); err == nil {
			t.Fatalf("unsafe origin accepted: %s", u)
		}
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(link, []byte("replace")); err == nil {
		t.Fatal("output symlink accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "preserve" {
		t.Fatal("symlink target modified")
	}
}
