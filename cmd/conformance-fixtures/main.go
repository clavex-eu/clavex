// conformance-fixtures creates local laboratory plans and keys from public templates.
// It never contacts Clavex, changes tenant trust, deploys, or starts a suite test.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type material struct {
	Backend string         `json:"backend_origin"`
	Suite   string         `json:"suite_origin"`
	Values  map[string]any `json:"values"`
}

func main() {
	dir := flag.String("dir", "conformance", "local output directory (contains private keys)")
	templates := flag.String("templates", "conformance/templates", "public plan templates")
	backend := flag.String("backend-origin", "https://issuer.example", "HTTPS origin of your own test backend")
	suite := flag.String("suite-origin", "https://localhost.emobix.co.uk:8443", "HTTPS suite origin")
	flag.Parse()
	if err := prepare(*dir, *templates, *backend, *suite); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Local plans prepared. Configure your test backend with the generated issuer certificates, then seed the test tenant. No service was contacted.")
}

func origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("expected an HTTPS origin without credentials, query or path")
	}
	return u, nil
}
func writePrivate(path string, data []byte) error {
	if s, err := os.Lstat(path); err == nil && (!s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0) {
		return fmt.Errorf("unsafe existing fixture permissions: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func certKey(key *ecdsa.PrivateKey) (string, error) {
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), nil
}
func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
func makeJWK(name string) (map[string]any, error) {
	key, e := newKey()
	if e != nil {
		return nil, e
	}
	j, e := jwk.FromRaw(key)
	if e != nil {
		return nil, e
	}
	if e = j.Set(jwk.KeyIDKey, "local-"+name); e != nil {
		return nil, e
	}
	if e = j.Set(jwk.AlgorithmKey, "ES256"); e != nil {
		return nil, e
	}
	if e = j.Set(jwk.KeyUsageKey, "sig"); e != nil {
		return nil, e
	}
	n, e := serial()
	if e != nil {
		return nil, e
	}
	c := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Local conformance " + name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(j)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	e = json.Unmarshal(b, &out)
	if e == nil {
		out["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	}
	return out, e
}
func generate(backend, suite string) (material, error) {
	m := material{Backend: backend, Suite: suite, Values: map[string]any{}}
	for _, name := range []string{"wallet1", "wallet2", "key-attestation", "fapi1", "fapi2"} {
		k, e := makeJWK(name)
		if e != nil {
			return m, e
		}
		m.Values["JWK:"+name] = k
	}
	root, e := newKey()
	if e != nil {
		return m, e
	}
	n, e := serial()
	if e != nil {
		return m, e
	}
	ca := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Local Clavex laboratory issuer CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &root.PublicKey, root)
	if e != nil {
		return m, e
	}
	m.Values["PEM:issuer-root-cert"] = certPEM(der)
	rootPEM, e := certKey(root)
	if e != nil {
		return m, e
	}
	m.Values["PEM:issuer-root-key"] = rootPEM
	u, e := origin(backend)
	if e != nil {
		return m, e
	}
	for _, name := range []string{"issuer", "metadata", "mtls1", "mtls2"} {
		k, e := newKey()
		if e != nil {
			return m, e
		}
		n, e := serial()
		if e != nil {
			return m, e
		}
		c := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "Local conformance " + name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(0, 1, 0), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
		if strings.HasPrefix(name, "mtls") {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			c.DNSNames = []string{u.Hostname()}
		}
		b, e := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, root)
		if e != nil {
			return m, e
		}
		kp, e := certKey(k)
		if e != nil {
			return m, e
		}
		m.Values["PEM:"+name+"-key"] = kp
		m.Values["PEM:"+name+"-cert"] = certPEM(b) + certPEM(der)
	}
	return m, nil
}
func resolve(v any, m material) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			z, e := resolve(v, m)
			if e != nil {
				return nil, e
			}
			out[k] = z
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			z, e := resolve(v, m)
			if e != nil {
				return nil, e
			}
			out[i] = z
		}
		return out, nil
	case string:
		if strings.HasPrefix(x, "${JWK:") || strings.HasPrefix(x, "${PEM:") {
			z, ok := m.Values[strings.TrimSuffix(strings.TrimPrefix(x, "${"), "}")]
			if !ok {
				return nil, fmt.Errorf("unknown template fixture")
			}
			return z, nil
		}
		x = strings.ReplaceAll(strings.ReplaceAll(x, "${BACKEND_ORIGIN}", m.Backend), "${SUITE_ORIGIN}", m.Suite)
		if strings.Contains(x, "${BACKEND_ORIGIN}") || strings.Contains(x, "${SUITE_ORIGIN}") {
			return nil, fmt.Errorf("unresolved template placeholder")
		}
		return x, nil
	default:
		return v, nil
	}
}
func prepare(dir, templates, backend, suite string) error {
	if _, e := origin(backend); e != nil {
		return e
	}
	if _, e := origin(suite); e != nil {
		return e
	}
	backend = strings.TrimSuffix(backend, "/")
	suite = strings.TrimSuffix(suite, "/")
	cache := filepath.Join(dir, ".local", "fixture-material.json")
	if e := os.MkdirAll(filepath.Dir(cache), 0700); e != nil {
		return e
	}
	var m material
	if s, e := os.Lstat(cache); e == nil {
		if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("unsafe fixture material permissions")
		}
		b, e := os.ReadFile(cache)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &m); e != nil {
			return e
		}
		if m.Backend != backend || m.Suite != suite {
			return fmt.Errorf("fixture origins changed; use a separate output directory")
		}
	} else if !os.IsNotExist(e) {
		return e
	} else {
		for _, pattern := range []string{"*-private-key.jwk", "*-plan.json"} {
			existing, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				return err
			}
			if len(existing) > 0 {
				return fmt.Errorf("existing fixtures without matching material cache; use a separate output directory")
			}
		}
		m, e = generate(backend, suite)
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(m, "", "  ")
		if e != nil {
			return e
		}
		if e = writePrivate(cache, b); e != nil {
			return e
		}
	}
	for key, file := range map[string]string{"wallet1": "oid4vci-wallet-private-key.jwk", "wallet2": "oid4vci-wallet2-private-key.jwk"} {
		b, e := json.Marshal(m.Values["JWK:"+key])
		if e != nil {
			return e
		}
		if e = writePrivate(filepath.Join(dir, file), b); e != nil {
			return e
		}
	}
	for _, name := range []string{"issuer-root", "issuer", "metadata", "mtls1", "mtls2"} {
		for _, kind := range []string{"key", "cert"} {
			v, ok := m.Values["PEM:"+name+"-"+kind].(string)
			if !ok {
				return fmt.Errorf("incomplete fixture material")
			}
			if e := writePrivate(filepath.Join(filepath.Dir(cache), name+"-"+kind+".pem"), []byte(v)); e != nil {
				return e
			}
		}
	}
	paths, e := filepath.Glob(filepath.Join(templates, "*plan.json"))
	if e != nil {
		return e
	}
	if len(paths) == 0 {
		return fmt.Errorf("no public plan templates found")
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		var raw any
		if e = json.Unmarshal(b, &raw); e != nil {
			return e
		}
		v, e := resolve(raw, m)
		if e != nil {
			return e
		}
		b, e = json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		if e = writePrivate(filepath.Join(dir, filepath.Base(p)), append(b, '\n')); e != nil {
			return e
		}
	}
	return nil
}
