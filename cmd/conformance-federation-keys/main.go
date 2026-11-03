// conformance-federation-keys creates local laboratory RP and TA material only.
// It never contacts a backend, changes trust or uploads/starts suite modules.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func prepare(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("key file already exists; refusing to replace laboratory identities")
	} else if !os.IsNotExist(err) {
		return err
	}
	bundle := map[string]any{}
	for _, name := range []string{"rp_ec_jwks", "rp_client_jwks", "trust_anchor_jwks"} {
		var raw any
		var err error
		alg := "ES256"
		if name == "rp_client_jwks" {
			raw, err = rsa.GenerateKey(rand.Reader, 2048)
			alg = "PS256"
		} else {
			raw, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			return err
		}
		key, err := jwk.FromRaw(raw)
		if err != nil {
			return err
		}
		for field, value := range map[string]string{"kid": "lab-" + uuid.NewString(), "alg": alg, "use": "sig"} {
			if err = key.Set(field, value); err != nil {
				return err
			}
		}
		bundle[name] = map[string]any{"keys": []jwk.Key{key}}
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func main() {
	out := flag.String("out", "conformance/.local/federation/keys.json", "private local laboratory key bundle; never commit")
	flag.Parse()
	if err := prepare(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Local laboratory keys created:", *out, "(no trust configured or tests started)")
}
