package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedCert generates an ECDSA P-256 self-signed certificate for
// "localhost"/127.0.0.1 and writes the cert and key PEM files into dir,
// returning their paths.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// TestBuildServerTLSConfig_NegotiatesX25519MLKEM768 confirms that a server built
// with BuildServerTLSConfig negotiates the hybrid post-quantum key-exchange
// mechanism X25519MLKEM768 (FIPS 203 / ML-KEM-768) when the client supports it.
//
// This is the transport-layer PQC counterpart to the ML-DSA-65 token-signature
// work in internal/oidc/pqc_signer.go — a conceptually separate layer.
func TestBuildServerTLSConfig_NegotiatesX25519MLKEM768(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg, err := BuildServerTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverCurve := make(chan tls.CurveID, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		tconn := conn.(*tls.Conn)
		if err := tconn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		serverCurve <- tconn.ConnectionState().CurveID
	}()

	// Trust the self-signed cert.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("append cert to pool")
	}

	// Client explicitly offers X25519MLKEM768 first so negotiation is deterministic.
	clientCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	clientCurve := conn.ConnectionState().CurveID
	if clientCurve != tls.X25519MLKEM768 {
		t.Fatalf("client negotiated curve = %v, want X25519MLKEM768", clientCurve)
	}

	select {
	case err := <-serverErr:
		t.Fatalf("server: %v", err)
	case sc := <-serverCurve:
		if sc != tls.X25519MLKEM768 {
			t.Fatalf("server negotiated curve = %v, want X25519MLKEM768", sc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server handshake")
	}
}

// TestBuildServerTLSConfig_PinsCurvePreferences asserts that BuildServerTLSConfig
// pins X25519MLKEM768 as the first (most-preferred) key-exchange mechanism rather
// than relying on Go's implicit defaults, which may change across releases.
func TestBuildServerTLSConfig_PinsCurvePreferences(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	cfg, err := BuildServerTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("BuildServerTLSConfig: %v", err)
	}

	if len(cfg.CurvePreferences) == 0 {
		t.Fatal("CurvePreferences not pinned (nil relies on implicit Go defaults)")
	}
	if cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("CurvePreferences[0] = %v, want X25519MLKEM768", cfg.CurvePreferences[0])
	}
}
