package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// BuildServerTLSConfig constructs a *tls.Config for the Clavex HTTPS listener.
//
// Parameters:
//
//	certFile    — PEM file containing the server TLS certificate chain.
//	keyFile     — PEM file containing the server private key.
//	caCertFile  — PEM file (CA bundle) used to verify client certificates.
//	              When non-empty, ClientAuth is set to RequireAndVerifyClientCert
//	              (full mTLS). When empty but certFile/keyFile are provided,
//	              ClientAuth is set to RequestClientCert so that clients MAY
//	              present a certificate for RFC 8705 certificate-bound access
//	              tokens without being required to do so.
//
// The returned config uses sane TLS 1.2+ defaults with strong cipher suites
// compatible with FAPI 2.0 requirements.
func BuildServerTLSConfig(certFile, keyFile, caCertFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load server cert/key: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// FAPI 2.0 mandates TLS 1.2+ with forward secrecy.
		// Go's default cipher suite selection already prefers ECDHE; pin the list
		// to eliminate static RSA key exchange and RC4.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	if caCertFile != "" {
		pool, err := loadCertPool(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load client CA bundle: %w", err)
		}
		cfg.ClientCAs = pool
		// RequireAndVerifyClientCert: client MUST present a valid cert.
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		// RequestClientCert: client MAY present a cert (used for RFC 8705
		// certificate-bound access tokens when mTLS is not enforced globally).
		cfg.ClientAuth = tls.RequestClientCert
	}

	return cfg, nil
}

// loadCertPool reads a PEM CA bundle from path and returns a *x509.CertPool.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}
	return pool, nil
}
