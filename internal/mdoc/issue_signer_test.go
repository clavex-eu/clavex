package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

type remoteTestSigner struct {
	key    *ecdsa.PrivateKey
	wrong  bool
	fail   bool
	called bool
}

func (s *remoteTestSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s *remoteTestSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.called = true
	if s.fail {
		return nil, errors.New("remote unavailable")
	}
	key := s.key
	if s.wrong {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return key.Sign(rand.Reader, digest, opts)
}

func TestIssueMdocRemoteSignerAndCertificateWindow(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	remote := &remoteTestSigner{key: key}
	p := IssuanceParams{DocType: DocTypeEuPid, Namespace: NSEuPid, Attributes: map[string]interface{}{"given_name": "Test"}, DSKey: remote, DSCertDER: cert, ValidityHours: 720, DSCertificateValidUntil: now.Add(time.Hour)}
	issued, err := IssueMdoc(p)
	require.NoError(t, err)
	require.True(t, remote.called)
	var signed IssuerSigned
	require.NoError(t, cbor.Unmarshal(issued, &signed))
	sig1, err := decodeCOSESign1(signed.IssuerAuth)
	require.NoError(t, err)
	mso, err := decodeMSO(sig1.Payload)
	require.NoError(t, err)
	require.Equal(t, now.Add(time.Hour).Unix(), mso.ValidityInfo.ValidUntil.Unix())
	require.False(t, mso.ValidityInfo.ValidFrom.Before(tmpl.NotBefore))
	remote.wrong = true
	_, err = IssueMdoc(p)
	require.Error(t, err)
	remote.wrong = false
	remote.fail = true
	_, err = IssueMdoc(p)
	require.Error(t, err)
	p.DSCertificateValidUntil = now.Add(-time.Second)
	remote.called = false
	_, err = IssueMdoc(p)
	require.Error(t, err)
	require.False(t, remote.called)
}
