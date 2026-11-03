package oidc

import (
	"runtime"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/require"
)

func TestSigningSnapshotKeepsKIDAndKeyTogether(t *testing.T) {
	first, second := newTestKeySet(t), newTestKeySet(t)
	signer := newTestKeySet(t)
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, key := range []*KeySet{first, second} {
				signer.mu.Lock()
				signer.privateKey = key.privateKey
				signer.kid = key.kid
				signer.mu.Unlock()
				runtime.Gosched()
			}
		}
	})
	t.Cleanup(func() { close(done); wg.Wait() })
	// Initialise from one of the two published keys before any token is signed.
	signer.mu.Lock()
	signer.privateKey = first.privateKey
	signer.kid = first.kid
	signer.mu.Unlock()
	for range 40 {
		raw, err := BuildJARMResponse(signer, "https://issuer.invalid/tenant", "client", "code", "state")
		require.NoError(t, err)
		msg, err := jws.Parse([]byte(raw))
		require.NoError(t, err)
		key := first
		if msg.Signatures()[0].ProtectedHeaders().KeyID() == second.kid {
			key = second
		}
		_, err = jws.Verify([]byte(raw), jws.WithKey(jwa.PS256, key.PublicKey()))
		require.NoError(t, err)
	}
}
