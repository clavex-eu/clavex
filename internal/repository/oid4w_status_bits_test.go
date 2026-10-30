package repository

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusBitListWidenPreservesRevocations(t *testing.T) {
	original := &statusBitList{bits: make([]byte, 65536/8), width: 1}
	for i := range original.bits {
		original.bits[i] = byte(i % 256)
	}
	original.bits[len(original.bits)-1] = 0x80
	widened, err := original.widen()
	require.NoError(t, err)
	require.Equal(t, 2, widened.width)
	for i := 0; i < 65536; i++ {
		want := (original.bits[i/8] >> uint(i%8)) & 1
		got := (widened.bits[i/4] >> uint((i%4)*2)) & 3
		require.Equal(t, want, got, "status index %d", i)
	}
	require.NoError(t, widened.Set(65534, 2))
	encoded, err := widened.Encode()
	require.NoError(t, err)
	restored, err := decodeStatusListRawWithBits(encoded, 2)
	require.NoError(t, err)
	require.Equal(t, widened, restored)
	require.Equal(t, byte(2), (restored.bits[65534/4]>>4)&3)
	require.Equal(t, byte(1), (restored.bits[65535/4]>>6)&3)
}
