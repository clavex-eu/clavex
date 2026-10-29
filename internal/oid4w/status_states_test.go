package oid4w

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStatusListWidthsAndSuspensionPreserveNeighbours(t *testing.T) {
	for _, width := range []int{1, 2, 4, 8} {
		list := NewStatusListWithBits(width)
		require.NotNil(t, list)
		for _, index := range []int{0, 1, 7, 8, 65535} {
			require.NoError(t, list.Set(index, 1))
		}
		if width > 1 {
			require.NoError(t, list.Set(1, StatusSuspended))
		}
		encoded, err := list.Encode()
		require.NoError(t, err)
		decoded, err := DecodeStatusListWithBits(encoded, width)
		require.NoError(t, err)
		for _, index := range []int{0, 1, 7, 8, 65535} {
			state, err := decoded.Get(index)
			require.NoError(t, err)
			expected := byte(1)
			if index == 1 && width > 1 {
				expected = StatusSuspended
			}
			require.Equal(t, expected, state)
		}
		state, err := decoded.Get(2)
		require.NoError(t, err)
		require.Zero(t, state)
		require.Error(t, decoded.Set(65536, 0))
		require.Error(t, decoded.Set(-1, 0))
	}
	require.Nil(t, NewStatusListWithBits(3))
}
