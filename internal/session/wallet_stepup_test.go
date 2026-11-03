package session

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestWalletStepUpAtomicSubjectConsumption(t *testing.T) {
	rdb := otpRedis(t)
	s := NewStore(rdb)
	ctx := context.Background()
	c := &WalletStepUpChallenge{ID: uuid.NewString(), OrgID: uuid.NewString(), UserID: uuid.NewString(), Nonce: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, s.SaveWalletStepUpChallenge(ctx, c))
	t.Cleanup(func() { rdb.Del(ctx, prefixWalletStepup+c.ID, prefixWalletStepupUser+c.OrgID+":"+c.UserID) })
	require.ErrorIs(t, s.CompleteWalletStepUpForSubject(ctx, c.ID, "other-org", c.UserID, c.Nonce), ErrWalletStepUpConsumed)
	require.ErrorIs(t, s.CompleteWalletStepUpForSubject(ctx, c.ID, c.OrgID, "other-user", c.Nonce), ErrWalletStepUpConsumed)
	require.ErrorIs(t, s.CompleteWalletStepUpForSubject(ctx, c.ID, c.OrgID, c.UserID, "other-nonce"), ErrWalletStepUpConsumed)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.CompleteWalletStepUpForSubject(ctx, c.ID, c.OrgID, c.UserID, c.Nonce) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.ErrorIs(t, s.FailWalletStepUpChallenge(ctx, c.ID), ErrWalletStepUpConsumed)
	saved, err := s.GetWalletStepUpChallenge(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", saved.Status)
}

func TestWalletStepUpRejectsExpiredPayloadEvenWithLiveRedisTTL(t *testing.T) {
	rdb := otpRedis(t)
	s := NewStore(rdb)
	ctx := context.Background()
	c := &WalletStepUpChallenge{ID: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(-time.Second)}
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	key := prefixWalletStepup + c.ID
	require.NoError(t, rdb.Set(ctx, key, raw, time.Minute).Err())
	t.Cleanup(func() { rdb.Del(ctx, key) })
	require.ErrorIs(t, s.CompleteWalletStepUpChallenge(ctx, c.ID), ErrWalletStepUpConsumed)
	saved, err := s.GetWalletStepUpChallenge(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, "pending", saved.Status)
}
