package handler

import (
	"testing"
	"time"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAccessRequestAuthorizes(t *testing.T) {
	cred := uuid.New()
	user := uuid.New()
	future := time.Now().Add(30 * time.Minute)
	past := time.Now().Add(-time.Minute)
	revoked := time.Now()

	base := func() *repository.PAMAccessRequest {
		return &repository.PAMAccessRequest{
			Status:      "active",
			RequesterID: user,
			ResourceID:  cred.String(),
			ExpiresAt:   &future,
		}
	}

	t.Run("valid approved request authorises", func(t *testing.T) {
		assert.True(t, accessRequestAuthorizes(base(), cred, user))
	})
	t.Run("nil request", func(t *testing.T) {
		assert.False(t, accessRequestAuthorizes(nil, cred, user))
	})
	t.Run("pending (not approved)", func(t *testing.T) {
		ar := base()
		ar.Status = "pending"
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
	t.Run("different requester", func(t *testing.T) {
		ar := base()
		ar.RequesterID = uuid.New()
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
	t.Run("different credential", func(t *testing.T) {
		ar := base()
		ar.ResourceID = uuid.New().String()
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
	t.Run("expired", func(t *testing.T) {
		ar := base()
		ar.ExpiresAt = &past
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
	t.Run("no expiry", func(t *testing.T) {
		ar := base()
		ar.ExpiresAt = nil
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
	t.Run("revoked", func(t *testing.T) {
		ar := base()
		ar.RevokedAt = &revoked
		assert.False(t, accessRequestAuthorizes(ar, cred, user))
	})
}
