package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── computeScores ─────────────────────────────────────────────────────────────

func TestComputeScores_ZeroUsers_ZeroMFAScores(t *testing.T) {
	p := computeScores(postureRaw{totalUsers: 0})
	assert.Equal(t, 0, p.MFACoverage)
	assert.Equal(t, 0, p.PasskeyCoverage)
}

func TestComputeScores_FullMFACoverage(t *testing.T) {
	p := computeScores(postureRaw{
		totalUsers:   10,
		usersWithMFA: 10,
	})
	assert.Equal(t, 100, p.MFACoverage)
}

func TestComputeScores_HalfMFACoverage(t *testing.T) {
	p := computeScores(postureRaw{
		totalUsers:   100,
		usersWithMFA: 50,
	})
	assert.Equal(t, 50, p.MFACoverage)
}

func TestComputeScores_PasskeyCoverage(t *testing.T) {
	p := computeScores(postureRaw{
		totalUsers:       20,
		usersWithPasskey: 5,
	})
	assert.Equal(t, 25, p.PasskeyCoverage)
}

func TestComputeScores_PolicyEngine_WithRules(t *testing.T) {
	p := computeScores(postureRaw{activePolicyRules: 3})
	assert.Equal(t, 100, p.PolicyEngine)
}

func TestComputeScores_PolicyEngine_NoRules(t *testing.T) {
	p := computeScores(postureRaw{activePolicyRules: 0})
	assert.Equal(t, 0, p.PolicyEngine)
}

func TestComputeScores_AnomalyScore_NoFailures(t *testing.T) {
	p := computeScores(postureRaw{failedLogins24h: 0})
	assert.Equal(t, 100, p.AnomalyScore)
}

func TestComputeScores_AnomalyScore_FiveFailures(t *testing.T) {
	// 5 failures → 5*5=25 deduction → score=75
	p := computeScores(postureRaw{failedLogins24h: 5})
	assert.Equal(t, 75, p.AnomalyScore)
}

func TestComputeScores_AnomalyScore_ManyFailures_ClampsAtZero(t *testing.T) {
	// 25+ failures → clamped at 0
	p := computeScores(postureRaw{failedLogins24h: 25})
	assert.Equal(t, 0, p.AnomalyScore)
}

func TestComputeScores_AnomalyScore_ExcessFailures_ClampsAtZero(t *testing.T) {
	p := computeScores(postureRaw{failedLogins24h: 1000})
	assert.Equal(t, 0, p.AnomalyScore)
}

func TestComputeScores_KeyRotation_IsStaticHeuristic(t *testing.T) {
	p := computeScores(postureRaw{})
	assert.Equal(t, 80, p.KeyRotation)
}

func TestComputeScores_OverallScore_PerfectOrg(t *testing.T) {
	// 100% MFA, 100% passkey, policy active, no failures
	p := computeScores(postureRaw{
		totalUsers:        100,
		usersWithMFA:      100,
		usersWithPasskey:  100,
		activePolicyRules: 1,
		failedLogins24h:   0,
	})
	// Score = (100*35 + 100*15 + 100*20 + 100*20 + 80*10) / 100
	//       = (3500 + 1500 + 2000 + 2000 + 800) / 100 = 9800/100 = 98
	assert.Equal(t, 98, p.Score)
}

func TestComputeScores_OverallScore_NoSecurity(t *testing.T) {
	// No MFA, no passkey, no policy, many failures
	p := computeScores(postureRaw{
		totalUsers:        100,
		usersWithMFA:      0,
		usersWithPasskey:  0,
		activePolicyRules: 0,
		failedLogins24h:   1000,
	})
	// MFACov=0, PasskeyCov=0, Policy=0, Anomaly=0, KeyRot=80
	// Score = (0 + 0 + 0 + 0 + 80*10) / 100 = 800/100 = 8
	assert.Equal(t, 8, p.Score)
}

func TestComputeScores_RawCountsPreserved(t *testing.T) {
	raw := postureRaw{
		totalUsers:         42,
		usersWithMFA:       21,
		usersWithPasskey:   7,
		activePolicyRules:  3,
		failedLogins24h:    5,
		anomalousLogins24h: 2,
	}
	p := computeScores(raw)
	assert.Equal(t, 42, p.TotalUsers)
	assert.Equal(t, 21, p.UsersWithMFA)
	assert.Equal(t, 7, p.UsersWithPasskey)
	assert.Equal(t, 3, p.ActivePolicyRules)
	assert.Equal(t, 5, p.FailedLogins24h)
	assert.Equal(t, 2, p.AnomalousLogins24h)
}

func TestComputeScores_ComputedAtIsSet(t *testing.T) {
	p := computeScores(postureRaw{})
	assert.False(t, p.ComputedAt.IsZero())
}

// ── clampInt ──────────────────────────────────────────────────────────────────

func TestClampInt(t *testing.T) {
	assert.Equal(t, 0, clampInt(-5, 0, 100))
	assert.Equal(t, 0, clampInt(0, 0, 100))
	assert.Equal(t, 50, clampInt(50, 0, 100))
	assert.Equal(t, 100, clampInt(100, 0, 100))
	assert.Equal(t, 100, clampInt(200, 0, 100))
}
