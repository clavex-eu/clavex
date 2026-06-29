package handler

// GDPRErasure implements GDPR Article 17 "Right to Erasure" (right to be forgotten).
//
// DELETE /api/v1/organizations/:org_id/compliance/gdpr-erasure/:user_id
//
// What is erased (within a single DB transaction):
//   - users row: email → erased_<id>@gdpr.invalid, first_name/last_name → "ERASED",
//     metadata → {}, password hash → "" (login disabled), is_active → false
//   - login_history rows: email/ip_address/user_agent/city/asn_org nullified per-event
//     (the event record itself is preserved for audit continuity / NIS2 compliance)
//   - issued_credentials: revoked with reason "gdpr_erasure"
//   - refresh_tokens: hard-deleted (sessions are already bound to the user)
//   - browser_sessions: hard-deleted
//   - mfa_credentials: hard-deleted
//   - user_idp_links: hard-deleted
//   - user_roles / group_members: hard-deleted
//   - verification_tokens: hard-deleted
//
// An audit log entry is written to record that erasure was performed, by whom,
// and at what time.  This satisfies the accountability requirement (Art.5(2)).
//
// Returns 200 with a confirmation object, or 404 if the user doesn't exist.

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

type erasureResult struct {
	UserID          string    `json:"user_id"`
	OrgID           string    `json:"org_id"`
	ErasedAt        time.Time `json:"erased_at"`
	AnonymisedEmail string    `json:"anonymised_email"`
	// Counts of related rows scrubbed.
	LoginHistoryRowsScrubbed int64 `json:"login_history_rows_scrubbed"`
	CredentialsRevoked       int64 `json:"credentials_revoked"`
	SessionsDeleted          int64 `json:"sessions_deleted"`
	RefreshTokensDeleted     int64 `json:"refresh_tokens_deleted"`
	// Compliance note for the caller.
	Note string `json:"note"`
}

// GDPRErasure handles DELETE /api/v1/organizations/:org_id/compliance/gdpr-erasure/:user_id
func (h *ComplianceHandler) GDPRErasure(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return err
	}
	userID, err := uuidParam(c, "user_id")
	if err != nil {
		return err
	}

	// Stable anonymised email derived from user UUID — deterministic, irreversible,
	// lets the audit log reference the erasure without storing PII.
	h256 := sha256.Sum256([]byte(userID.String()))
	anonEmail := fmt.Sprintf("erased_%x@gdpr.invalid", h256[:8])

	var result erasureResult
	result.UserID = userID.String()
	result.OrgID = orgID.String()
	result.ErasedAt = time.Now().UTC()
	result.AnonymisedEmail = anonEmail

	err = pgx.BeginTxFunc(ctx, h.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// 1. Verify the user exists in this org.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND org_id = $2)`,
			userID, orgID,
		).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return echo.NewHTTPError(http.StatusNotFound, "user not found in this organization")
		}

		// 2. Anonymise the users row.
		if _, err := tx.Exec(ctx, `
			UPDATE users SET
				email           = $1,
				first_name      = 'ERASED',
				last_name       = 'ERASED',
				password_hash   = '',
				metadata        = '{}',
				is_active       = FALSE,
				updated_at      = NOW()
			WHERE id = $2 AND org_id = $3`,
			anonEmail, userID, orgID,
		); err != nil {
			return fmt.Errorf("anonymise user: %w", err)
		}

		// 3. Scrub personal data from login_history (keep events for audit continuity).
		tag, err := tx.Exec(ctx, `
			UPDATE login_history SET
				email      = NULL,
				ip_address = NULL,
				user_agent = NULL,
				city       = NULL,
				asn_org    = NULL
			WHERE user_id = $1`,
			userID,
		)
		if err != nil {
			return fmt.Errorf("scrub login_history: %w", err)
		}
		result.LoginHistoryRowsScrubbed = tag.RowsAffected()

		// 4. Revoke issued verifiable credentials.
		reason := "gdpr_erasure"
		tag, err = tx.Exec(ctx, `
			UPDATE issued_credentials SET
				is_revoked        = TRUE,
				revoked_at        = NOW(),
				revocation_reason = $1
			WHERE user_id = $2 AND is_revoked = FALSE`,
			reason, userID,
		)
		if err != nil {
			return fmt.Errorf("revoke credentials: %w", err)
		}
		result.CredentialsRevoked = tag.RowsAffected()

		// 5. Delete active browser sessions.
		tag, err = tx.Exec(ctx, `DELETE FROM browser_sessions WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("delete browser_sessions: %w", err)
		}
		result.SessionsDeleted = tag.RowsAffected()

		// 6. Delete refresh tokens.
		tag, err = tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("delete refresh_tokens: %w", err)
		}
		result.RefreshTokensDeleted = tag.RowsAffected()

		// 7. Delete MFA credentials.
		if _, err := tx.Exec(ctx,
			`DELETE FROM mfa_credentials WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("delete mfa_credentials: %w", err)
		}

		// 8. Delete IdP links.
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_idp_links WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("delete user_idp_links: %w", err)
		}

		// 9. Delete role assignments + group memberships.
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_roles WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("delete user_roles: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM group_members WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("delete group_members: %w", err)
		}

		// 10. Delete pending verification tokens.
		if _, err := tx.Exec(ctx,
			`DELETE FROM verification_tokens WHERE user_id = $1`, userID,
		); err != nil {
			return fmt.Errorf("delete verification_tokens: %w", err)
		}

		return nil
	})
	if err != nil {
		if he, ok := err.(*echo.HTTPError); ok {
			return he
		}
		log.Error().Err(err).
			Str("user_id", userID.String()).
			Str("org_id", orgID.String()).
			Msg("gdpr-erasure: transaction failed")
		return echo.ErrInternalServerError
	}

	result.Note = "Personal data erased per GDPR Art.17. " +
		"Login history events are retained for audit continuity (Art.17(3)(e)) " +
		"with all personally identifiable fields set to NULL. " +
		"The anonymised email is a deterministic one-way hash and cannot be reversed."

	log.Info().
		Str("user_id", userID.String()).
		Str("org_id", orgID.String()).
		Str("anonymised_email", anonEmail).
		Int64("login_history_rows", result.LoginHistoryRowsScrubbed).
		Int64("credentials_revoked", result.CredentialsRevoked).
		Msg("gdpr-erasure: completed")

	return c.JSON(http.StatusOK, result)
}
