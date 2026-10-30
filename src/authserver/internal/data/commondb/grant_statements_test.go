package commondb

import (
	"context"
	"database/sql/driver"
	"testing"
)

// The statements of a grant's records, held on all four engines to what each asks of the engine:
// codes, refresh tokens, revoked rotation families, revoked access tokens and parked authorize
// requests (#644, #676).
//
// Most of these exist for their condition. A code is claimed only while it is neither used nor
// revoked, a refresh token is revoked only while it is live, a sweep of a session's, a client's or
// a user's grants reaches the rows of that session, client or user and no other, and a cleanup
// reaps only the rows nothing can use any more. The condition is in the statement's text and
// nowhere else, so this reads the text with each placeholder rendered as the value it binds, one
// expected statement for all four engines, as the users' narrow writes are read. The columns of a
// read of whole records are left to the record mapping test.

const (
	grantCodeId    = 9
	grantUserId    = 7
	grantClientId  = 3
	grantSessionId = "sid-1"
	grantFamilyJti = "first-jti"
	grantAccessJti = "at-jti"
)

func grantStatements() []narrowWrite {
	return []narrowWrite{
		// Codes.
		{
			name: "MarkCodeAsUsed",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.MarkCodeAsUsed(ctx, nil, grantCodeId)
			},
			answer: true,
			statements: []string{
				"UPDATE codes SET used = true, updated_at = <now> WHERE id = 9 AND used = false AND revoked = false",
			},
		},
		{
			name:  "MarkCodeAsUsed when no row transitioned",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.MarkCodeAsUsed(ctx, nil, grantCodeId)
			},
			answer: false,
			statements: []string{
				"UPDATE codes SET used = true, updated_at = <now> WHERE id = 9 AND used = false AND revoked = false",
			},
		},
		{
			name:  "RevokeCodesBySessionIdentifier",
			execs: []*scriptedExec{{rowsAffected: 2}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RevokeCodesBySessionIdentifier(ctx, nil, grantSessionId)
			},
			answer: int64(2),
			statements: []string{
				"UPDATE codes SET revoked = true, updated_at = <now> WHERE session_identifier = 'sid-1' AND revoked = false",
			},
		},
		{
			name:  "RevokeCodesByClientId",
			execs: []*scriptedExec{{rowsAffected: 2}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RevokeCodesByClientId(ctx, nil, grantClientId)
			},
			answer: int64(2),
			statements: []string{
				"UPDATE codes SET revoked = true, updated_at = <now> WHERE client_id = 3 AND revoked = false",
			},
		},
		{
			name:  "RevokeUnusedCodesByUserIdAndClientId",
			execs: []*scriptedExec{{rowsAffected: 2}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RevokeUnusedCodesByUserIdAndClientId(ctx, nil, grantUserId, grantClientId)
			},
			answer: int64(2),
			statements: []string{
				"UPDATE codes SET revoked = true, updated_at = <now> " +
					"WHERE user_id = 7 AND client_id = 3 AND used = false AND revoked = false",
			},
		},
		{
			name: "GetCodeById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetCodeById(ctx, nil, grantCodeId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM codes WHERE id = 9"},
		},
		{
			name: "GetCodeByCodeHash",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetCodeByCodeHash(ctx, nil, "hash-1", true)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM codes WHERE code_hash = 'hash-1' AND used = true"},
		},
		{
			name: "DeleteCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteCode(ctx, nil, grantCodeId)
			},
			statements: []string{"DELETE FROM codes WHERE id = 9"},
		},
		{
			name: "DeleteCodesWithoutRefreshTokens",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteCodesWithoutRefreshTokens(ctx, nil, staleBefore)
			},
			statements: []string{
				"DELETE FROM codes WHERE created_at < 2003-03-03T00:00:00Z AND " +
					"NOT EXISTS (SELECT 1 FROM refresh_tokens WHERE refresh_tokens.code_id = codes.id)",
			},
		},

		// Refresh tokens.
		{
			name: "MarkRefreshTokenAsRevoked",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.MarkRefreshTokenAsRevoked(ctx, nil, grantCodeId)
			},
			answer: true,
			statements: []string{
				"UPDATE refresh_tokens SET revoked = true, updated_at = <now> WHERE id = 9 AND revoked = false",
			},
		},
		{
			name:  "MarkRefreshTokenAsRevoked when no row transitioned",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.MarkRefreshTokenAsRevoked(ctx, nil, grantCodeId)
			},
			answer: false,
			statements: []string{
				"UPDATE refresh_tokens SET revoked = true, updated_at = <now> WHERE id = 9 AND revoked = false",
			},
		},
		{
			name:  "RevokeRefreshTokenFamily",
			execs: []*scriptedExec{{rowsAffected: 2}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RevokeRefreshTokenFamily(ctx, nil, grantFamilyJti)
			},
			answer: int64(2),
			statements: []string{
				"UPDATE refresh_tokens SET revoked = true, updated_at = <now> " +
					"WHERE first_refresh_token_jti = 'first-jti' AND revoked = false",
			},
		},
		{
			name: "PromoteRefreshTokenGenerations",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.PromoteRefreshTokenGenerations(ctx, nil, []int64{4, 5}, 6)
			},
			statements: []string{
				"UPDATE refresh_tokens SET auth_state_generation = 6, updated_at = <now> " +
					"WHERE revoked = false AND id IN (4, 5)",
			},
		},
		{
			name: "GetRefreshTokenById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokenById(ctx, nil, grantCodeId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM refresh_tokens WHERE id = 9"},
		},
		{
			name: "GetRefreshTokenByJti",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokenByJti(ctx, nil, "jti-1")
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM refresh_tokens WHERE refresh_token_jti = 'jti-1'"},
		},
		{
			name: "GetRefreshTokensByCodeId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokensByCodeId(ctx, nil, grantCodeId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM refresh_tokens WHERE code_id = 9"},
		},
		{
			name: "GetRefreshTokensBySessionIdentifier",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokensBySessionIdentifier(ctx, nil, grantSessionId)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
					"WHERE codes.session_identifier = 'sid-1'",
			},
		},
		{
			name: "GetRefreshTokensByUserId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokensByUserId(ctx, nil, grantUserId)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
					"WHERE codes.user_id = 7 " +
					"UNION ALL SELECT <columns> FROM refresh_tokens WHERE refresh_tokens.user_id = 7",
			},
		},
		{
			name: "GetRefreshTokensByUserIdAndClientId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokensByUserIdAndClientId(ctx, nil, grantUserId, grantClientId)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
					"WHERE codes.user_id = 7 AND codes.client_id = 3 " +
					"UNION ALL SELECT <columns> FROM refresh_tokens " +
					"WHERE refresh_tokens.user_id = 7 AND refresh_tokens.client_id = 3",
			},
		},
		{
			name: "GetRefreshTokensByClientId",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetRefreshTokensByClientId(ctx, nil, grantClientId)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM refresh_tokens INNER JOIN codes ON codes.id = refresh_tokens.code_id " +
					"WHERE codes.client_id = 3 " +
					"UNION ALL SELECT <columns> FROM refresh_tokens WHERE refresh_tokens.client_id = 3",
			},
		},
		{
			name: "DeleteRefreshToken",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteRefreshToken(ctx, nil, grantCodeId)
			},
			statements: []string{"DELETE FROM refresh_tokens WHERE id = 9"},
		},
		{
			name: "deleteRefreshTokensByColumn by user",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.deleteRefreshTokensByColumn(ctx, nil, "user_id", grantUserId)
			},
			statements: []string{"DELETE FROM refresh_tokens WHERE user_id = 7"},
		},
		{
			name: "deleteRefreshTokensByColumn by client",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.deleteRefreshTokensByColumn(ctx, nil, "client_id", grantClientId)
			},
			statements: []string{"DELETE FROM refresh_tokens WHERE client_id = 3"},
		},
		{
			name: "DeleteExpiredRefreshTokens",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteExpiredRefreshTokens(ctx, nil)
			},
			statements: []string{"DELETE FROM refresh_tokens WHERE (expires_at < <now> OR max_lifetime < <now>)"},
		},

		// Revoked rotation families.
		{
			name: "RecordRefreshTokenFamilyRevoked",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RecordRefreshTokenFamilyRevoked(ctx, nil, grantFamilyJti, "replay")
			},
			answer: true,
			statements: []string{
				"SELECT first_refresh_token_jti FROM refresh_token_family_revocations WHERE first_refresh_token_jti = 'first-jti'",
				"INSERT INTO refresh_token_family_revocations (first_refresh_token_jti, reason, revoked_at) " +
					"VALUES ('first-jti', 'replay', <now>)",
			},
		},
		{
			name: "RecordRefreshTokenFamilyRevoked for a family already recorded",
			rows: []*scriptedRows{{cols: []string{"first_refresh_token_jti"}, values: [][]driver.Value{{grantFamilyJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RecordRefreshTokenFamilyRevoked(ctx, nil, grantFamilyJti, "replay")
			},
			answer: false,
			statements: []string{
				"SELECT first_refresh_token_jti FROM refresh_token_family_revocations WHERE first_refresh_token_jti = 'first-jti'",
			},
		},
		{
			name: "IsRefreshTokenFamilyRevoked",
			rows: []*scriptedRows{{cols: []string{"first_refresh_token_jti"}, values: [][]driver.Value{{grantFamilyJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IsRefreshTokenFamilyRevoked(ctx, nil, grantFamilyJti)
			},
			answer: true,
			statements: []string{
				"SELECT first_refresh_token_jti FROM refresh_token_family_revocations WHERE first_refresh_token_jti = 'first-jti'",
			},
		},
		{
			name: "IsRefreshTokenFamilyRevoked when the engine folded the match",
			rows: []*scriptedRows{{cols: []string{"first_refresh_token_jti"}, values: [][]driver.Value{{grantFamilyJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IsRefreshTokenFamilyRevoked(ctx, nil, grantFamilyJti+" ")
			},
			answer: false,
			statements: []string{
				"SELECT first_refresh_token_jti FROM refresh_token_family_revocations WHERE first_refresh_token_jti = 'first-jti '",
			},
		},
		{
			name: "DeleteOrphanedRefreshTokenFamilyRevocations",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteOrphanedRefreshTokenFamilyRevocations(ctx, nil)
			},
			statements: []string{
				"DELETE FROM refresh_token_family_revocations WHERE NOT EXISTS (SELECT 1 FROM refresh_tokens " +
					"WHERE refresh_tokens.first_refresh_token_jti = refresh_token_family_revocations.first_refresh_token_jti)",
			},
		},

		// Revoked access tokens without a grant.
		{
			name: "RecordAccessTokenRevoked",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RecordAccessTokenRevoked(ctx, nil, grantAccessJti, staleBefore)
			},
			answer: true,
			statements: []string{
				"SELECT jti FROM revoked_access_tokens WHERE jti = 'at-jti'",
				"INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ('at-jti', 2003-03-03T00:00:00Z)",
			},
		},
		{
			name: "RecordAccessTokenRevoked for a token already revoked",
			rows: []*scriptedRows{{cols: []string{"jti"}, values: [][]driver.Value{{grantAccessJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.RecordAccessTokenRevoked(ctx, nil, grantAccessJti, staleBefore)
			},
			answer:     false,
			statements: []string{"SELECT jti FROM revoked_access_tokens WHERE jti = 'at-jti'"},
		},
		{
			name: "IsAccessTokenRevoked",
			rows: []*scriptedRows{{cols: []string{"jti"}, values: [][]driver.Value{{grantAccessJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IsAccessTokenRevoked(ctx, nil, grantAccessJti)
			},
			answer:     true,
			statements: []string{"SELECT jti FROM revoked_access_tokens WHERE jti = 'at-jti'"},
		},
		{
			name: "IsAccessTokenRevoked when the engine folded the match",
			rows: []*scriptedRows{{cols: []string{"jti"}, values: [][]driver.Value{{grantAccessJti}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IsAccessTokenRevoked(ctx, nil, grantAccessJti+" ")
			},
			answer:     false,
			statements: []string{"SELECT jti FROM revoked_access_tokens WHERE jti = 'at-jti '"},
		},
		{
			name: "DeleteExpiredRevokedAccessTokens",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteExpiredRevokedAccessTokens(ctx, nil, staleBefore)
			},
			statements: []string{"DELETE FROM revoked_access_tokens WHERE expires_at < 2003-03-03T00:00:00Z"},
		},

		// Parked authorize requests.
		{
			name: "GetAuthorizeRequestByHandleHash",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetAuthorizeRequestByHandleHash(ctx, nil, "handle-hash", issuedAt)
				return nil, err
			},
			statements: []string{
				"SELECT <columns> FROM authorize_requests WHERE handle_hash = 'handle-hash' AND expires_at > 2001-01-01T00:00:00Z",
			},
		},
		{
			name: "ClaimAuthorizeRequest",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.ClaimAuthorizeRequest(ctx, nil, grantCodeId)
			},
			answer:     true,
			statements: []string{"DELETE FROM authorize_requests WHERE id = 9"},
		},
		{
			name:  "ClaimAuthorizeRequest when another call claimed it",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.ClaimAuthorizeRequest(ctx, nil, grantCodeId)
			},
			answer:     false,
			statements: []string{"DELETE FROM authorize_requests WHERE id = 9"},
		},
		{
			name: "DeleteExpiredAuthorizeRequests",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteExpiredAuthorizeRequests(ctx, nil, staleBefore)
			},
			statements: []string{"DELETE FROM authorize_requests WHERE expires_at < 2003-03-03T00:00:00Z"},
		},
	}
}

func TestGrantStatements_SendTheirStatementOnEveryEngine(t *testing.T) {
	assertNarrowWritesOnEveryEngine(t, grantStatements(), true)
}
