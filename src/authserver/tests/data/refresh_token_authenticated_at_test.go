package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refresh_tokens.authenticated_at is where an ROPC grant keeps the moment its password was
// checked, so every refresh can issue it as auth_time (#125). These pin the three things the data
// layer owes it: it round-trips, NULL included; a full-row update cannot change it; and the one
// query that joins codes, which carry an authenticated_at of their own, reads the token's.

// seedROPCRefreshToken writes an ROPC-shaped token, user and client set and no code, recording
// instant.
func seedROPCRefreshToken(t *testing.T, instant sql.NullTime) *record.RefreshToken {
	t.Helper()
	client := createTestClient(t)
	user := createTestUser(t)
	jti := fake.UUID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	token := &record.RefreshToken{
		UserId:               sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId:             sql.NullInt64{Int64: client.Id, Valid: true},
		RefreshTokenJti:      jti,
		FirstRefreshTokenJti: jti,
		RefreshTokenType:     "Offline",
		Scope:                "openid",
		IssuedAt:             sql.NullTime{Time: now, Valid: true},
		ExpiresAt:            sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		AuthenticatedAt:      instant,
	}
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, token))
	return token
}

func TestRefreshToken_AuthenticatedAtRoundTrips(t *testing.T) {
	// Microseconds, the precision all four engines store: the claim is whole seconds, so this is
	// stricter than issuance needs, and it is what proves nothing rounds.
	threeDaysAgo := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)

	for _, tc := range []struct {
		name    string
		instant sql.NullTime
	}{
		{"an ROPC token records its grant's instant", sql.NullTime{Time: threeDaysAgo, Valid: true}},
		{"a token recording none reads none", sql.NullTime{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := seedROPCRefreshToken(t, tc.instant)

			byId, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
			require.NoError(t, err)
			byJti, err := database.GetRefreshTokenByJti(context.Background(), nil, created.RefreshTokenJti)
			require.NoError(t, err)

			for _, read := range []*record.RefreshToken{byId, byJti} {
				require.NotNil(t, read)
				assert.Equal(t, tc.instant.Valid, read.AuthenticatedAt.Valid)
				if tc.instant.Valid {
					assert.True(t, tc.instant.Time.Equal(read.AuthenticatedAt.Time),
						"stored %v, read %v", tc.instant.Time, read.AuthenticatedAt.Time)
				}
			}
		})
	}
}

// Tagged dont-update, like auth_state_generation: the refresh endpoint revokes the presented token
// with a full-row update, and the column must come out of that as it went in, whatever the model
// in hand says.
func TestUpdateRefreshToken_DoesNotClobberTheAuthenticationInstant(t *testing.T) {
	instant := sql.NullTime{Time: time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond), Valid: true}
	created := seedROPCRefreshToken(t, instant)

	reloaded, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
	require.NoError(t, err)
	reloaded.AuthenticatedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
	reloaded.Revoked = true
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, reloaded))

	after, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
	require.NoError(t, err)
	require.True(t, after.AuthenticatedAt.Valid)
	assert.True(t, instant.Time.Equal(after.AuthenticatedAt.Time),
		"UpdateRefreshToken moved authenticated_at to %v (is the dont-update tag missing?)", after.AuthenticatedAt.Time)
	assert.True(t, after.Revoked, "the rest of the update must still apply")

	// And a NULL in hand does not blank a recorded instant.
	after.AuthenticatedAt = sql.NullTime{}
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, after))
	final, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
	require.NoError(t, err)
	assert.True(t, final.AuthenticatedAt.Valid, "UpdateRefreshToken blanked authenticated_at")
}

// GetRefreshTokensBySessionIdentifier joins codes, and codes has an authenticated_at column too.
// The column read has to be the token's: an unqualified one would be ambiguous on some engines and
// the code's on others. The two tokens here carry NULL, as every authorization-code token does, and
// a value distinct from the code's, and the code carries a third.
func TestGetRefreshTokensBySessionIdentifier_ReadsTheTokensInstantNotTheCodes(t *testing.T) {
	client := createTestClient(t)
	user := createTestUser(t)
	sessionId := "sess_" + fake.LetterN(12)
	codeInstant := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	tokenInstant := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)

	code := &record.Code{
		ClientId:            client.Id,
		UserId:              user.Id,
		Code:                "code_" + fake.LetterN(6),
		CodeHash:            "hash_" + fake.LetterN(6),
		CodeChallenge:       sql.NullString{String: "challenge_" + fake.LetterN(6), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		IpAddress:           "127.0.0.1",
		UserAgent:           "test",
		ResponseMode:        "query",
		AuthenticatedAt:     codeInstant,
		SessionIdentifier:   sessionId,
		AcrLevel:            "1",
		AuthMethods:         "pwd",
		Used:                true,
	}
	require.NoError(t, database.CreateCode(context.Background(), nil, code))

	now := time.Now().UTC().Truncate(time.Microsecond)
	wanted := map[string]sql.NullTime{}
	for _, instant := range []sql.NullTime{{}, {Time: tokenInstant, Valid: true}} {
		jti := fake.UUID()
		require.NoError(t, database.CreateRefreshToken(context.Background(), nil, &record.RefreshToken{
			CodeId:               sql.NullInt64{Int64: code.Id, Valid: true},
			RefreshTokenJti:      jti,
			FirstRefreshTokenJti: jti,
			SessionIdentifier:    sessionId,
			RefreshTokenType:     "Refresh",
			Scope:                "openid",
			IssuedAt:             sql.NullTime{Time: now, Valid: true},
			ExpiresAt:            sql.NullTime{Time: now.Add(time.Hour), Valid: true},
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
			AuthenticatedAt:      instant,
		}))
		wanted[jti] = instant
	}

	tokens, err := database.GetRefreshTokensBySessionIdentifier(context.Background(), nil, sessionId)
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	for _, token := range tokens {
		want := wanted[token.RefreshTokenJti]
		assert.Equal(t, want.Valid, token.AuthenticatedAt.Valid, "token %s", token.RefreshTokenJti)
		if want.Valid {
			assert.True(t, want.Time.Equal(token.AuthenticatedAt.Time),
				"token %s read %v, which is not its own %v", token.RefreshTokenJti, token.AuthenticatedAt.Time, want.Time)
		}
		assert.False(t, token.AuthenticatedAt.Valid && token.AuthenticatedAt.Time.Equal(codeInstant),
			"token %s read the code's authenticated_at", token.RefreshTokenJti)
	}
}
