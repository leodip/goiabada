package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// valueAtTheBound is one value of exactly the bound's bytes.
type valueAtTheBound struct {
	name  string
	value string
}

// valuesAtTheBound returns three values of exactly max bytes, in one-, two- and four-byte
// characters. The engines count a column's width differently, MySQL and PostgreSQL in code points
// and SQL Server in UTF-16 units, and the authorization endpoint and the password grant bound
// state, nonce and scope in bytes because a string is never fewer bytes than either, so these are
// the values that prove the bound fits every column: the ASCII one at the most characters the bound
// admits, and the other two at the most UTF-16 units per byte (#437).
func valuesAtTheBound(t *testing.T, max int) []valueAtTheBound {
	t.Helper()
	require.Zero(t, max%4, "the two- and four-byte values need a bound both widths divide")
	values := []valueAtTheBound{
		{"ascii", strings.Repeat("a", max)},
		{"two-byte characters", strings.Repeat("é", max/2)},
		{"four-byte characters", strings.Repeat("😀", max/4)},
	}
	for _, v := range values {
		require.Len(t, v.value, max, "%s is off the bound, so the case no longer observes the column's edge", v.name)
	}
	return values
}

// TestCreateCode_StateNonceAndScopeAtTheBoundRoundTrip is what the authorization endpoint's byte
// bounds stand on: a state, nonce or scope it admits is stored in codes and read back unchanged on
// every engine, rather than refused by a column narrower than the bound, which the request would
// have met as a 500 at /auth/issue after the user had signed in (#437).
func TestCreateCode_StateNonceAndScopeAtTheBoundRoundTrip(t *testing.T) {
	columns := []struct {
		name string
		max  int
		set  func(*models.Code, string)
		get  func(*models.Code) string
	}{
		{"state", models.StateMaxBytes, func(c *models.Code, v string) { c.State = v }, func(c *models.Code) string { return c.State }},
		{"nonce", models.NonceMaxBytes, func(c *models.Code, v string) { c.Nonce = v }, func(c *models.Code) string { return c.Nonce }},
		{"scope", models.ScopeMaxBytes, func(c *models.Code, v string) { c.Scope = v }, func(c *models.Code) string { return c.Scope }},
	}

	for _, column := range columns {
		for _, tc := range valuesAtTheBound(t, column.max) {
			t.Run(column.name+"/"+tc.name, func(t *testing.T) {
				client := createTestClient(t)
				user := createTestUser(t)
				random := fake.LetterN(6)
				code := &models.Code{
					ClientId:          client.Id,
					UserId:            user.Id,
					Code:              "testcode_" + random,
					CodeHash:          "testhash_" + random,
					RedirectURI:       "https://example.com/callback",
					Scope:             "openid",
					ResponseMode:      "query",
					AuthenticatedAt:   time.Now().UTC().Truncate(time.Microsecond),
					SessionIdentifier: "testsession_" + random,
					AcrLevel:          "1",
					AuthMethods:       "password",
				}
				column.set(code, tc.value)

				err := database.CreateCode(context.Background(), nil, code)
				require.NoError(t, err, "a code carrying a %d-byte %s was refused by the column", column.max, column.name)

				stored, err := database.GetCodeById(context.Background(), nil, code.Id)
				require.NoError(t, err)
				require.NotNil(t, stored)
				require.Equal(t, tc.value, column.get(stored), "the code's %s did not round-trip unchanged", column.name)
			})
		}
	}

	// A sign-in that uses all three at their bounds writes them in one row, which is a different
	// claim from three rows that each hold one: SQL Server moves variable-length columns out of the
	// row page when they add up to more than a page, and MySQL's row size limit is on the sum.
	states := valuesAtTheBound(t, models.StateMaxBytes)
	nonces := valuesAtTheBound(t, models.NonceMaxBytes)
	scopes := valuesAtTheBound(t, models.ScopeMaxBytes)
	for i, tc := range states {
		t.Run("all three together/"+tc.name, func(t *testing.T) {
			client := createTestClient(t)
			user := createTestUser(t)
			random := fake.LetterN(6)
			code := &models.Code{
				ClientId:          client.Id,
				UserId:            user.Id,
				Code:              "testcode_" + random,
				CodeHash:          "testhash_" + random,
				RedirectURI:       "https://example.com/callback",
				State:             states[i].value,
				Nonce:             nonces[i].value,
				Scope:             scopes[i].value,
				ResponseMode:      "query",
				AuthenticatedAt:   time.Now().UTC().Truncate(time.Microsecond),
				SessionIdentifier: "testsession_" + random,
				AcrLevel:          "1",
				AuthMethods:       "password",
			}

			err := database.CreateCode(context.Background(), nil, code)
			require.NoError(t, err, "a code with state, nonce and scope all at their bounds was refused")

			stored, err := database.GetCodeById(context.Background(), nil, code.Id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			require.Equal(t, states[i].value, stored.State)
			require.Equal(t, nonces[i].value, stored.Nonce)
			require.Equal(t, scopes[i].value, stored.Scope)
		})
	}
}

// TestCreateRefreshToken_AScopeAtTheBoundRoundTrips covers the second table a scope is stored in:
// a refresh token descended from the code, and the one the password grant issues, both carry the
// scope granted.
func TestCreateRefreshToken_AScopeAtTheBoundRoundTrips(t *testing.T) {
	for _, tc := range valuesAtTheBound(t, models.ScopeMaxBytes) {
		t.Run(tc.name, func(t *testing.T) {
			client := createTestClient(t)
			user := createTestUser(t)
			code := createTestCode(t, client.Id, user.Id)
			refreshToken := &models.RefreshToken{
				CodeId:            sql.NullInt64{Int64: code.Id, Valid: true},
				UserId:            sql.NullInt64{Int64: user.Id, Valid: true},
				ClientId:          sql.NullInt64{Int64: client.Id, Valid: true},
				RefreshTokenJti:   fake.UUID(),
				SessionIdentifier: fake.UUID(),
				RefreshTokenType:  "Bearer",
				Scope:             tc.value,
				IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
				ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
				MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
			}

			err := database.CreateRefreshToken(context.Background(), nil, refreshToken)
			require.NoError(t, err, "a refresh token carrying a %d-byte scope was refused by the column", models.ScopeMaxBytes)

			stored, err := database.GetRefreshTokenById(context.Background(), nil, refreshToken.Id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			require.Equal(t, tc.value, stored.Scope, "the refresh token's scope did not round-trip unchanged")
		})
	}
}

// TestCreateUserConsent_AScopeAtTheBoundRoundTrips covers the third: the consent the user gave, from
// which a later refresh is checked.
func TestCreateUserConsent_AScopeAtTheBoundRoundTrips(t *testing.T) {
	for _, tc := range valuesAtTheBound(t, models.ScopeMaxBytes) {
		t.Run(tc.name, func(t *testing.T) {
			client := createTestClient(t)
			user := createTestUser(t)
			consent := &models.UserConsent{
				UserId:    user.Id,
				ClientId:  client.Id,
				Scope:     tc.value,
				GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
			}

			err := database.CreateUserConsent(context.Background(), nil, consent)
			require.NoError(t, err, "a consent carrying a %d-byte scope was refused by the column", models.ScopeMaxBytes)

			stored, err := database.GetUserConsentById(context.Background(), nil, consent.Id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			require.Equal(t, tc.value, stored.Scope, "the consent's scope did not round-trip unchanged")
		})
	}
}
