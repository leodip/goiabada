package datatests

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codes.dpop_jkt is the thumbprint of the DPoP key an authorization request bound its code to with
// dpop_jkt, NULL for a code bound to none (RFC 9449 section 10, #42 decision 14). These pin what the
// data layer owes it on every engine: it round-trips, NULL included, through each read of a code; a
// full-row update can neither change nor clear it; and concurrent redemptions of one bound code,
// through the real issuer, leave exactly one winner, its access token bound to that key.
//
// The thumbprints are refresh_token_dpop_binding_test.go's literals: RFC 7638 section 3.1's example
// and a second value of the same shape.

func TestCode_DPoPJktRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding sql.NullString
	}{
		{"a bound code reads its key's thumbprint", sql.NullString{String: bindingFamilyKey, Valid: true}},
		{"an unbound code reads NULL", sql.NullString{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := createBoundTestCodeOn(t, database, tc.binding)

			byId, err := database.GetCodeById(context.Background(), nil, created.Id)
			require.NoError(t, err)
			byHash, err := database.GetCodeByCodeHash(context.Background(), nil, created.CodeHash, false)
			require.NoError(t, err)
			for _, read := range []*record.Code{byId, byHash} {
				require.NotNil(t, read)
				assert.Equal(t, tc.binding, read.DPoPJkt)
			}

			// A used code is read through the reuse lookup too, which the token endpoint's binding
			// check answers from.
			claimed, err := database.MarkCodeAsUsed(context.Background(), nil, created.Id)
			require.NoError(t, err)
			require.True(t, claimed)
			used, err := database.GetCodeByCodeHash(context.Background(), nil, created.CodeHash, true)
			require.NoError(t, err)
			require.NotNil(t, used)
			assert.Equal(t, tc.binding, used.DPoPJkt)
		})
	}
}

// Tagged dont-update, like auth_state_generation: the binding is set when a code is born and never
// by an update, so a full-row update with another key, or with none, leaves it as it was, and an
// unbound code cannot be bound by one either.
func TestUpdateCode_NeitherChangesNorClearsTheDPoPJkt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding sql.NullString
	}{
		{"a bound code", sql.NullString{String: bindingFamilyKey, Valid: true}},
		{"an unbound code", sql.NullString{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := createBoundTestCodeOn(t, database, tc.binding)

			for _, inHand := range []sql.NullString{{String: bindingOtherKey, Valid: true}, {}} {
				reloaded, err := database.GetCodeById(context.Background(), nil, created.Id)
				require.NoError(t, err)
				reloaded.DPoPJkt = inHand
				reloaded.Scope = "openid " + fake.LetterN(6)
				require.NoError(t, database.UpdateCode(context.Background(), nil, reloaded))

				after, err := database.GetCodeById(context.Background(), nil, created.Id)
				require.NoError(t, err)
				assert.Equal(t, tc.binding, after.DPoPJkt, "UpdateCode with %v in hand moved dpop_jkt (is the dont-update tag missing?)", inHand)
				assert.Equal(t, reloaded.Scope, after.Scope, "the rest of the update still applies")
			}
		})
	}
}

// Concurrent redemptions of one bound code, each by the code's key as the validator would pass them,
// through the real issuer. Exactly one claims the code and mints, its access token bound to the key;
// every other loses the claim and mints nothing; and the code is used, its binding untouched. The
// binding is checked before the claim, so it adds nothing to the race: the compare-and-set is still
// what lets exactly one redemption mint. Redemptions genuinely overlap on every engine but SQLite,
// whose pool has one connection.
func TestRedeemBoundCode_ConcurrentRedemptionsHaveExactlyOneWinner(t *testing.T) {
	const redemptions = 8
	withRealSigningKeyOn(t, database)
	code := createBoundTestCodeOn(t, database, sql.NullString{String: bindingFamilyKey, Valid: true})

	presented := make([]*record.Code, redemptions)
	for i := range presented {
		read, err := database.GetCodeByCodeHash(context.Background(), nil, code.CodeHash, false)
		require.NoError(t, err)
		require.NotNil(t, read, "the code is unused when every redemption reads it")
		presented[i] = read
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accessTokens []string
	var refusals []error
	for _, read := range presented {
		wg.Add(1)
		go func(read *record.Code) {
			defer wg.Done()
			<-start
			response, err := refreshIssuerOn(database).IssueAuthorizationCodeGrant(context.Background(), rotationSettings(), read, bindingFamilyKey)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				refusals = append(refusals, err)
				return
			}
			accessTokens = append(accessTokens, response.AccessToken)
		}(read)
	}
	close(start)
	wg.Wait()

	for _, err := range refusals {
		require.ErrorIsf(t, err, issuance.ErrCodeNotClaimed, "a redemption that did not mint lost the claim")
	}
	require.Len(t, accessTokens, 1, "exactly one redemption mints")
	assert.Equal(t, map[string]any{"jkt": bindingFamilyKey}, claimsOf(t, accessTokens[0])["cnf"],
		"the winner's access token is bound to the code's key")

	after, err := database.GetCodeById(context.Background(), nil, code.Id)
	require.NoError(t, err)
	assert.True(t, after.Used, "the code is spent")
	assert.Equal(t, sql.NullString{String: bindingFamilyKey, Valid: true}, after.DPoPJkt, "and still bound to its key")
	refreshTokens, err := database.GetRefreshTokensByCodeId(context.Background(), nil, code.Id)
	require.NoError(t, err)
	assert.Len(t, refreshTokens, 1, "one redemption's refresh token, and no other")
}

// createBoundTestCodeOn is createTestCodeOn's code, bound to binding and issued in a live session of
// its own, so the real issuer can redeem it. Created with the binding, since no update sets it.
func createBoundTestCodeOn(t *testing.T, db data.Database, binding sql.NullString) *record.Code {
	t.Helper()
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)
	session := createTestUserSessionOn(t, db, user.Id)

	code := createTestCodeOn(t, db, client.Id, user.Id)
	code.Id = 0
	random := fake.LetterN(8)
	code.Code = "boundcode_" + random
	code.CodeHash = "boundhash_" + random
	code.SessionIdentifier = session.SessionIdentifier
	code.DPoPJkt = binding
	require.NoError(t, db.CreateCode(context.Background(), nil, code))
	return code
}
