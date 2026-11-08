package datatests

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refresh_tokens.dpop_jkt is the thumbprint of the DPoP key a public client's refresh-token family
// is bound to (#42 decision 11). These pin what the data layer owes it on every engine: it
// round-trips, NULL included; a full-row update can neither change nor clear it; and concurrent
// rotations of one bound token, through the real issuer, leave exactly one child, bound to the
// family's key.
//
// The thumbprints are literals, RFC 7638 section 3.1's example and a second value of the same
// shape: the data layer stores and the issuer copies them, and nothing here computes one.
const (
	bindingFamilyKey = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	bindingOtherKey  = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
)

func TestRefreshToken_DPoPJktRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding sql.NullString
	}{
		{"a bound token reads its key's thumbprint", sql.NullString{String: bindingFamilyKey, Valid: true}},
		{"an unbound token reads NULL", sql.NullString{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := seedBoundRefreshToken(t, tc.binding)

			byId, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
			require.NoError(t, err)
			byJti, err := database.GetRefreshTokenByJti(context.Background(), nil, created.RefreshTokenJti)
			require.NoError(t, err)
			for _, read := range []*record.RefreshToken{byId, byJti} {
				require.NotNil(t, read)
				assert.Equal(t, tc.binding, read.DPoPJkt)
			}
		})
	}
}

// Tagged dont-update, like auth_state_generation: the binding is set when a token is born and
// never by an update, so a full-row update with another key, or with none, leaves it as it was,
// and an unbound token cannot be bound by one either.
func TestUpdateRefreshToken_NeitherChangesNorClearsTheDPoPBinding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding sql.NullString
	}{
		{"a bound token", sql.NullString{String: bindingFamilyKey, Valid: true}},
		{"an unbound token", sql.NullString{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := seedBoundRefreshToken(t, tc.binding)

			for _, inHand := range []sql.NullString{{String: bindingOtherKey, Valid: true}, {}} {
				reloaded, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
				require.NoError(t, err)
				reloaded.DPoPJkt = inHand
				reloaded.Scope = "openid " + fake.LetterN(6)
				require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, reloaded))

				after, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
				require.NoError(t, err)
				assert.Equal(t, tc.binding, after.DPoPJkt, "UpdateRefreshToken with %v in hand moved dpop_jkt (is the dont-update tag missing?)", inHand)
				assert.Equal(t, reloaded.Scope, after.Scope, "the rest of the update still applies")
			}

			claimed, err := database.MarkRefreshTokenAsRevoked(context.Background(), nil, created.Id)
			require.NoError(t, err)
			require.True(t, claimed)
			after, err := database.GetRefreshTokenById(context.Background(), nil, created.Id)
			require.NoError(t, err)
			assert.Equal(t, tc.binding, after.DPoPJkt, "the rotation's claim leaves the binding as it was")
		})
	}
}

// seedBoundRefreshToken writes an ROPC-shaped token bound to binding, NULL for none.
func seedBoundRefreshToken(t *testing.T, binding sql.NullString) *record.RefreshToken {
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
		AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
		DPoPJkt:              binding,
	}
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, token))
	return token
}

// Concurrent rotations of one token through the real issuer, each presenting the token as the
// validator read it before any began: by the family's key, by another key, and with no proof. On a
// bound family exactly one commits, by the family's key, and every token the family holds afterwards
// is bound to it, so no rotation, however raced, yields an unbound token in a bound family. On an
// unbound family of a public client the same race binds it exactly when the winner carried a proof.
// Rotations here genuinely overlap on every engine but SQLite, whose pool has one connection.
func TestRefreshRotation_ConcurrentRotationsKeepTheFamilysDPoPBinding(t *testing.T) {
	const rotations = 9
	thumbprints := []string{bindingFamilyKey, "", bindingOtherKey}

	for _, ropc := range []bool{false, true} {
		shape := "code-descended family"
		if ropc {
			shape = "password grant family"
		}
		for _, bound := range []bool{true, false} {
			name := shape + ", bound"
			proofs := thumbprints
			if !bound {
				name = shape + ", unbound"
				proofs = thumbprints[:2]
			}
			t.Run(name, func(t *testing.T) {
				withRealSigningKeyOn(t, database)
				f := newBindingFamily(t, database, ropc, bound)

				inputs := make([]*issuance.RefreshTokenGrantInput, rotations)
				for i := range inputs {
					inputs[i] = f.presenting(t, database, f.live.RefreshTokenJti)
					inputs[i].DPoPThumbprint = proofs[i%len(proofs)]
				}

				start := make(chan struct{})
				var wg sync.WaitGroup
				var mu sync.Mutex
				var winners []*issuance.RefreshTokenGrantInput
				var children []string
				var refusals []error
				for _, input := range inputs {
					wg.Add(1)
					go func(input *issuance.RefreshTokenGrantInput) {
						defer wg.Done()
						<-start
						response, _, err := refreshIssuerOn(database).IssueRefreshTokenGrant(context.Background(), rotationSettings(), input)
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							refusals = append(refusals, err)
							return
						}
						winners = append(winners, input)
						children = append(children, response.RefreshToken)
					}(input)
				}
				close(start)
				wg.Wait()

				for _, err := range refusals {
					assert.Truef(t, errors.Is(err, issuance.ErrRefreshTokenNotClaimed) || errors.Is(err, issuance.ErrRefreshTokenBindingMismatch),
						"a rotation that did not commit lost its claim or did not prove the key, got %v", err)
				}
				require.Len(t, winners, 1, "exactly one rotation commits")
				child := childOf(t, database, children[0])

				if bound {
					assert.Equal(t, bindingFamilyKey, winners[0].DPoPThumbprint, "the rotation that commits is one by the family's key")
					for _, token := range f.tokens(t, database) {
						assert.Equalf(t, sql.NullString{String: bindingFamilyKey, Valid: true}, token.DPoPJkt,
							"every token of the bound family is bound to its key, %s", token.RefreshTokenJti)
					}
					return
				}
				want := sql.NullString{String: winners[0].DPoPThumbprint, Valid: winners[0].DPoPThumbprint != ""}
				assert.Equal(t, want, child.DPoPJkt, "the child is bound to the winner's proof key, or unbound when it carried none")
			})
		}
	}
}

// newBindingFamily is newFamily's two members for a public client, the live one bound to the
// family's key when bound, as the family's first bound token or its copy would be.
func newBindingFamily(t *testing.T, db data.Database, ropc bool, bound bool) *family {
	t.Helper()
	f := newFamily(t, db, ropc)

	client, err := db.GetClientById(context.Background(), nil, f.client.Id)
	require.NoError(t, err)
	client.IsPublic = true
	client.AuthorizationCodeEnabled = true
	require.NoError(t, db.UpdateClient(context.Background(), nil, client))
	f.client = client

	if !bound {
		return f
	}
	// The live member was born unbound, and no update binds it: retire it and give the family a
	// bound live member in its place.
	claimed, err := db.MarkRefreshTokenAsRevoked(context.Background(), nil, f.live.Id)
	require.NoError(t, err)
	require.True(t, claimed)
	live := *f.live
	live.Id = 0
	live.RefreshTokenJti = fake.UUID()
	live.PreviousRefreshTokenJti = f.live.RefreshTokenJti
	live.Revoked = false
	live.DPoPJkt = sql.NullString{String: bindingFamilyKey, Valid: true}
	require.NoError(t, db.CreateRefreshToken(context.Background(), nil, &live))
	f.live = &live
	return f
}

// tokens is every refresh token born bound or after the family's live member: the live member and
// every child of it.
func (f *family) tokens(t *testing.T, db data.Database) []*record.RefreshToken {
	t.Helper()
	var all []*record.RefreshToken
	var err error
	if f.ropc {
		all, err = db.GetRefreshTokensByUserId(context.Background(), nil, f.user.Id)
	} else {
		all, err = db.GetRefreshTokensByCodeId(context.Background(), nil, f.code.Id)
	}
	require.NoError(t, err)

	var fromLive []*record.RefreshToken
	for _, token := range all {
		if token.RefreshTokenJti == f.live.RefreshTokenJti || token.PreviousRefreshTokenJti == f.live.RefreshTokenJti {
			fromLive = append(fromLive, token)
		}
	}
	require.NotEmpty(t, fromLive)
	return fromLive
}
