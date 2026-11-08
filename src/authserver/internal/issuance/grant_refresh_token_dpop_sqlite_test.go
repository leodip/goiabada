package issuance

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
)

// A public client's refresh tokens bound to its DPoP key (RFC 9449 section 5, #42 decision 11),
// through the issuer's three grants that write a refresh token, over a real SQLite database migrated
// to head: the family's first bound token, the binding copied through every rotation, the upgrade of
// an unbound family, a confidential client's family left unbound, a binding kept once the client is
// confidential, and concurrent rotations of one token, run under the race detector in the race
// tier. The token endpoint's validator refuses a refresh without the bound key before the issuer is
// asked; the issuer refuses one too, so nothing it is handed can mint from a bound token without
// that key. The data tier runs the same rotations on all four engines.
//
// The thumbprints are literals, RFC 7638 section 3.1's example and a second value of the same
// shape: the issuer stores and compares them, and never computes one.
const (
	familyKey = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	otherKey  = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
)

// familyShape is which grant starts a family: the code exchange, whose tokens name their code, or
// the password grant, whose tokens name their user and client.
type familyShape struct {
	name string
	ropc bool
}

var familyShapes = []familyShape{{"code-descended family", false}, {"password grant family", true}}

type bindingFixture struct {
	t        *testing.T
	db       *sqlitedb.Database
	issuer   *TokenIssuer
	settings *record.Settings
	client   *record.Client
	user     *record.User
	shape    familyShape
}

func newBindingFixture(t *testing.T, shape familyShape, public bool) *bindingFixture {
	t.Helper()
	ctx := context.Background()

	db, err := sqlitedb.New(ctx, "file:"+filepath.Join(t.TempDir(), "refresh_binding_test.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })
	m, err := db.NewMigrator(ctx, nil)
	require.NoError(t, err)
	if upErr := m.Up(ctx); upErr != nil && !errors.Is(upErr, migrator.ErrNoChange) {
		require.NoError(t, upErr, "migrate to head")
	}

	keyPair, err := signingkeys.NewKeyPair(testDataCipher, record.KeyStateCurrent, 2048)
	require.NoError(t, err)
	require.NoError(t, db.CreateKeyPair(ctx, nil, keyPair))

	ropcOn := true
	client := &record.Client{
		ClientIdentifier:                        "binding-client-" + fake.LetterN(6),
		Enabled:                                 true,
		IsPublic:                                public,
		AuthorizationCodeEnabled:                true,
		ResourceOwnerPasswordCredentialsEnabled: &ropcOn,
		DefaultAcrLevel:                         record.AcrLevel1,
	}
	require.NoError(t, db.CreateClient(ctx, nil, client))
	user := &record.User{
		Enabled:  true,
		Subject:  fake.UUID(),
		Username: "binding-" + fake.LetterN(6),
		Email:    fake.LetterN(8) + "@example.com",
	}
	require.NoError(t, db.CreateUser(ctx, nil, user))

	return &bindingFixture{
		t:      t,
		db:     db,
		issuer: NewTokenIssuer(db, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil),
		settings: &record.Settings{
			Issuer:                                  "https://binding.example.com",
			TokenExpirationInSeconds:                300,
			RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
			RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
			ResourceOwnerPasswordCredentialsEnabled: true,
		},
		client: client,
		user:   user,
		shape:  shape,
	}
}

// start begins a family, the request carrying a proof whose thumbprint is thumbprint, empty for
// none, and returns the jti of its first refresh token.
func (f *bindingFixture) start(thumbprint string) string {
	f.t.Helper()
	ctx := context.Background()

	if f.shape.ropc {
		response, err := f.issuer.IssuePasswordGrant(ctx, f.settings, &ROPCGrantInput{
			Client: f.currentClient(), User: f.user, Scope: "openid", DPoPThumbprint: thumbprint,
		})
		require.NoError(f.t, err)
		return refreshJti(f.t, response.RefreshToken)
	}

	// No session: the grant is offline, so nothing here depends on a session row.
	code := &record.Code{
		ClientId:            f.client.Id,
		UserId:              f.user.Id,
		CodeHash:            "hash_" + fake.LetterN(12),
		CodeChallenge:       sql.NullString{String: "challenge_" + fake.LetterN(6), Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid offline_access",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Add(-time.Minute),
		AcrLevel:            record.AcrLevel1,
		AuthMethods:         "pwd",
	}
	require.NoError(f.t, f.db.CreateCode(ctx, nil, code))
	response, err := f.issuer.IssueAuthorizationCodeGrant(ctx, f.settings, code, thumbprint)
	require.NoError(f.t, err)
	return refreshJti(f.t, response.RefreshToken)
}

func (f *bindingFixture) currentClient() *record.Client {
	f.t.Helper()
	client, err := f.db.GetClientById(context.Background(), nil, f.client.Id)
	require.NoError(f.t, err)
	return client
}

// presenting is what the token endpoint hands the issuer for a refresh of the token with this jti,
// with a proof whose thumbprint is thumbprint: the row as the validator reads it, its code loaded
// for a code-descended token, and the client as it is now.
func (f *bindingFixture) presenting(jti string, thumbprint string) *RefreshTokenGrantInput {
	f.t.Helper()
	token := f.row(jti)
	if !f.shape.ropc {
		require.NoError(f.t, f.db.RefreshTokenLoadCode(context.Background(), nil, token))
	}
	return &RefreshTokenGrantInput{
		Client:         f.currentClient(),
		RefreshToken:   token,
		IsROPC:         f.shape.ropc,
		DPoPThumbprint: thumbprint,
	}
}

// refresh rotates the token with this jti and returns the child's jti.
func (f *bindingFixture) refresh(jti string, thumbprint string) (string, error) {
	f.t.Helper()
	response, _, err := f.issuer.IssueRefreshTokenGrant(context.Background(), f.settings, f.presenting(jti, thumbprint))
	if err != nil {
		return "", err
	}
	return refreshJti(f.t, response.RefreshToken), nil
}

func (f *bindingFixture) row(jti string) *record.RefreshToken {
	f.t.Helper()
	token, err := f.db.GetRefreshTokenByJti(context.Background(), nil, jti)
	require.NoError(f.t, err)
	require.NotNil(f.t, token, "refresh token %s", jti)
	return token
}

// binding is the thumbprint the token with this jti is bound to, empty for none.
func (f *bindingFixture) binding(jti string) string {
	f.t.Helper()
	token := f.row(jti)
	if token.DPoPJkt.Valid {
		require.NotEmpty(f.t, token.DPoPJkt.String, "a binding is NULL or a thumbprint, never empty")
	}
	return token.DPoPJkt.String
}

func (f *bindingFixture) makeConfidential() {
	f.t.Helper()
	client := f.currentClient()
	client.IsPublic = false
	secret, err := testDataCipher.Encrypt("a-secret-" + fake.LetterN(8))
	require.NoError(f.t, err)
	client.ClientSecretEncrypted = secret
	require.NoError(f.t, f.db.UpdateClient(context.Background(), nil, client))
}

func refreshJti(t *testing.T, refreshToken string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(refreshToken, claims)
	require.NoError(t, err)
	jti, ok := claims["jti"].(string)
	require.True(t, ok, "the refresh token names its jti")
	return jti
}

func TestRefreshTokenBinding_APublicClientsFirstTokenIsBoundAndEveryRotationCopiesIt(t *testing.T) {
	for _, shape := range familyShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			first := f.start(familyKey)
			assert.Equal(t, familyKey, f.binding(first), "the family's first token is bound to the proof's key")

			child, err := f.refresh(first, familyKey)
			require.NoError(t, err)
			assert.Equal(t, familyKey, f.binding(child), "the rotation copies the parent's binding")

			grandchild, err := f.refresh(child, familyKey)
			require.NoError(t, err)
			assert.Equal(t, familyKey, f.binding(grandchild), "and so does every later one")
		})
	}
}

func TestRefreshTokenBinding_ABoundTokenIsNotRotatedWithoutItsKey(t *testing.T) {
	for _, shape := range familyShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			first := f.start(familyKey)

			for _, thumbprint := range []string{"", otherKey} {
				_, err := f.refresh(first, thumbprint)
				require.ErrorIs(t, err, ErrRefreshTokenBindingMismatch, "a refresh with the proof key %q", thumbprint)
				assert.False(t, f.row(first).Revoked, "the refused rotation spends nothing")
			}

			child, err := f.refresh(first, familyKey)
			require.NoError(t, err, "the token is still the key holder's to refresh")
			assert.Equal(t, familyKey, f.binding(child))
		})
	}
}

// A public client's unbound family, begun without a proof or before this change, is bound by its
// first refresh with a proof, and stays bound (RFC 9449 section 5's MUST).
func TestRefreshTokenBinding_AnUnboundFamilyOfAPublicClientIsBoundByItsFirstRefreshWithAProof(t *testing.T) {
	for _, shape := range familyShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			first := f.start("")
			assert.Empty(t, f.binding(first), "a family begun without a proof is unbound")

			child, err := f.refresh(first, "")
			require.NoError(t, err)
			assert.Empty(t, f.binding(child), "a refresh without a proof leaves it unbound")

			bound, err := f.refresh(child, familyKey)
			require.NoError(t, err)
			assert.Equal(t, familyKey, f.binding(bound), "the first refresh with a proof binds the family")

			_, err = f.refresh(bound, "")
			require.ErrorIs(t, err, ErrRefreshTokenBindingMismatch, "a bound family never becomes unbound")
			_, err = f.refresh(bound, otherKey)
			require.ErrorIs(t, err, ErrRefreshTokenBindingMismatch, "nor moves to another key")
		})
	}
}

// A confidential client's family is never bound, whether its first token or a refresh carried the
// proof: its client authentication already ties the token to it, and leaving it unbound keeps its
// key rotation (#42 decision 11).
func TestRefreshTokenBinding_AConfidentialClientsFamilyStaysUnbound(t *testing.T) {
	for _, shape := range familyShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newBindingFixture(t, shape, false)
			first := f.start(familyKey)
			assert.Empty(t, f.binding(first), "the first token of a confidential client's family is unbound")

			child, err := f.refresh(first, otherKey)
			require.NoError(t, err, "a refresh with another key is answered")
			assert.Empty(t, f.binding(child), "and leaves the family unbound")

			grandchild, err := f.refresh(child, "")
			require.NoError(t, err, "as is one without a proof")
			assert.Empty(t, f.binding(grandchild))
		})
	}
}

// A binding already on a family is enforced and inherited whatever the client's type is now: a
// public client switched to confidential keeps its grants, and their refreshes still take a proof
// by the family's key. Only the first binding of an unbound family depends on the client being
// public at that refresh.
func TestRefreshTokenBinding_ABoundFamilyStaysBoundOnceItsClientIsConfidential(t *testing.T) {
	for _, shape := range familyShapes {
		t.Run(shape.name, func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			bound := f.start(familyKey)
			unbound := f.start("")
			f.makeConfidential()

			for _, thumbprint := range []string{"", otherKey} {
				_, err := f.refresh(bound, thumbprint)
				require.ErrorIs(t, err, ErrRefreshTokenBindingMismatch, "a refresh with the proof key %q", thumbprint)
			}
			child, err := f.refresh(bound, familyKey)
			require.NoError(t, err)
			assert.Equal(t, familyKey, f.binding(child), "the binding is inherited")

			upgraded, err := f.refresh(unbound, familyKey)
			require.NoError(t, err)
			assert.Empty(t, f.binding(upgraded), "a confidential client's refresh binds no unbound family")
		})
	}
}

// Concurrent rotations of one token, by the family's key, by another key and with no proof at all:
// exactly one rotation commits, it is one by the family's key, and no rotation, however raced,
// leaves an unbound token in the bound family. For an unbound family the same race binds it
// exactly when the rotation that won carried a proof.
func TestRefreshTokenBinding_ConcurrentRotationsNeverLeaveAnUnboundTokenInABoundFamily(t *testing.T) {
	const rotations = 12
	thumbprints := []string{familyKey, "", otherKey}

	for _, shape := range familyShapes {
		t.Run(shape.name+", bound family", func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			first := f.start(familyKey)

			winners := raceRotations(t, f, first, rotations, func(i int) string { return thumbprints[i%len(thumbprints)] })
			require.Len(t, winners, 1, "exactly one rotation commits")
			assert.Equal(t, familyKey, winners[0].thumbprint, "and it is one by the family's key")
			assert.Equal(t, familyKey, f.binding(winners[0].child))

			for _, token := range f.family(first) {
				assert.Truef(t, token.DPoPJkt.Valid && token.DPoPJkt.String == familyKey,
					"every token of the family is bound to its key, %s is bound to %v", token.RefreshTokenJti, token.DPoPJkt)
			}
		})

		t.Run(shape.name+", unbound family", func(t *testing.T) {
			f := newBindingFixture(t, shape, true)
			first := f.start("")

			winners := raceRotations(t, f, first, rotations, func(i int) string { return thumbprints[i%2] })
			require.Len(t, winners, 1, "exactly one rotation commits")
			assert.Equal(t, winners[0].thumbprint, f.binding(winners[0].child),
				"the child is bound to the winner's proof key, or unbound when it carried none")
		})
	}
}

type rotationWinner struct {
	thumbprint string
	child      string
}

// raceRotations runs rotations rotations of the token with this jti at once, the i-th with a proof
// whose thumbprint is thumbprintOf(i), every one presenting the token as it was read before any
// began, and returns the ones that committed. Every other is refused for the claim it lost or for
// the key it did not prove.
func raceRotations(t *testing.T, f *bindingFixture, jti string, rotations int, thumbprintOf func(int) string) []rotationWinner {
	t.Helper()

	inputs := make([]*RefreshTokenGrantInput, rotations)
	for i := range inputs {
		inputs[i] = f.presenting(jti, thumbprintOf(i))
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []rotationWinner
	var refusals []error
	for i := range inputs {
		wg.Add(1)
		go func(input *RefreshTokenGrantInput) {
			defer wg.Done()
			<-start
			response, _, err := f.issuer.IssueRefreshTokenGrant(context.Background(), f.settings, input)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				refusals = append(refusals, err)
				return
			}
			winners = append(winners, rotationWinner{thumbprint: input.DPoPThumbprint, child: response.RefreshToken})
		}(inputs[i])
	}
	close(start)
	wg.Wait()

	for _, err := range refusals {
		assert.Truef(t, errors.Is(err, ErrRefreshTokenNotClaimed) || errors.Is(err, ErrRefreshTokenBindingMismatch),
			"a rotation that did not commit lost its claim or did not prove the key, got %v", err)
	}
	for i := range winners {
		winners[i].child = refreshJti(t, winners[i].child)
	}
	return winners
}

// family is every refresh token of the family whose first token has this jti.
func (f *bindingFixture) family(firstJti string) []*record.RefreshToken {
	f.t.Helper()
	var tokens []*record.RefreshToken
	var err error
	if f.shape.ropc {
		tokens, err = f.db.GetRefreshTokensByUserId(context.Background(), nil, f.user.Id)
	} else {
		tokens, err = f.db.GetRefreshTokensByCodeId(context.Background(), nil, f.row(firstJti).CodeId.Int64)
	}
	require.NoError(f.t, err)
	require.NotEmpty(f.t, tokens)
	return tokens
}
