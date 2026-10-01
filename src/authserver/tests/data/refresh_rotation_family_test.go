package datatests

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refresh rotation claims the presented token and inserts its child in ONE transaction, and a
// family's revocation record is what a revocation leaves behind for that rotation to find (#132,
// #259, #437). The unit tests pin the order of the statements and the transaction each is handed;
// this file is where an engine shows what a mock cannot: a containment or a client made public that
// arrives between the claim and the insert, on a real catalog, with the two transactions genuinely
// overlapping. The rotation is the real IssueRefreshTokenGrant, paused at its child's insert, so the
// statements measured are the ones that ship.
//
// The gap cannot be shut by the sweep alone: a rotation's parent is claimed and uncommitted, so the
// sweep's predicate either waits on it or skips it, and the child does not exist yet for the sweep
// to find. The invariant is therefore not that the child is revoked, which differs by engine, but
// that it cannot be redeemed: it is revoked, or it was born into a recorded family and is refused.

// noBumps is the session port a rotation bumps through, which these cases do not exercise.
type noBumps struct{}

func (noBumps) BumpUserSession(context.Context, string, int64, string, models.AcrLevel, string) (*models.UserSession, error) {
	return nil, nil
}

// pausingInserts holds a rotation at the moment it inserts its child, handing the test the
// transaction it is in. Only the first insert pauses: a deadlock's rerun reaches it again and must
// not wait for a release that has already come.
type pausingInserts struct {
	data.Database
	paused  chan *sql.Tx
	release chan struct{}
	once    sync.Once
}

func newPausingInserts(db data.Database) *pausingInserts {
	return &pausingInserts{Database: db, paused: make(chan *sql.Tx, 1), release: make(chan struct{})}
}

func (p *pausingInserts) CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error {
	p.once.Do(func() {
		p.paused <- tx
		<-p.release
	})
	return p.Database.CreateRefreshToken(ctx, tx, refreshToken)
}

func rotationSettings() *models.Settings {
	settings := implicitSettings()
	settings.UserSessionIdleTimeoutInSeconds = 1200
	settings.UserSessionMaxLifetimeInSeconds = 2400
	settings.RefreshTokenOfflineIdleTimeoutInSeconds = 1800
	settings.RefreshTokenOfflineMaxLifetimeInSeconds = 3600
	settings.ResourceOwnerPasswordCredentialsEnabled = true
	return settings
}

// familyShape is which grant a rotation family descends from, and so which way a credential change
// treats it: a session-bound code's tokens are kept alive when the change preserves their session, an
// offline grant's are kept alive the same way because their code names the session they came from,
// and a password grant's are revoked, having no session to preserve (#131).
type familyShape int

const (
	sessionBoundFamily familyShape = iota
	offlineFamily
	passwordGrantFamily
)

func (s familyShape) String() string {
	return [...]string{"session-bound family", "offline family", "password grant family"}[s]
}

// family is a rotation family of two members, an earlier one that is already revoked and the live
// one a refresh would present, and the shape it is: code-descended, or a password grant's.
type family struct {
	ropc    bool
	offline bool
	client  *models.Client
	user    *models.User
	code    *models.Code
	// replayed is the earlier, revoked member: presenting it is a replay.
	replayed *models.RefreshToken
	// live is the member a refresh presents.
	live *models.RefreshToken
}

func (f *family) firstJti() string { return f.replayed.RefreshTokenJti }

func newFamily(t *testing.T, db data.Database, ropc bool) *family {
	t.Helper()

	if ropc {
		return newFamilyOfShape(t, db, passwordGrantFamily)
	}
	return newFamilyOfShape(t, db, sessionBoundFamily)
}

func newFamilyOfShape(t *testing.T, db data.Database, shape familyShape) *family {
	t.Helper()

	ropc := shape == passwordGrantFamily
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)
	f := &family{ropc: ropc, offline: shape == offlineFamily, client: client, user: user}

	now := time.Now().UTC().Truncate(time.Microsecond)
	firstJti := fake.UUID()
	row := func(jti string, revoked bool) *models.RefreshToken {
		token := &models.RefreshToken{
			RefreshTokenJti:      jti,
			FirstRefreshTokenJti: firstJti,
			Revoked:              revoked,
			Scope:                "openid profile",
			IssuedAt:             sql.NullTime{Time: now, Valid: true},
			ExpiresAt:            sql.NullTime{Time: now.Add(time.Hour), Valid: true},
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		}
		if jti != firstJti {
			token.PreviousRefreshTokenJti = firstJti
		}
		if ropc {
			token.UserId = sql.NullInt64{Int64: user.Id, Valid: true}
			token.ClientId = sql.NullInt64{Int64: client.Id, Valid: true}
			token.RefreshTokenType = "Offline"
			token.AuthenticatedAt = sql.NullTime{Time: now.Add(-time.Hour), Valid: true}
		} else if f.offline {
			// An offline grant's token names no session of its own: the one it came from is on its code.
			token.CodeId = sql.NullInt64{Int64: f.code.Id, Valid: true}
			token.RefreshTokenType = "Offline"
			token.Scope = "openid profile offline_access"
		} else {
			token.CodeId = sql.NullInt64{Int64: f.code.Id, Valid: true}
			token.SessionIdentifier = f.code.SessionIdentifier
			token.RefreshTokenType = "Refresh"
		}
		require.NoError(t, db.CreateRefreshToken(context.Background(), nil, token))
		return token
	}

	if !ropc {
		session := createTestUserSessionOn(t, db, user.Id)
		f.code = createTestCodeInSessionOn(t, db, client.Id, user.Id, session.SessionIdentifier)
		if f.offline {
			f.code.Scope = "openid profile offline_access"
			require.NoError(t, db.UpdateCode(context.Background(), nil, f.code))
		}
	}
	f.replayed = row(firstJti, true)
	f.live = row(fake.UUID(), false)
	return f
}

// presenting is the input the token endpoint hands the issuer for a presentation of the token with
// this jti, as the validator reads it: the row as it is now, its code loaded for the code shape, and
// the flow on for the client.
func (f *family) presenting(t *testing.T, db data.Database, jti string) *issuance.RefreshTokenGrantInput {
	t.Helper()

	token, err := db.GetRefreshTokenByJti(context.Background(), nil, jti)
	require.NoError(t, err)
	require.NotNil(t, token)
	if !f.ropc {
		require.NoError(t, db.RefreshTokenLoadCode(context.Background(), nil, token))
	}
	client := *f.client
	client.AuthorizationCodeEnabled = true
	ropcOn := true
	client.ResourceOwnerPasswordCredentialsEnabled = &ropcOn
	return &issuance.RefreshTokenGrantInput{
		Client:         &client,
		RefreshToken:   token,
		ScopeRequested: "openid profile",
		IsROPC:         f.ropc,
	}
}

// members is how many refresh tokens the family's grant holds, by the linkage its shape has.
func (f *family) members(t *testing.T, db data.Database) int {
	t.Helper()

	var tokens []*models.RefreshToken
	var err error
	if f.ropc {
		tokens, err = db.GetRefreshTokensByUserId(context.Background(), nil, f.user.Id)
	} else {
		tokens, err = db.GetRefreshTokensByCodeId(context.Background(), nil, f.code.Id)
	}
	require.NoError(t, err)
	return len(tokens)
}

func childOf(t *testing.T, db data.Database, response string) *models.RefreshToken {
	t.Helper()

	child, err := db.GetRefreshTokenByJti(context.Background(), nil, claimsOf(t, response)["jti"].(string))
	require.NoError(t, err)
	require.NotNil(t, child, "the rotation's child was inserted")
	return child
}

// requireUnredeemable asserts the child can no longer be refreshed: presenting it is refused as a
// replay when it was revoked, and by the rotation's own family check when it is live in a recorded
// family. Which of the two an engine leaves behind is the engine's; that it is one of them is the
// decision.
func (f *family) requireUnredeemable(t *testing.T, db data.Database, child *models.RefreshToken) {
	t.Helper()

	presented := f.presenting(t, db, child.RefreshTokenJti)
	_, _, err := refreshIssuerOn(db).IssueRefreshTokenGrant(context.Background(), rotationSettings(), presented)

	var replayed *issuance.RefreshTokenReplayedError
	refused := errors.Is(err, issuance.ErrRefreshFamilyRevoked) || errors.As(err, &replayed)
	require.True(t, refused, "a child of a revoked family must be refused, got %v", err)
}

// requireNoRedeemableChild is the decision's invariant for a rotation that raced a revocation of its
// family, whichever way the engine ordered them. Either the rotation committed, and the child it
// inserted cannot be refreshed, which is the record doing its work on the engines where the
// revocation's sweep read the family before the child existed; or the engine chose the rotation as
// the victim of a deadlock with the revocation (MySQL's foreign key takes a shared lock on the code
// row the client's revocation has marked), RunInTransaction reran it, and the rerun found its
// parent already revoked or the family recorded, so nothing was inserted (pattern 6, #301).
func requireNoRedeemableChild(t *testing.T, f *family, result rotationResult) {
	t.Helper()

	if result.err == nil {
		child := childOf(t, database, result.response)
		f.requireUnredeemable(t, database, child)
		assert.Equal(t, 3, f.members(t, database), "the refused attempt to refresh the child inserted no grandchild")
		return
	}

	refused := errors.Is(result.err, issuance.ErrRefreshTokenNotClaimed) || errors.Is(result.err, issuance.ErrRefreshFamilyRevoked)
	require.True(t, refused, "a rotation that lost the race is refused cleanly, got %v", result.err)
	assert.Equal(t, 2, f.members(t, database), "a refused rotation inserted no child")
}

func refreshIssuerOn(db data.Database) *issuance.TokenIssuer {
	return issuance.NewTokenIssuer(db, implicitTestBaseURL, dataCipher, noBumps{})
}

type rotationResult struct {
	response string
	err      error
}

// startRotation runs the real rotation of the family's live token in the background, paused at its
// child's insert, and returns the transaction it holds at that point with the channel its outcome
// arrives on.
func startRotation(t *testing.T, ctx context.Context, f *family, pause *pausingInserts) (*sql.Tx, chan rotationResult) {
	t.Helper()

	outcome := make(chan rotationResult, 1)
	input := f.presenting(t, pause, f.live.RefreshTokenJti)
	go func() {
		response, _, err := refreshIssuerOn(pause).IssueRefreshTokenGrant(ctx, rotationSettings(), input)
		result := rotationResult{err: err}
		if response != nil {
			result.response = response.RefreshToken
		}
		outcome <- result
	}()

	select {
	case tx := <-pause.paused:
		return tx, outcome
	case result := <-outcome:
		t.Fatalf("the rotation finished before it inserted its child: %v", result.err)
	case <-time.After(blockedCeiling):
		t.Fatal("the rotation never reached its child's insert")
	}
	return nil, nil
}

// skipWhereTransactionsCannotOverlap skips a forced interleaving on the engine that cannot have
// one. sqlitedb has one connection per process, so a deployment's two transactions never overlap:
// the second waits for the pool, and the rotation and the revocation run one after the other. The
// second handle this tier opens is a second connection, which on SQLite makes the second writer
// fail at once with SQLITE_BUSY instead of waiting, a shape no deployment has. The sequential
// cases below run on every engine, SQLite included.
func skipWhereTransactionsCannotOverlap(t *testing.T) {
	t.Helper()
	if dbType() == data.SQLite {
		t.Skip("SQLite's pool has one connection, so a rotation and a revocation cannot overlap in a deployment; the sequential cases cover it")
	}
}

// A containment of the family arriving while a rotation holds its claim and has not inserted its
// child. The rotation's parent row is claimed and uncommitted, so the containment's sweep waits on
// it; the rotation then inserts the child and commits, and the containment resumes having
// recorded the family (#132). Whatever the engine leaves of the child's revoked flag, it cannot be
// refreshed, and no grandchild is ever inserted.
func TestRefreshRotation_AContainmentBetweenTheClaimAndTheInsertLeavesAChildThatCannotBeRedeemed(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	for _, ropc := range []bool{false, true} {
		name := "code-descended family"
		if ropc {
			name = "password grant family"
		}
		t.Run(name, func(t *testing.T) {
			other := secondDatabase(t)
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamily(t, database, ropc)
			// Read before the rotation holds anything: a read on the package's handle while the
			// rotation's transaction holds SQLite's one write lock is not what this case measures.
			replayInput := f.presenting(t, database, f.replayed.RefreshTokenJti)
			pause := newPausingInserts(database)
			tx, rotation := startRotation(t, ctx, f, pause)

			// The replay of the earlier, revoked member, arriving on the other handle.
			containment := goBlocked(t, "the containment of the family", tx, func(reached func()) error {
				reached()
				_, _, err := refreshIssuerOn(other).IssueRefreshTokenGrant(ctx, rotationSettings(), replayInput)
				return err
			})
			containment.requireBlocked(t)
			containment.requireStillWaiting(t)

			close(pause.release)
			result := <-rotation

			var replayed *issuance.RefreshTokenReplayedError
			require.ErrorAs(t, containment.await(t), &replayed, "the replay is refused as a replay once it resumes")
			assert.True(t, replayed.FamilyRecorded, "this containment wrote the family's record")

			recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, f.firstJti())
			require.NoError(t, err)
			assert.True(t, recorded, "the family is recorded")

			requireNoRedeemableChild(t, f, result)
		})
	}
}

// A client made public while a rotation holds its claim. The flip's sweep read the client's tokens
// before the child existed, so the child is live after the flip commits on every engine: it is the
// family's record, written by the flip in its own transaction for every family the client holds a
// token of, that refuses it (#259).
func TestRefreshRotation_AClientMadePublicBetweenTheClaimAndTheInsertLeavesAChildThatCannotBeRedeemed(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	for _, ropc := range []bool{false, true} {
		name := "code-descended family"
		if ropc {
			name = "password grant family"
		}
		t.Run(name, func(t *testing.T) {
			other := secondDatabase(t)
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamily(t, database, ropc)
			pause := newPausingInserts(database)
			tx, rotation := startRotation(t, ctx, f, pause)

			flip := goBlocked(t, "the client's revocation", tx, func(reached func()) error {
				reached()
				_, err := revocation.RevokeClientGrantsTx(ctx, other, f.client.Id, func(*sql.Tx) (bool, error) { return true, nil })
				return err
			})
			flip.requireBlocked(t)
			flip.requireStillWaiting(t)

			close(pause.release)
			result := <-rotation
			require.NoError(t, flip.await(t), "the revocation commits, rerun once if the engine chose it as a deadlock victim")

			recorded, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, f.firstJti())
			require.NoError(t, err)
			assert.True(t, recorded, "the flip recorded the family although one of its members was mid-rotation")

			requireNoRedeemableChild(t, f, result)
		})
	}
}

// A containment that committed before the rotation started: the family is recorded while its live
// member is untouched, which is what a client's revocation leaves for a member it has not swept. The
// rotation claims the token and finds the record, so it rolls back: the claim is undone and no child
// is inserted (#132, #259).
func TestRefreshRotation_ARecordedFamilyRollsTheRotationBack(t *testing.T) {
	for _, ropc := range []bool{false, true} {
		name := "code-descended family"
		if ropc {
			name = "password grant family"
		}
		t.Run(name, func(t *testing.T) {
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamily(t, database, ropc)
			written, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, f.firstJti(), "test_family_record")
			require.NoError(t, err)
			require.True(t, written)

			_, _, err = refreshIssuerOn(database).IssueRefreshTokenGrant(ctx, rotationSettings(),
				f.presenting(t, database, f.live.RefreshTokenJti))

			require.ErrorIs(t, err, issuance.ErrRefreshFamilyRevoked)
			assertTokenRevoked(t, f.live.Id, false, "the presented token: the claim rolled back with the rotation")
			assert.Equal(t, 2, f.members(t, database), "no child was inserted")
		})
	}
}

// A containment that arrives after the rotation committed: the child exists, is live, and is swept
// with the rest of the family, and the record is written by the same transaction.
func TestRefreshRotation_AContainmentAfterTheRotationRevokesTheChild(t *testing.T) {
	for _, ropc := range []bool{false, true} {
		name := "code-descended family"
		if ropc {
			name = "password grant family"
		}
		t.Run(name, func(t *testing.T) {
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamily(t, database, ropc)
			response, _, err := refreshIssuerOn(database).IssueRefreshTokenGrant(ctx, rotationSettings(),
				f.presenting(t, database, f.live.RefreshTokenJti))
			require.NoError(t, err)
			child := childOf(t, database, response.RefreshToken)

			_, _, err = refreshIssuerOn(database).IssueRefreshTokenGrant(ctx, rotationSettings(),
				f.presenting(t, database, f.replayed.RefreshTokenJti))

			var replayed *issuance.RefreshTokenReplayedError
			require.ErrorAs(t, err, &replayed)
			assert.Equal(t, int64(1), replayed.FamilyRevokedCount, "the child is the one live member")
			assert.True(t, replayed.FamilyRecorded)
			assertTokenRevoked(t, child.Id, true, "the child the containment swept")
			assertTokenRevoked(t, f.live.Id, true, "the parent the rotation claimed")
			f.requireUnredeemable(t, database, child)
		})
	}
}

// A second replay of the same family writes no record and revokes nothing, which is what keeps a
// client from amplifying the audit log by presenting the same token repeatedly.
func TestRefreshRotation_ASecondContainmentIsANoOp(t *testing.T) {
	withRealSigningKeyOn(t, database)
	ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
	defer cancel()

	f := newFamily(t, database, false)
	for attempt := 1; attempt <= 2; attempt++ {
		_, _, err := refreshIssuerOn(database).IssueRefreshTokenGrant(ctx, rotationSettings(),
			f.presenting(t, database, f.replayed.RefreshTokenJti))

		var replayed *issuance.RefreshTokenReplayedError
		require.ErrorAs(t, err, &replayed)
		if attempt == 1 {
			assert.Equal(t, int64(1), replayed.FamilyRevokedCount)
			assert.True(t, replayed.FamilyRecorded)
		} else {
			assert.Zero(t, replayed.FamilyRevokedCount)
			assert.False(t, replayed.FamilyRecorded, "the record is written once")
		}
	}
}

// Every read the rotation's mint makes runs on the rotation's transaction. sqlitedb has one
// connection, so a read on nil while the transaction holds it waits for a connection the
// transaction itself owns until the context expires, and the claim mapper, which swallows a failed
// picture lookup, then drops the claim without an error (#139, #437). So the case is bounded by a
// deadline the real request would also have, and asserts the claim on every engine, for both
// shapes: a picture the user has, in both tokens the rotation mints.
func TestRefreshRotation_KeepsThePictureInBothTokens(t *testing.T) {
	for _, ropc := range []bool{false, true} {
		name := "code-descended family"
		if ropc {
			name = "password grant family"
		}
		t.Run(name, func(t *testing.T) {
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			f := newFamily(t, database, ropc)
			withProfilePictureOn(t, database, f.user.Id)

			response, _, err := refreshIssuerOn(database).IssueRefreshTokenGrant(ctx, rotationSettings(),
				f.presenting(t, database, f.live.RefreshTokenJti))
			require.NoError(t, err, "the rotation completes within its deadline, on this engine's connection model")

			want := implicitTestBaseURL + "/userinfo/picture/" + f.user.Subject
			assert.Equal(t, want, claimsOf(t, response.AccessToken)["picture"], "the access token carries the picture")
			assert.Equal(t, want, claimsOf(t, response.IdToken)["picture"], "the ID token carries the picture")
		})
	}
}
