package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The implicit grant signs inside a transaction that takes the session row first, as the code flow
// does (#197, decision 16), and every read the signing makes runs on that transaction. This file is
// where an engine, and not a mock, shows both: the two orders in which issuance and a termination of
// the session can meet, and the one read a mock cannot prove, the claim mapper's picture lookup,
// which swallows its own failure and so drops the claim without an error when it hangs.

const implicitTestBaseURL = "http://localhost:8081"

// implicitIssuerOn is the issuer /auth/issue signs implicit tokens with, over the handle it is
// given.
func implicitIssuerOn(db data.Database) *issuance.TokenIssuer {
	return issuance.NewTokenIssuer(db, implicitTestBaseURL, dataCipher, nil)
}

// implicitSettings turns the profile claims on for both tokens, so the picture lookup is reached by
// the access token and by the ID token.
func implicitSettings() *record.Settings {
	return &record.Settings{
		Issuer:                                  "https://implicit.example.com",
		TokenExpirationInSeconds:                600,
		IncludeOpenIDConnectClaimsInAccessToken: true,
		IncludeOpenIDConnectClaimsInIdToken:     true,
	}
}

// implicitInput is the ceremony's implicit grant for this client, user and session.
func implicitInput(client *record.Client, user *record.User, sessionIdentifier string) *issuance.ImplicitGrantInput {
	return &issuance.ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             "openid profile",
		AcrLevel:          record.AcrLevel1,
		AuthMethods:       "pwd",
		SessionIdentifier: sessionIdentifier,
		Nonce:             "implicit-nonce",
		AuthenticatedAt:   time.Now().UTC().Add(-time.Minute),
	}
}

// withRealSigningKeyOn makes the database's current signing key one the issuer can really sign
// with, replacing whatever held that state, and puts the state back to empty afterwards: other tests
// in this package create their own fixture key in that state, which the unique index allows once.
func withRealSigningKeyOn(t *testing.T, db data.Database) {
	t.Helper()

	keyPairs, err := db.GetAllSigningKeys(context.Background(), nil)
	require.NoError(t, err)
	for _, existing := range keyPairs {
		if existing.State == record.KeyStateCurrent.String() {
			require.NoError(t, db.DeleteKeyPair(context.Background(), nil, existing.Id))
		}
	}

	keyPair, err := signingkeys.NewKeyPair(dataCipher, record.KeyStateCurrent, 2048)
	require.NoError(t, err, "generating a signing key")
	require.NoError(t, db.CreateKeyPair(context.Background(), nil, keyPair))
	t.Cleanup(func() { _ = db.DeleteKeyPair(context.Background(), nil, keyPair.Id) })
}

// withProfilePictureOn stores a real picture for the user, so the mapper's lookup has something to
// find.
func withProfilePictureOn(t *testing.T, db data.Database, userId int64) {
	t.Helper()
	require.NoError(t, db.CreateUserProfilePicture(context.Background(), nil, &record.UserProfilePicture{
		UserId:      userId,
		Picture:     createTestPNG(100, 100),
		ContentType: "image/png",
	}))
}

// claimsOf reads a token's claims without verifying it: the signature is the issuer unit's, and
// what this file asserts is what the tokens say.
func claimsOf(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err, "parsing a token this test's issuer signed")
	return claims
}

// implicitOutcome is what one implicit ceremony's transaction came to.
type implicitOutcome struct {
	response *issuance.ImplicitGrantResponse
	err      error
}

// The picture lookup is the one read the claim mapper makes, and it is made on the transaction the
// issuance holds. sqlitedb has one connection, so a lookup made on nil while that transaction holds
// it waits for a connection the transaction itself owns until the context expires, and the mapper,
// which swallows a failed lookup, then drops the claim without an error. So the case is bounded by
// a deadline the real handler's request would also have, and asserts the claim, on every engine: a
// picture the user has, in both tokens, under a live session and a real signing key.
func TestIssueImplicit_KeepsThePictureInBothTokens(t *testing.T) {
	db := database
	withRealSigningKeyOn(t, db)
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)
	session := createTestUserSessionOn(t, db, user.Id)
	withProfilePictureOn(t, db, user.Id)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := implicitIssuerOn(db).IssueImplicitTx(ctx, implicitSettings(),
		implicitInput(client, user, session.SessionIdentifier), true, true)
	require.NoError(t, err, "issuance completes within its deadline, on this engine's connection model")
	require.NotNil(t, response)

	want := implicitTestBaseURL + "/userinfo/picture/" + user.Subject
	assert.Equal(t, want, claimsOf(t, response.AccessToken)["picture"], "the access token carries the picture")
	assert.Equal(t, want, claimsOf(t, response.IdToken)["picture"], "the ID token carries the picture")
	assert.Equal(t, session.SessionIdentifier, claimsOf(t, response.AccessToken)["sid"])
}

// A user with no picture gets no claim: the case above is about the lookup being made and answered,
// not about the claim being unconditional.
func TestIssueImplicit_NoPictureNoClaim(t *testing.T) {
	db := database
	withRealSigningKeyOn(t, db)
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)
	session := createTestUserSessionOn(t, db, user.Id)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := implicitIssuerOn(db).IssueImplicitTx(ctx, implicitSettings(),
		implicitInput(client, user, session.SessionIdentifier), true, true)
	require.NoError(t, err)

	assert.NotContains(t, claimsOf(t, response.AccessToken), "picture")
	assert.NotContains(t, claimsOf(t, response.IdToken), "picture")
}

// A session that is gone is refused with the sentinel /auth/issue answers with the level 1 restart,
// and nothing is signed: no row to take is the whole of the refusal, whatever the engine.
func TestIssueImplicit_ASessionThatIsGoneIsRefused(t *testing.T) {
	db := database
	withRealSigningKeyOn(t, db)
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)
	session := createTestUserSessionOn(t, db, user.Id)
	require.NoError(t, db.DeleteUserSession(context.Background(), nil, session.Id))

	response, err := implicitIssuerOn(db).IssueImplicitTx(context.Background(), implicitSettings(),
		implicitInput(client, user, session.SessionIdentifier), true, true)

	require.ErrorIs(t, err, issuance.ErrIssuingSessionGone)
	assert.Nil(t, response)
}

// An empty identifier is not a session that is gone: AcquireUserSessionRow refuses it as a caller's
// bug, so it surfaces as an error the handler answers with a 500, and never as the sentinel that
// restarts the ceremony. The ceremony the exemption used to serve, an implicit one with no session
// identifier, is refused as the gone shape by /auth/issue's decision before the issuer is reached
// (decision 16); this pins that the issuer does not paper over the same input a second time.
func TestIssueImplicit_NoSessionIdentifierIsACallerError(t *testing.T) {
	db := database
	withRealSigningKeyOn(t, db)
	client := createTestClientOn(t, db)
	user := createTestUserOn(t, db)

	response, err := implicitIssuerOn(db).IssueImplicitTx(context.Background(), implicitSettings(),
		implicitInput(client, user, ""), true, true)

	require.Error(t, err)
	require.NotErrorIs(t, err, issuance.ErrIssuingSessionGone)
	assert.Nil(t, response)
}

// TestImplicitIssuanceOrdering_AgainstTermination is #139's measurement for the flow that mints no
// code, on a real catalog and every engine: the signing and the termination of its session
// genuinely overlapping. Both parties write the one user_sessions row before touching anything
// else, the termination by deleting it and the ceremony by AcquireUserSessionRow, so one of them
// waits for the other and reads its answer AFTER the wait. That leaves exactly two outcomes, one per
// subtest:
//
//   - the termination waits, and the tokens were signed while the session was alive;
//   - the ceremony waits, and its acquisition then matches no rows, so it refuses and signs nothing.
//
// Before #197 the implicit flow read the session once, statements ahead of the signing, so a
// termination that committed in the gap was invisible to it and tokens were signed for a session
// that had ended.
func TestImplicitIssuanceOrdering_AgainstTermination(t *testing.T) {
	runImplicitOrderingAgainstTermination(t, database, secondDatabase(t))
}

// TestImplicitIssuanceOrdering_AgainstTermination_RCSI is the same pair against a SQL Server
// database with READ_COMMITTED_SNAPSHOT on, the configuration a pair measured clean with it off has
// not been measured in (#139 stage 8): removing a lock conflict changes which interleavings are
// reachable. It skips on the other three engines.
func TestImplicitIssuanceOrdering_AgainstTermination_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runImplicitOrderingAgainstTermination(t, f.primary, f.secondary)
}

// runImplicitOrderingAgainstTermination is the pair, over two handles it is given rather than the
// package's. Both handles must point at the SAME database and be two distinct pools.
func runImplicitOrderingAgainstTermination(t *testing.T, db data.Database, other data.Database) {
	t.Run("issuance goes first and the termination waits", func(t *testing.T) {
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		tx, err := db.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(context.Background(), tx) }()

		// The acquisition and the signing, on the transaction the ceremony holds and has not yet
		// committed. Without the acquisition ahead of the signing the termination below would not
		// wait, and would end the session between the read that let the ceremony through and the
		// tokens leaving.
		response, err := implicitIssuerOn(db).IssueImplicit(context.Background(), tx, implicitSettings(),
			implicitInput(client, user, session.SessionIdentifier), true, true)
		require.NoError(t, err, "the ceremony takes the session row and signs on its transaction")
		require.NotNil(t, response)

		termination := goBlocked(t, "the termination", tx, func(reached func()) error {
			reached()
			_, terminateErr := revocation.TerminateUserSessionTx(context.Background(), other, session)
			return terminateErr
		})

		termination.requireBlocked(t)
		termination.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(context.Background(), tx), "committing the ceremony")

		require.NoError(t, termination.await(t),
			"the termination must wait for the ceremony and then commit, not deadlock with it or be refused")

		// The tokens were signed while the session was alive, name it, and the termination then
		// ended it.
		assert.Equal(t, session.SessionIdentifier, claimsOf(t, response.AccessToken)["sid"])
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})

	t.Run("the termination goes first and issuance waits", func(t *testing.T) {
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		session := createTestUserSessionOn(t, db, user.Id)

		// revocation.TerminateUserSessionTx owns and commits its own transaction, so an ordering
		// that needs the termination HELD OPEN across the ceremony's arrival replays its statements
		// by hand; the other subtest drives the real function.
		tx, err := db.BeginTransaction(context.Background())
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = db.RollbackTransaction(context.Background(), tx) }()

		require.NoError(t, terminationStatements(db, tx, session),
			"the termination's statements on a session nothing else has touched yet")

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) implicitOutcome {
			otherTx, beginErr := other.BeginTransaction(context.Background())
			if beginErr != nil {
				reached()
				return implicitOutcome{err: beginErr}
			}
			defer func() { _ = other.RollbackTransaction(context.Background(), otherTx) }()

			reached()
			response, issueErr := implicitIssuerOn(other).IssueImplicit(context.Background(), otherTx, implicitSettings(),
				implicitInput(client, user, session.SessionIdentifier), true, true)
			if issueErr != nil {
				// Production commits only what it signed; a refusal rolls back.
				return implicitOutcome{response: response, err: issueErr}
			}
			return implicitOutcome{response: response, err: other.CommitTransaction(context.Background(), otherTx)}
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(context.Background(), tx), "committing the termination")

		outcome := ceremony.await(t)

		// The whole value of the ceremony waiting: its acquisition reads its answer AFTER the wait,
		// so it sees the row the termination removed and refuses. A deadlock or any other failure is
		// a different error and fails here too.
		require.ErrorIs(t, outcome.err, issuance.ErrIssuingSessionGone,
			"the ceremony must wait for the termination and then refuse, not deadlock with it or sign")
		assert.Nil(t, outcome.response, "a ceremony whose session is gone signs nothing")
		assertSessionGoneOn(t, db, session.Id, "the terminated session")
	})
}
