package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A rename of a client revokes its grants in the rename's transaction (#710 decision 5). A password
// grant has no code for that sweep to mark and, until its first refresh token is written, no family
// to record, so the initial password grant is ordered against the rename through the client's row:
// it writes its first refresh token in a transaction that takes that row with a locking read and
// reads the identifier again. Either it commits before the rename, whose sweep then revokes its
// token, or it runs after and finds the identifier is no longer the one the request named, and
// issues nothing. Never a live grant under the earlier identifier. This file shows both orders on a
// real engine, with the statements that ship: issuance.TokenIssuer.IssuePasswordGrant and
// revocation.RevokeClientGrantsTx around SetClientIdentifier, as the settings save runs them.

// TestGetClientByIDForUpdate: the read answers the client GetClientByID answers, nothing for a
// client that is not there, and requires a transaction, without which the row would be released
// before the caller decides.
func TestGetClientByIDForUpdate(t *testing.T) {
	ctx := context.Background()
	client := createIdentifierTestClient(t)
	plain, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)

	tx := beginTx(t)
	locked, err := database.GetClientByIDForUpdate(ctx, tx, client.ID)
	require.NoError(t, err)
	assert.Equal(t, plain, locked, "the same client GetClientByID reads")
	missing, err := database.GetClientByIDForUpdate(ctx, tx, client.ID+1_000_000)
	require.NoError(t, err)
	assert.Nil(t, missing)
	require.NoError(t, database.RollbackTransaction(ctx, tx))

	_, err = database.GetClientByIDForUpdate(ctx, nil, client.ID)
	require.Error(t, err)

	after, err := database.GetClientByID(ctx, nil, client.ID)
	require.NoError(t, err)
	assert.Equal(t, plain.UpdatedAt, after.UpdatedAt, "the read writes nothing, updated_at included")
}

// passwordGrantIssuerOn is the issuer the token endpoint answers a password grant with, over the
// handle it is given.
func passwordGrantIssuerOn(db data.Database) *issuance.TokenIssuer {
	return issuance.NewTokenIssuer(db, implicitTestBaseURL, "http://localhost:9091", dataCipher, noBumps{})
}

// passwordGrantInput is a password grant for this client, as the token endpoint loaded it, and user.
func passwordGrantInput(client *record.Client, user *record.User) *issuance.ROPCGrantInput {
	loaded := *client
	return &issuance.ROPCGrantInput{Client: &loaded, User: user, Scope: "openid offline_access"}
}

// renameRevoking runs the settings save's rename and the revocation it decides, in one transaction
// the helper opens and commits.
func renameRevoking(ctx context.Context, db data.Database, clientID int64, identifier string) (revocation.ClientGrantResult, error) {
	return revocation.RevokeClientGrantsTx(ctx, db, clientID, revocation.ReasonClientIdentifierChanged,
		func(tx *sql.Tx) (bool, error) { return db.SetClientIdentifier(ctx, tx, clientID, identifier) })
}

// refreshTokensOfClientOn answers every refresh token row the client holds.
func refreshTokensOfClientOn(t *testing.T, db data.Database, clientID int64) []*record.RefreshToken {
	t.Helper()
	tokens, err := db.GetRefreshTokensByClientID(context.Background(), nil, clientID)
	require.NoError(t, err)
	return tokens
}

// The sequential half, on every engine: a grant whose client is still called what the request
// named is issued, and its first refresh token row is the client's.
func TestPasswordGrant_IssuedWhileTheClientKeepsItsIdentifier(t *testing.T) {
	ctx := context.Background()
	withRealSigningKeyOn(t, database)
	client := createIdentifierTestClient(t)
	user := createTestUserOn(t, database)

	response, err := passwordGrantIssuerOn(database).IssuePasswordGrant(ctx, rotationSettings(), passwordGrantInput(client, user))

	require.NoError(t, err)
	require.NotNil(t, response)
	tokens := refreshTokensOfClientOn(t, database, client.ID)
	require.Len(t, tokens, 1)
	assert.Equal(t, claimsOf(t, response.RefreshToken)["jti"], tokens[0].RefreshTokenJTI)
	assert.False(t, tokens[0].Revoked)
}

// The sequential half of the rename: a grant whose request named the identifier a rename committed
// since gave up is refused and writes nothing, on every engine.
func TestPasswordGrant_RefusedAfterARenameCommittedSinceTheRequestNamedTheClient(t *testing.T) {
	ctx := context.Background()
	withRealSigningKeyOn(t, database)
	client := createIdentifierTestClient(t)
	user := createTestUserOn(t, database)
	input := passwordGrantInput(client, user)

	_, err := renameRevoking(ctx, database, client.ID, "renamed_"+fake.LetterN(8))
	require.NoError(t, err)

	response, err := passwordGrantIssuerOn(database).IssuePasswordGrant(ctx, rotationSettings(), input)

	require.ErrorIs(t, err, issuance.ErrPasswordGrantClientRenamed)
	assert.Nil(t, response)
	assert.Empty(t, refreshTokensOfClientOn(t, database, client.ID), "no refresh token is written")
}

// TestPasswordGrantOrdering_AgainstRename is the race on a real engine, both ways round.
func TestPasswordGrantOrdering_AgainstRename(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	runPasswordGrantOrderingAgainstRename(t, database, secondDatabase(t))
}

// TestPasswordGrantOrdering_AgainstRename_RCSI is the same pair on a SQL Server database with
// READ_COMMITTED_SNAPSHOT on, where removing a lock conflict could change which interleavings are
// reachable. It skips on the other three engines.
func TestPasswordGrantOrdering_AgainstRename_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runPasswordGrantOrderingAgainstRename(t, f.primary, f.secondary)
}

// runPasswordGrantOrderingAgainstRename is the pair, over two handles to the SAME database, two
// distinct pools.
func runPasswordGrantOrderingAgainstRename(t *testing.T, db data.Database, other data.Database) {
	t.Run("the grant goes first and the rename waits", func(t *testing.T) {
		ctx := context.Background()
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)

		// The real grant, held at its refresh token's insert: it has read the client's row with its
		// lock and not yet written or committed.
		pause := newPausingInserts(t, db)
		type grantOutcome struct {
			response *oauth.TokenResponse
			err      error
		}
		granted := make(chan grantOutcome, 1)
		go func() {
			response, err := passwordGrantIssuerOn(pause).IssuePasswordGrant(ctx, rotationSettings(), passwordGrantInput(client, user))
			granted <- grantOutcome{response, err}
		}()
		var grantTx *sql.Tx
		select {
		case grantTx = <-pause.paused:
		case o := <-granted:
			t.Fatalf("the grant finished before it wrote its refresh token: %v", o.err)
		}
		require.NotNil(t, grantTx, "the grant writes its first refresh token in a transaction")

		type renameOutcome struct {
			result revocation.ClientGrantResult
			err    error
		}
		rename := goBlocked(t, "the rename", grantTx, func(reached func()) renameOutcome {
			reached()
			result, err := renameRevoking(ctx, other, client.ID, "renamed_"+fake.LetterN(8))
			return renameOutcome{result, err}
		})

		rename.requireBlocked(t)
		rename.requireStillWaiting(t)
		pause.proceed()

		grant := <-granted
		require.NoError(t, grant.err, "the grant held the client's row first, and commits")
		require.NotNil(t, grant.response)
		jti := claimsOf(t, grant.response.RefreshToken)["jti"].(string)

		renamed := rename.await(t)
		require.NoError(t, renamed.err, "the rename waits for the grant and then commits")
		assert.Equal(t, []string{jti}, renamed.result.RevokedRefreshTokenJTIs,
			"the rename's sweep ran after the grant committed, so it found the grant's refresh token")

		row, err := db.GetRefreshTokenByJTI(ctx, nil, jti)
		require.NoError(t, err)
		require.NotNil(t, row)
		assert.True(t, row.Revoked, "the grant's refresh token is revoked")
		recorded, err := db.IsRefreshTokenFamilyRevoked(ctx, nil, jti)
		require.NoError(t, err)
		assert.True(t, recorded, "and its family recorded as revoked")
	})

	t.Run("the rename goes first and the grant waits", func(t *testing.T) {
		ctx := context.Background()
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		input := passwordGrantInput(client, user)

		// RevokeClientGrantsTx owns and commits its own transaction, so the rename HELD OPEN across
		// the grant's arrival runs its statements by hand; the other order drives the real function.
		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err)
		defer func() { _ = db.RollbackTransaction(ctx, tx) }()
		changed, err := db.SetClientIdentifier(ctx, tx, client.ID, "renamed_"+fake.LetterN(8))
		require.NoError(t, err)
		require.True(t, changed)
		_, err = revocation.RevokeClientGrants(ctx, db, tx, client.ID, revocation.ReasonClientIdentifierChanged)
		require.NoError(t, err)

		type grantOutcome struct {
			response *oauth.TokenResponse
			err      error
		}
		grant := goBlocked(t, "the grant", tx, func(reached func()) grantOutcome {
			reached()
			response, err := passwordGrantIssuerOn(other).IssuePasswordGrant(ctx, rotationSettings(), input)
			return grantOutcome{response, err}
		})

		grant.requireBlocked(t)
		grant.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(ctx, tx), "committing the rename")

		outcome := grant.await(t)
		require.ErrorIs(t, outcome.err, issuance.ErrPasswordGrantClientRenamed,
			"the grant waits for the rename, then reads the identifier it gave the client and refuses")
		assert.Nil(t, outcome.response)
		assert.Empty(t, refreshTokensOfClientOn(t, db, client.ID), "no refresh token is written")
	})
}

// TestDeleteClientOrdering_AgainstInitialPasswordGrant is a client's deletion meeting the initial
// password grant on the client's row, both ways round. The grant writes its first refresh token
// under a locking read of that row, and refresh_tokens.client_id is NO ACTION, so a deletion that
// swept the client's refresh tokens only before it took the row would meet a token the grant
// committed while it waited, and fail on the key with the client left in place. Either way round,
// the deletion succeeds, the client is gone, and no refresh token of it is left.
func TestDeleteClientOrdering_AgainstInitialPasswordGrant(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	runDeleteClientOrderingAgainstPasswordGrant(t, database, secondDatabase(t))
}

// TestDeleteClientOrdering_AgainstInitialPasswordGrant_RCSI is the same pair on a SQL Server
// database with READ_COMMITTED_SNAPSHOT on. It skips on the other three engines.
func TestDeleteClientOrdering_AgainstInitialPasswordGrant_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runDeleteClientOrderingAgainstPasswordGrant(t, f.primary, f.secondary)
}

func runDeleteClientOrderingAgainstPasswordGrant(t *testing.T, db data.Database, other data.Database) {
	type grantOutcome struct {
		response *oauth.TokenResponse
		err      error
	}

	t.Run("the grant goes first and the deletion waits", func(t *testing.T) {
		ctx := context.Background()
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)

		// The real grant, held at its refresh token's insert: it has read the client's row with its
		// lock and not yet written or committed.
		pause := newPausingInserts(t, db)
		granted := make(chan grantOutcome, 1)
		go func() {
			response, err := passwordGrantIssuerOn(pause).IssuePasswordGrant(ctx, rotationSettings(), passwordGrantInput(client, user))
			granted <- grantOutcome{response, err}
		}()
		var grantTx *sql.Tx
		select {
		case grantTx = <-pause.paused:
		case o := <-granted:
			t.Fatalf("the grant finished before it wrote its refresh token: %v", o.err)
		}
		require.NotNil(t, grantTx, "the grant writes its first refresh token in a transaction")

		deletion := goBlocked(t, "the deletion", grantTx, func(reached func()) error {
			reached()
			return other.DeleteClient(ctx, nil, client.ID)
		})

		deletion.requireBlocked(t)
		deletion.requireStillWaiting(t)
		pause.proceed()

		grant := <-granted
		require.NoError(t, deletion.await(t),
			"the deletion waits for the grant, and then deletes the client and the token the grant committed")

		// The grant held the row first and commits, unless the engine answered the two with a
		// deadlock and reran the grant, which then waits for the deletion and finds no client.
		if grant.err == nil {
			require.NotNil(t, grant.response)
			jti := claimsOf(t, grant.response.RefreshToken)["jti"].(string)
			row, err := db.GetRefreshTokenByJTI(ctx, nil, jti)
			require.NoError(t, err)
			assert.Nil(t, row, "the grant's refresh token went with its client")
		} else {
			require.ErrorIs(t, grant.err, issuance.ErrPasswordGrantClientRenamed)
		}

		gone, err := db.GetClientByID(ctx, nil, client.ID)
		require.NoError(t, err)
		assert.Nil(t, gone, "the client is deleted")
		assert.Empty(t, refreshTokensOfClientOn(t, db, client.ID), "no refresh token of the client is left")
	})

	t.Run("the deletion goes first and the grant waits", func(t *testing.T) {
		ctx := context.Background()
		withRealSigningKeyOn(t, db)
		client := createTestClientOn(t, db)
		user := createTestUserOn(t, db)
		input := passwordGrantInput(client, user)

		tx, err := db.BeginTransaction(ctx)
		require.NoError(t, err)
		defer func() { _ = db.RollbackTransaction(ctx, tx) }()
		require.NoError(t, db.DeleteClient(ctx, tx, client.ID))

		grant := goBlocked(t, "the grant", tx, func(reached func()) grantOutcome {
			reached()
			response, grantErr := passwordGrantIssuerOn(other).IssuePasswordGrant(ctx, rotationSettings(), input)
			return grantOutcome{response, grantErr}
		})

		grant.requireBlocked(t)
		grant.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(ctx, tx), "committing the deletion")

		outcome := grant.await(t)
		require.ErrorIs(t, outcome.err, issuance.ErrPasswordGrantClientRenamed,
			"the grant waits for the deletion, then finds no client and refuses")
		assert.Nil(t, outcome.response)

		gone, err := db.GetClientByID(ctx, nil, client.ID)
		require.NoError(t, err)
		assert.Nil(t, gone, "the client is deleted")
		assert.Empty(t, refreshTokensOfClientOn(t, db, client.ID), "no refresh token is written")
	})
}
