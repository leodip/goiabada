package datatests

import (
	"context"
	"database/sql"
	"sort"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A hinted sign-out revokes the departing client's session-bound grants from the session it
// signs out of (#135 decision 9): the session-bound refresh tokens that client holds from that
// session, and that client's codes from it not yet redeemed. The two reads below are that sweep's,
// held on every engine against the grants it must leave alone: the client's offline token from
// the same session, another client's tokens and codes on the session, the client's grants from
// another session, and a password grant with the client, which belongs to no session.

// signOutGrants is one user's grants around one session sid that two clients share.
type signOutGrants struct {
	user          *record.User
	client, other *record.Client
	sid           string

	// The client's session-bound tokens from sid: one live, one revoked by an earlier rotation.
	live, rotated *record.RefreshToken
	// What the sweep must not reach.
	offline, otherClients, otherSession, passwordGrant *record.RefreshToken
}

// signOutCode creates a used code of clientID and the user on sid, the code a session-bound or
// offline token descends from.
func signOutCode(t *testing.T, clientID, userID int64, sid string) *record.Code {
	t.Helper()
	code := newWithdrawalCode(t, clientID, userID)
	code.SessionIdentifier = sid
	require.NoError(t, database.UpdateCode(context.Background(), nil, code))
	return code
}

// sessionBound creates a session-bound refresh token from code, its session_identifier the
// code's, as issuance writes one.
func sessionBound(t *testing.T, code *record.Code, revoked bool) *record.RefreshToken {
	t.Helper()
	return newWithdrawalToken(t, &record.RefreshToken{
		CodeID:               sql.NullInt64{Int64: code.ID, Valid: true},
		SessionIdentifier:    code.SessionIdentifier,
		RefreshTokenType:     "Refresh",
		FirstRefreshTokenJTI: "family_" + fake.UUID(),
		Revoked:              revoked,
	})
}

// newSignOutGrants creates the grants of user with client and other around sid.
func newSignOutGrants(t *testing.T, user *record.User, client, other *record.Client, sid string) signOutGrants {
	t.Helper()
	g := signOutGrants{user: user, client: client, other: other, sid: sid}

	g.live = sessionBound(t, signOutCode(t, g.client.ID, g.user.ID, g.sid), false)
	g.rotated = sessionBound(t, signOutCode(t, g.client.ID, g.user.ID, g.sid), true)

	// An offline token's own session_identifier is empty; its code names the session.
	g.offline = newWithdrawalToken(t, &record.RefreshToken{
		CodeID:               sql.NullInt64{Int64: signOutCode(t, g.client.ID, g.user.ID, g.sid).ID, Valid: true},
		RefreshTokenType:     "Offline",
		FirstRefreshTokenJTI: "family_" + fake.UUID(),
	})
	g.otherClients = sessionBound(t, signOutCode(t, g.other.ID, g.user.ID, g.sid), false)
	g.otherSession = sessionBound(t, signOutCode(t, g.client.ID, g.user.ID, "sess_"+fake.UUID()), false)
	g.passwordGrant = newWithdrawalToken(t, &record.RefreshToken{
		UserID:               sql.NullInt64{Int64: g.user.ID, Valid: true},
		ClientID:             sql.NullInt64{Int64: g.client.ID, Valid: true},
		RefreshTokenType:     "Offline",
		FirstRefreshTokenJTI: "family_" + fake.UUID(),
	})
	return g
}

func sortedJTIs(jtis ...string) []string {
	sort.Strings(jtis)
	return jtis
}

func assertRefreshTokenRevoked(t *testing.T, rt *record.RefreshToken, want bool, what string) {
	t.Helper()
	reloaded, err := database.GetRefreshTokenByID(context.Background(), nil, rt.ID)
	require.NoError(t, err)
	require.NotNil(t, reloaded, "%s is still stored", what)
	assert.Equal(t, want, reloaded.Revoked, "%s revoked", what)
}

// TestGetSessionBoundRefreshTokensBySessionIdentifierAndClientID: the client's session-bound tokens
// from the session, revoked ones included so the sweep records their families, and nothing else.
func TestGetSessionBoundRefreshTokensBySessionIdentifierAndClientID(t *testing.T) {
	ctx := context.Background()
	g := newSignOutGrants(t, createTestUser(t), createTestClient(t), createTestClient(t), "sess_"+fake.UUID())

	got, err := database.GetSessionBoundRefreshTokensBySessionIdentifierAndClientID(ctx, nil, g.sid, g.client.ID)
	require.NoError(t, err)
	assert.Equal(t, sortedJTIs(g.live.RefreshTokenJTI, g.rotated.RefreshTokenJTI), jtisOf(got),
		"the client's live and revoked session-bound tokens from the session, and not its offline token "+
			"from it, the other client's, its own from another session or its password grant")

	got, err = database.GetSessionBoundRefreshTokensBySessionIdentifierAndClientID(ctx, nil, g.sid, g.other.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{g.otherClients.RefreshTokenJTI}, jtisOf(got), "the other client's, on its own")

	// An empty session identifier or a zero client id names no grant, rather than matching every
	// token with an empty session or none.
	got, err = database.GetSessionBoundRefreshTokensBySessionIdentifierAndClientID(ctx, nil, "", g.client.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
	got, err = database.GetSessionBoundRefreshTokensBySessionIdentifierAndClientID(ctx, nil, g.sid, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestRevokeUnusedCodesBySessionIdentifierAndClientID: the client's codes from the session not yet
// redeemed are marked, and nothing else; the count is what the call transitioned.
func TestRevokeUnusedCodesBySessionIdentifierAndClientID(t *testing.T) {
	ctx := context.Background()
	user, client, other := createTestUser(t), createTestClient(t), createTestClient(t)
	sid := "sess_" + fake.UUID()

	first := createTestCodeInSession(t, client.ID, user.ID, sid)
	second := createTestCodeInSession(t, client.ID, user.ID, sid)
	used := createTestCodeInSession(t, client.ID, user.ID, sid)
	claimed, err := database.MarkCodeAsUsed(ctx, nil, used.ID)
	require.NoError(t, err)
	require.True(t, claimed)
	otherClients := createTestCodeInSession(t, other.ID, user.ID, sid)
	otherSession := createTestCodeInSession(t, client.ID, user.ID, "sess_"+fake.UUID())

	count, err := database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, nil, sid, client.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
	assertCodeRevoked(t, first.ID, true, "an unused code of the client from the session")
	assertCodeRevoked(t, second.ID, true, "a second unused code of the client from the session")
	// A used code's grant is its refresh tokens, which the sweep revokes itself; marked, it would also
	// refuse an offline token descended from it.
	assertCodeRevoked(t, used.ID, false, "a used code of the client from the session")
	assertCodeRevoked(t, otherClients.ID, false, "another client's code from the session")
	assertCodeRevoked(t, otherSession.ID, false, "the client's code from another session")

	count, err = database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, nil, sid, client.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "a second call transitions nothing")

	_, err = database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, nil, "", client.ID)
	require.Error(t, err, "an empty session identifier is refused, not used as a filter")
	_, err = database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, nil, sid, 0)
	require.Error(t, err, "a zero client id is refused, not used as a filter")
	assertCodeRevoked(t, otherClients.ID, false, "another client's code after the refused calls")
}

// TestRevokeUnusedCodesBySessionIdentifierAndClientID_TransactionAndFailurePath holds the mark to the
// sign-out's transaction, so a sign-out that rolls back leaves the code redeemable, and its failure
// to an error rather than a benign zero.
func TestRevokeUnusedCodesBySessionIdentifierAndClientID_TransactionAndFailurePath(t *testing.T) {
	ctx := context.Background()
	user, client := createTestUser(t), createTestClient(t)
	sid := "sess_" + fake.UUID()
	code := createTestCodeInSession(t, client.ID, user.ID, sid)

	tx := beginTx(t)
	count, err := database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, tx, sid, client.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
	require.NoError(t, database.RollbackTransaction(ctx, tx))
	assertCodeRevoked(t, code.ID, false, "a code revoked inside a rolled-back transaction")

	count, err = database.RevokeUnusedCodesBySessionIdentifierAndClientID(ctx, tx, sid, client.ID)
	require.Error(t, err, "a statement that cannot run returns an error")
	assert.Equal(t, int64(0), count)
}

// TestEndClientPartTx_RevokesTheDepartingClientsSessionBoundGrants: the hinted sign-out's end, on a
// session two clients share, revokes the departing client's session-bound token and its unredeemed
// code from the session, records their families with the reason client_signed_out, and reports what
// it transitioned; its offline token, the other client's grants and its own from another session
// stay as they were, and so does the session, which the other client keeps.
func TestEndClientPartTx_RevokesTheDepartingClientsSessionBoundGrants(t *testing.T) {
	ctx := context.Background()
	user, client, other := createTestUser(t), createTestClient(t), createTestClient(t)
	// The staying client joins the session first, so the departing client's row on it has an id of
	// its own: in a fresh database the client created first and the row created first would both be 1,
	// and a sweep keyed on the row's id would look keyed on the client's.
	session := createTestUserSessionWithClient(t, user.ID, other.ID)
	require.NoError(t, database.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{
		UserSessionID: session.ID, ClientID: client.ID,
		Started: session.Started, LastAccessed: session.LastAccessed,
	}))
	g := newSignOutGrants(t, user, client, other, session.SessionIdentifier)
	unredeemed := createTestCodeInSession(t, g.client.ID, g.user.ID, session.SessionIdentifier)
	othersUnredeemed := createTestCodeInSession(t, g.other.ID, g.user.ID, session.SessionIdentifier)

	end, err := revocation.EndClientPartTx(ctx, database, session.SessionIdentifier, g.client.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, end.Ended, "the client's part ended")
	assert.False(t, end.SessionDeleted, "the other client keeps the session")
	assert.Equal(t, []string{g.live.RefreshTokenJTI}, end.RevokedRefreshTokenJTIs,
		"the one token this call moved from live to revoked")
	assert.Equal(t, int64(1), end.RevokedCodeCount, "the client's one unredeemed code from the session")

	assertRefreshTokenRevoked(t, g.live, true, "the client's session-bound token from the session")
	assertCodeRevoked(t, unredeemed.ID, true, "the client's unredeemed code from the session")
	for _, family := range []string{g.live.FirstRefreshTokenJTI, g.rotated.FirstRefreshTokenJTI} {
		reason, _, found := familyRevocationRow(t, family)
		assert.True(t, found, "the family of each session-bound token the sweep read is recorded")
		assert.Equal(t, "client_signed_out", reason)
	}

	for _, kept := range []struct {
		rt   *record.RefreshToken
		what string
	}{
		{g.offline, "the client's offline token from the session"},
		{g.otherClients, "the other client's session-bound token"},
		{g.otherSession, "the client's session-bound token from another session"},
		{g.passwordGrant, "the client's password grant"},
	} {
		assertRefreshTokenRevoked(t, kept.rt, false, kept.what)
		_, _, found := familyRevocationRow(t, kept.rt.FirstRefreshTokenJTI)
		assert.False(t, found, "%s: no family record", kept.what)
	}
	assertCodeRevoked(t, othersUnredeemed.ID, false, "the other client's unredeemed code")

	kept, err := database.GetUserSessionBySessionIdentifier(ctx, nil, session.SessionIdentifier)
	require.NoError(t, err)
	assert.NotNil(t, kept, "the session stays")
}

// TestEndClientPartTx_TheSessionsLastClientRevokesAsWell: whether other clients share the session no
// longer decides anything. A lone client's sign-out deletes the session and revokes the same grants.
func TestEndClientPartTx_TheSessionsLastClientRevokesAsWell(t *testing.T) {
	ctx := context.Background()
	user, client := createTestUser(t), createTestClient(t)
	session := createTestUserSessionWithClient(t, user.ID, client.ID)
	bound := sessionBound(t, signOutCode(t, client.ID, user.ID, session.SessionIdentifier), false)

	end, err := revocation.EndClientPartTx(ctx, database, session.SessionIdentifier, client.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, end.Ended)
	assert.True(t, end.SessionDeleted, "the client was the session's last")
	assert.Equal(t, []string{bound.RefreshTokenJTI}, end.RevokedRefreshTokenJTIs)
	assertRefreshTokenRevoked(t, bound, true, "the lone client's session-bound token")

	again, err := revocation.EndClientPartTx(ctx, database, session.SessionIdentifier, client.ClientIdentifier)
	require.NoError(t, err)
	assert.Nil(t, again.Ended, "a session already gone has no part to end")
	assert.Empty(t, again.RevokedRefreshTokenJTIs)
}
