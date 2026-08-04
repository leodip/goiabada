package handlers

import (
	"database/sql"
	"errors"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// revokeTx is an opaque non-nil transaction. RevokeUserAuthState requires one, so passing nil
// here would exercise a shape production never runs. The mocks never dereference it; it only
// has to be the same pointer the helper forwards.
var revokeTx = &sql.Tx{}

// The user under revocation, and the two sessions the fixture below spreads tokens across.
const (
	revokeUserId   = int64(7)
	revokeKeepSid  = "sid-keep"
	revokeOtherSid = "sid-other"
	// Nonzero on purpose. A fixture at 0 coincides with the column default, so an
	// implementation that never read the stored value would still pass.
	revokeOldGeneration = int64(3)
	revokeNewGeneration = int64(4)
)

// revocationFixture builds the five refresh tokens the sweep table reasons about. It is one
// fixture shared by both cases (exceptSid set and empty) so the two are directly comparable:
// the only thing that varies between them is exceptSid.
//
// The five shapes are chosen to cover both linkage forms and both the preserved and swept
// sides of each:
//
//	1 rt-keep-session   auth-code, session-bound, on the PRESERVED session
//	2 rt-keep-offline   auth-code, OFFLINE, on the preserved session, own sid empty
//	3 rt-other-session  auth-code, session-bound, on another session
//	4 rt-already-gone   auth-code, on another session, ALREADY revoked
//	5 rt-ropc           ROPC, no code at all
//
// Token 2 is the load-bearing one. Its own session_identifier is empty, because an offline
// grant is not session-bound, and the sid it came from lives only on the joined codes row.
// So it is indistinguishable from the ROPC token by inspecting the user-scoped rows alone,
// and any implementation that derives the preserved set from those rows revokes it. That
// contradicts decision 4: the user changes their own password and their own session's
// offline tokens die.
func revocationFixture() []*models.RefreshToken {
	return []*models.RefreshToken{
		{
			Id: 1, RefreshTokenJti: "rt-keep-session",
			SessionIdentifier:   revokeKeepSid,
			RefreshTokenType:    "Refresh",
			CodeId:              sql.NullInt64{Int64: 11, Valid: true},
			AuthStateGeneration: revokeOldGeneration,
		},
		{
			Id: 2, RefreshTokenJti: "rt-keep-offline",
			SessionIdentifier:   "",
			RefreshTokenType:    "Offline",
			CodeId:              sql.NullInt64{Int64: 12, Valid: true},
			AuthStateGeneration: revokeOldGeneration,
		},
		{
			Id: 3, RefreshTokenJti: "rt-other-session",
			SessionIdentifier:   revokeOtherSid,
			RefreshTokenType:    "Refresh",
			CodeId:              sql.NullInt64{Int64: 13, Valid: true},
			AuthStateGeneration: revokeOldGeneration,
		},
		{
			Id: 4, RefreshTokenJti: "rt-already-gone",
			SessionIdentifier:   revokeOtherSid,
			RefreshTokenType:    "Refresh",
			CodeId:              sql.NullInt64{Int64: 14, Valid: true},
			Revoked:             true,
			AuthStateGeneration: revokeOldGeneration,
		},
		{
			Id: 5, RefreshTokenJti: "rt-ropc",
			SessionIdentifier:   "",
			RefreshTokenType:    "Offline",
			CodeId:              sql.NullInt64{Valid: false},
			UserId:              sql.NullInt64{Int64: revokeUserId, Valid: true},
			AuthStateGeneration: revokeOldGeneration,
		},
	}
}

func revocationSessions() []models.UserSession {
	return []models.UserSession{
		{Id: 100, SessionIdentifier: revokeKeepSid, UserId: revokeUserId,
			AuthStateGeneration: revokeOldGeneration},
		{Id: 200, SessionIdentifier: revokeOtherSid, UserId: revokeUserId,
			AuthStateGeneration: revokeOldGeneration},
	}
}

// TestRevokeUserAuthState_PreservingASession is the exhaustive owner of the sweep table for
// the exceptSid case (#106 stage 4). Every expectation is registered on a strict mock, so an
// unexpected or missing database call fails the test on its own.
func TestRevokeUserAuthState_PreservingASession(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	tokens := revocationFixture()

	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
		Return(revokeNewGeneration, nil).Once()

	// The sid-scoped query, which is the ONLY thing that can identify token 2 as belonging
	// to the preserved session. It matches codes.session_identifier, so it returns both the
	// session-bound and the offline token of that session.
	db.On("GetRefreshTokensBySessionIdentifier", revokeTx, revokeKeepSid).
		Return([]*models.RefreshToken{tokens[0], tokens[1]}, nil).Once()

	db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
		Return(tokens, nil).Once()

	// Exactly the three tokens outside the preserved set are written, and the
	// already-revoked one is not among them.
	db.On("UpdateRefreshToken", revokeTx, tokens[2]).Return(nil).Once()
	db.On("UpdateRefreshToken", revokeTx, tokens[4]).Return(nil).Once()

	db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{1, 2}, revokeNewGeneration).
		Return(nil).Once()

	db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).
		Return(revocationSessions(), nil).Once()
	db.On("PromoteUserSessionGeneration", revokeTx, int64(100), revokeNewGeneration).
		Return(nil).Once()
	db.On("DeleteUserSession", revokeTx, int64(200)).Return(nil).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, revokeKeepSid)
	require.NoError(t, err)

	// Both tokens of the preserved session are promoted, the offline one included. This is
	// the assertion that fails against an implementation deriving the preserved set from the
	// user-scoped rows: token 2 would land in the revoked list instead.
	assert.Equal(t, []int64{1, 2}, promotedIds(t, db),
		"the preserved session's session-bound AND offline tokens must be promoted")

	// Two revoked, not three: rt-already-gone was revoked before the call and so is neither
	// written again nor reported. Callers use "we revoked something" as a signal (#77).
	assert.Equal(t, []string{"rt-other-session", "rt-ropc"}, result.RevokedRefreshTokenJtis)
	assert.NotContains(t, result.RevokedRefreshTokenJtis, "rt-already-gone")

	assert.Equal(t, []string{revokeOtherSid}, result.TerminatedSessionIdentifiers)
	assert.Equal(t, revokeKeepSid, result.PreservedSessionIdentifier)
	assert.Equal(t, revokeOldGeneration, result.OldGeneration)
	assert.Equal(t, revokeNewGeneration, result.NewGeneration)

	// The tokens the sweep touched carry Revoked, and the preserved ones do not.
	assert.False(t, tokens[0].Revoked, "rt-keep-session must survive")
	assert.False(t, tokens[1].Revoked, "rt-keep-offline must survive")
	assert.True(t, tokens[2].Revoked)
	assert.True(t, tokens[4].Revoked)
}

// TestRevokeUserAuthState_RevokingEverything is the same fixture with exceptSid empty.
// Exactly one input differs from the test above, so any difference in outcome is attributable
// to it.
func TestRevokeUserAuthState_RevokingEverything(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	tokens := revocationFixture()

	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
		Return(revokeNewGeneration, nil).Once()
	db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
		Return(tokens, nil).Once()

	db.On("UpdateRefreshToken", revokeTx, tokens[0]).Return(nil).Once()
	db.On("UpdateRefreshToken", revokeTx, tokens[1]).Return(nil).Once()
	db.On("UpdateRefreshToken", revokeTx, tokens[2]).Return(nil).Once()
	db.On("UpdateRefreshToken", revokeTx, tokens[4]).Return(nil).Once()

	db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, revokeNewGeneration).
		Return(nil).Once()

	db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).
		Return(revocationSessions(), nil).Once()
	db.On("DeleteUserSession", revokeTx, int64(100)).Return(nil).Once()
	db.On("DeleteUserSession", revokeTx, int64(200)).Return(nil).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, "")
	require.NoError(t, err)

	// FOUR entries, not five. Every live token transitions, and the already-revoked one is
	// still excluded from the report. An earlier draft of the plan said "all five revoked",
	// which contradicted its own executed sketch (finding 27); this count is the correction.
	assert.Len(t, result.RevokedRefreshTokenJtis, 4)
	assert.Equal(t, []string{"rt-keep-session", "rt-keep-offline", "rt-other-session", "rt-ropc"},
		result.RevokedRefreshTokenJtis)

	assert.ElementsMatch(t, []string{revokeKeepSid, revokeOtherSid}, result.TerminatedSessionIdentifiers)
	assert.Equal(t, "", result.PreservedSessionIdentifier)
	assert.Equal(t, revokeOldGeneration, result.OldGeneration)
	assert.Equal(t, revokeNewGeneration, result.NewGeneration)

	// Nothing promoted, and no sid-scoped query issued at all. The second is enforced by the
	// strict mock: no GetRefreshTokensBySessionIdentifier expectation is registered, so a
	// call would fail the test.
	assert.Empty(t, promotedIds(t, db))
	db.AssertNotCalled(t, "PromoteUserSessionGeneration", mock.Anything, mock.Anything, mock.Anything)
}

// promotedIds pulls the id list actually passed to PromoteRefreshTokenGenerations, rather than
// trusting the expectation to have matched a nil-versus-empty slice loosely.
func promotedIds(t *testing.T, db *mocks_data.Database) []int64 {
	t.Helper()
	for _, call := range db.Calls {
		if call.Method == "PromoteRefreshTokenGenerations" {
			ids, ok := call.Arguments[1].([]int64)
			require.True(t, ok, "second argument should be []int64")
			return ids
		}
	}
	t.Fatal("PromoteRefreshTokenGenerations was never called")
	return nil
}

// TestRevokeUserAuthState_RequiresATransaction pins the entry precondition. The helper spans
// an increment and a multi-table sweep, so without a transaction a failure part-way through
// leaves the user on a new generation with their old state half swept. Enforced here rather
// than left to whichever nested data method happens to check, so the contract is the
// function's own.
func TestRevokeUserAuthState_RequiresATransaction(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	result, err := RevokeUserAuthState(db, nil, revokeUserId, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a transaction")
	// Nothing was attempted. The strict mock has no expectations registered, so any call at
	// all would fail the test on its own.
	assert.Equal(t, RevocationResult{
		TerminatedSessionIdentifiers: []string{},
		RevokedRefreshTokenJtis:      []string{},
	}, result)
}

// TestRevokeUserAuthState_UnknownUser pins that an unknown user is an error rather than a
// silent no-op. There is no pre-read to catch it: IncrementUserAuthStateGeneration requires
// exactly one affected row and reports it, which is why the helper does not look the user up
// separately (finding 30).
func TestRevokeUserAuthState_UnknownUser(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	notFound := errors.New("user not found when incrementing auth state generation")
	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
		Return(int64(0), notFound).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, "")

	require.ErrorIs(t, err, notFound)
	assert.Empty(t, result.RevokedRefreshTokenJtis)
	// No sweep was attempted after the failed increment: revoking state while leaving the
	// generation behind would be the worst of both outcomes.
	db.AssertNotCalled(t, "GetRefreshTokensByUserId", mock.Anything, mock.Anything)
	assert.Equal(t, int64(0), result.OldGeneration)
	assert.Equal(t, int64(0), result.NewGeneration)
}

// TestRevokeUserAuthState_OldGenerationIsDerivedFromTheIncrement is the finding-30 regression.
// The helper used to SELECT the stored generation before incrementing, which is not a locking
// read: a concurrent revocation can commit between the read and the increment, and the caller
// then reports an old generation it never moved away from.
//
// The fixture makes that concrete. The increment returns 9, meaning another transaction had
// already advanced the user past whatever a prior read would have seen. OldGeneration must be
// 8, the value THIS increment moved away from, not the 3 a pre-read would have reported.
func TestRevokeUserAuthState_OldGenerationIsDerivedFromTheIncrement(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).Return(int64(9), nil).Once()
	db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
		Return([]*models.RefreshToken{}, nil).Once()
	db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, int64(9)).Return(nil).Once()
	db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).
		Return([]models.UserSession{}, nil).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, "")

	require.NoError(t, err)
	assert.Equal(t, int64(9), result.NewGeneration)
	assert.Equal(t, int64(8), result.OldGeneration)
	// The user is never read separately. A GetUserById call would fail on the strict mock,
	// which is what keeps the racy pre-read from coming back.
	db.AssertNotCalled(t, "GetUserById", mock.Anything, mock.Anything)
}

// TestRevokeUserAuthState_ChildCommittedBetweenTheDiscoveryQueries covers a refresh racing the
// sweep, in the one window the query ORDER can do anything about (finding 33).
//
// A refresh that validated before the sweep began commits its child token while the sweep is
// running. Where a database gives each statement a fresh read view, a child landing between the
// user-scoped query and the sid-scoped one is absent from the first and present in the second.
// Querying user-scoped FIRST is what makes that harmless: the child is never a candidate for
// revocation, and the sid-scoped query promotes it. The reverse order revokes the user's own
// newly issued token.
//
// TWO LIMITS, both deliberate and neither fixable at this layer. This says nothing about a child
// committed after both queries, which no ordering can reach. And it says nothing about whether the
// second query can see the commit at all: under MySQL/InnoDB's default REPEATABLE READ both reads
// can share one snapshot, in which case the child is invisible to both and the order is moot. The
// residual is accepted in decision 16 and tracked in #131, whose criterion 5 is the cross-engine
// validation this test cannot provide.
func TestRevokeUserAuthState_ChildCommittedBetweenTheDiscoveryQueries(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	parent := &models.RefreshToken{
		Id: 1, RefreshTokenJti: "rt-parent", SessionIdentifier: revokeKeepSid,
		RefreshTokenType: "Refresh", CodeId: sql.NullInt64{Int64: 11, Valid: true},
		AuthStateGeneration: revokeOldGeneration,
	}
	// Committed by the racing refresh after the user-scoped query ran, so it appears only in
	// the sid-scoped result below.
	child := &models.RefreshToken{
		Id: 2, RefreshTokenJti: "rt-child", SessionIdentifier: revokeKeepSid,
		RefreshTokenType: "Refresh", CodeId: sql.NullInt64{Int64: 11, Valid: true},
		PreviousRefreshTokenJti: "rt-parent", AuthStateGeneration: revokeOldGeneration,
	}

	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
		Return(revokeNewGeneration, nil).Once()
	db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
		Return([]*models.RefreshToken{parent}, nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", revokeTx, revokeKeepSid).
		Return([]*models.RefreshToken{parent, child}, nil).Once()
	db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{1, 2}, revokeNewGeneration).
		Return(nil).Once()
	db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).
		Return([]models.UserSession{revocationSessions()[0]}, nil).Once()
	db.On("PromoteUserSessionGeneration", revokeTx, int64(100), revokeNewGeneration).
		Return(nil).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, revokeKeepSid)
	require.NoError(t, err)

	// The child is promoted, not revoked. Promoting an id the sweep never saw is deliberate:
	// it belongs to the exempted grant origin by the only query that can establish that.
	assert.Equal(t, []int64{1, 2}, promotedIds(t, db))
	assert.False(t, child.Revoked, "the racing child must not be revoked")
	assert.Empty(t, result.RevokedRefreshTokenJtis)

	// The ORDER itself, asserted directly on the recorded calls. Everything above would hold
	// under the reverse order too, because a mock returns the same rows whenever it is called
	// and so cannot represent a commit landing between two queries. This assertion therefore
	// proves the order and NOTHING about visibility: on an engine where the second query can
	// see the commit, the order is what decides whether the racing child is promoted or
	// revoked, and on one where it cannot, the order is moot. Pinned here so the ordering is
	// not "tidied" by someone who reads it as arbitrary.
	userScoped := callIndex(t, db, "GetRefreshTokensByUserId")
	sidScoped := callIndex(t, db, "GetRefreshTokensBySessionIdentifier")
	assert.Less(t, userScoped, sidScoped,
		"the user-scoped query must run BEFORE the sid-scoped one, so a child committed between them is promoted rather than swept")
}

// callIndex reports where a method appears in the mock's recorded call sequence.
func callIndex(t *testing.T, db *mocks_data.Database, method string) int {
	t.Helper()
	for i, call := range db.Calls {
		if call.Method == method {
			return i
		}
	}
	t.Fatalf("%v was never called", method)
	return -1
}

// TestRevokeUserAuthState_PreservedSessionAlreadyReaped covers exceptSid naming a session
// with no row left. Legitimate rather than an error: the background worker reaps idle
// sessions while offline refresh tokens outlive them, so the tokens are still exempted and
// there is simply nothing to promote.
func TestRevokeUserAuthState_PreservedSessionAlreadyReaped(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	offline := &models.RefreshToken{
		Id: 2, RefreshTokenJti: "rt-keep-offline", RefreshTokenType: "Offline",
		CodeId: sql.NullInt64{Int64: 12, Valid: true}, AuthStateGeneration: revokeOldGeneration,
	}

	db.On("IncrementUserAuthStateGeneration", revokeTx, revokeUserId).
		Return(revokeNewGeneration, nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", revokeTx, revokeKeepSid).
		Return([]*models.RefreshToken{offline}, nil).Once()
	db.On("GetRefreshTokensByUserId", revokeTx, revokeUserId).
		Return([]*models.RefreshToken{offline}, nil).Once()
	db.On("PromoteRefreshTokenGenerations", revokeTx, []int64{2}, revokeNewGeneration).
		Return(nil).Once()
	db.On("GetUserSessionsByUserId", revokeTx, revokeUserId).
		Return([]models.UserSession{}, nil).Once()

	result, err := RevokeUserAuthState(db, revokeTx, revokeUserId, revokeKeepSid)
	require.NoError(t, err)

	assert.False(t, offline.Revoked, "the token is still preserved even with no session row")
	assert.Equal(t, []int64{2}, promotedIds(t, db))
	// The exemption WAS applied, so the result reports it even with no session row left
	// (finding 32). Reporting "" here would leave the audit record unable to explain why
	// rt-keep-offline is missing from the revoked list. The field names the exempted grant
	// origin, not a surviving session.
	assert.Equal(t, revokeKeepSid, result.PreservedSessionIdentifier)
	assert.Empty(t, result.TerminatedSessionIdentifiers)
}

// TestRevokeRefreshTokens covers the extracted primitive on its own. Its contract is one
// sentence, "return only the JTIs this call transitioned", and #77's teardown guard depends on
// it, so it is tested apart from the sweep that uses it.
func TestRevokeRefreshTokens(t *testing.T) {
	t.Run("empty input writes nothing and returns an empty list", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)

		jtis, err := revokeRefreshTokens(db, revokeTx, nil)

		require.NoError(t, err)
		assert.Empty(t, jtis)
		// Non-nil, so a JSON audit payload carries [] rather than null.
		assert.NotNil(t, jtis)
		db.AssertNotCalled(t, "UpdateRefreshToken", mock.Anything, mock.Anything)
	})

	t.Run("all already revoked writes nothing and reports nothing", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tokens := []*models.RefreshToken{
			{Id: 1, RefreshTokenJti: "a", Revoked: true},
			{Id: 2, RefreshTokenJti: "b", Revoked: true},
		}

		jtis, err := revokeRefreshTokens(db, revokeTx, tokens)

		require.NoError(t, err)
		// The load-bearing case for #77: an empty return here is what tells
		// revokeOnAuthCodeReuse to leave the session alone.
		assert.Empty(t, jtis)
		db.AssertNotCalled(t, "UpdateRefreshToken", mock.Anything, mock.Anything)
	})

	t.Run("mixed input reports only the transitioned ones", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tokens := []*models.RefreshToken{
			{Id: 1, RefreshTokenJti: "live-1"},
			{Id: 2, RefreshTokenJti: "dead", Revoked: true},
			{Id: 3, RefreshTokenJti: "live-2"},
		}
		db.On("UpdateRefreshToken", revokeTx, tokens[0]).Return(nil).Once()
		db.On("UpdateRefreshToken", revokeTx, tokens[2]).Return(nil).Once()

		jtis, err := revokeRefreshTokens(db, revokeTx, tokens)

		require.NoError(t, err)
		assert.Equal(t, []string{"live-1", "live-2"}, jtis)
		assert.True(t, tokens[0].Revoked)
		assert.True(t, tokens[2].Revoked)
	})

	t.Run("an error mid-loop discards the partial list", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		tokens := []*models.RefreshToken{
			{Id: 1, RefreshTokenJti: "live-1"},
			{Id: 2, RefreshTokenJti: "live-2"},
		}
		boom := errors.New("connection refused")
		db.On("UpdateRefreshToken", revokeTx, tokens[0]).Return(nil).Once()
		db.On("UpdateRefreshToken", revokeTx, tokens[1]).Return(boom).Once()

		jtis, err := revokeRefreshTokens(db, revokeTx, tokens)

		require.ErrorIs(t, err, boom)
		// Nil, not ["live-1"]. The caller rolls the transaction back, so reporting a JTI as
		// revoked when the transaction never committed would put a false claim in the audit
		// log. Returning the partial list is the tempting shape and is wrong.
		assert.Nil(t, jtis)
	})
}

// The session under termination (#129 stage 3). Deliberately a different id and identifier from
// the #106 fixtures above, so an expectation copied from one of those tests cannot match here by
// accident.
const (
	terminateSessionId = int64(300)
	terminateSid       = "sid-terminate"
)

func terminatedSession() *models.UserSession {
	return &models.UserSession{
		Id:                terminateSessionId,
		SessionIdentifier: terminateSid,
		UserId:            revokeUserId,
	}
}

// terminationFixture builds the three refresh tokens the sid-scoped sweep reasons about:
//
//	1 rt-session-bound  session-bound, its own session_identifier set
//	2 rt-offline        OFFLINE, its own session_identifier EMPTY, code id set
//	3 rt-already-gone   session-bound, ALREADY revoked
//
// Token 2 is the load-bearing one. An offline grant is not session-bound, so the row itself
// carries no sid and only the joined codes row ties it to this session. It is returned here
// because GetRefreshTokensBySessionIdentifier matches codes.session_identifier, and any
// implementation that re-filters these rows by rt.SessionIdentifier drops exactly the offline
// tokens decision 2 exists to revoke.
func terminationFixture() []*models.RefreshToken {
	return []*models.RefreshToken{
		{
			Id: 1, RefreshTokenJti: "rt-session-bound",
			SessionIdentifier: terminateSid,
			RefreshTokenType:  "Refresh",
			CodeId:            sql.NullInt64{Int64: 21, Valid: true},
		},
		{
			Id: 2, RefreshTokenJti: "rt-offline",
			SessionIdentifier: "",
			RefreshTokenType:  "Offline",
			CodeId:            sql.NullInt64{Int64: 22, Valid: true},
		},
		{
			Id: 3, RefreshTokenJti: "rt-already-gone",
			SessionIdentifier: terminateSid,
			RefreshTokenType:  "Refresh",
			CodeId:            sql.NullInt64{Int64: 23, Valid: true},
			Revoked:           true,
		},
	}
}

// TestTerminateUserSessionTx_RevokesTheGrantsOfTheSession is the happy path, and the owner of
// decision 5's write order. Every expectation is registered on a strict mock against the exact
// transaction BeginTransaction returned, so a write that reached the pool instead, or a call
// nobody expected, fails the test on its own.
func TestTerminateUserSessionTx_RevokesTheGrantsOfTheSession(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	tokens := terminationFixture()

	db.On("BeginTransaction").Return(revokeTx, nil).Once()
	db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).Return(int64(2), nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).Return(tokens, nil).Once()
	// The two live tokens only. rt-already-gone is not written again.
	db.On("UpdateRefreshToken", revokeTx, tokens[0]).Return(nil).Once()
	db.On("UpdateRefreshToken", revokeTx, tokens[1]).Return(nil).Once()
	db.On("DeleteUserSession", revokeTx, terminateSessionId).Return(nil).Once()
	db.On("CommitTransaction", revokeTx).Return(nil).Once()
	// The deferred rollback runs on the success path too, where it is a no-op against a committed
	// transaction. A test omitting this fails on the strict mock.
	db.On("RollbackTransaction", revokeTx).Return(nil).Once()

	result, err := TerminateUserSessionTx(db, terminatedSession())
	require.NoError(t, err)

	// The count is the sweep's own, reported as-is: it is what the audit event carries, and
	// stage 1's data cases pin that it counts rows TRANSITIONED rather than rows matched.
	assert.Equal(t, int64(2), result.RevokedCodeCount)

	// Two JTIs, not three. rt-already-gone was revoked before the call, so it is neither written
	// again nor reported, which is the invariant #77's teardown guard depends on.
	assert.Equal(t, []string{"rt-session-bound", "rt-offline"}, result.RevokedRefreshTokenJtis)
	assert.NotContains(t, result.RevokedRefreshTokenJtis, "rt-already-gone")

	// The offline token is revoked although its own session_identifier is empty. This is the
	// assertion that fails against an implementation re-filtering the swept rows by
	// rt.SessionIdentifier, which would leave an offline grant refreshing after termination:
	// gap 1, the defect this issue opens with.
	assert.True(t, tokens[1].Revoked, "the offline token of the terminated session must be revoked")
	assert.True(t, tokens[0].Revoked)

	// Decision 5's order: the durable marker first, then the tokens, then the row. Within one
	// transaction this is not a safety boundary and neither sweep reads user_sessions, so the
	// assertion pins the design's order rather than a correctness property, and is here so
	// reordering has to be deliberate.
	codeSweep := callIndex(t, db, "RevokeCodesBySessionIdentifier")
	tokenSweep := callIndex(t, db, "GetRefreshTokensBySessionIdentifier")
	deletion := callIndex(t, db, "DeleteUserSession")
	assert.Less(t, codeSweep, tokenSweep, "codes are marked before the tokens are swept")
	assert.Less(t, tokenSweep, deletion, "the session row is deleted last")

	// The negative control, and the reason this seam is worth having. Terminating one session
	// must not advance the user's generation nor sweep user-scoped tokens: either would sign out
	// every other device that user has, which is the opposite of what the action means and the
	// reason #129 exists separately from #106.
	db.AssertNotCalled(t, "IncrementUserAuthStateGeneration", mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "GetRefreshTokensByUserId", mock.Anything, mock.Anything)
	db.AssertNotCalled(t, "PromoteRefreshTokenGenerations", mock.Anything, mock.Anything, mock.Anything)
}

// TestTerminateUserSessionTx_NothingToRevoke covers a session with no grants at all. Ending it is
// not an error, and the event still attests that the action happened, so the result reports zeros
// rather than the helper refusing.
func TestTerminateUserSessionTx_NothingToRevoke(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	db.On("BeginTransaction").Return(revokeTx, nil).Once()
	db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).Return(int64(0), nil).Once()
	db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).
		Return([]*models.RefreshToken{}, nil).Once()
	db.On("DeleteUserSession", revokeTx, terminateSessionId).Return(nil).Once()
	db.On("CommitTransaction", revokeTx).Return(nil).Once()
	db.On("RollbackTransaction", revokeTx).Return(nil).Once()

	result, err := TerminateUserSessionTx(db, terminatedSession())
	require.NoError(t, err)

	assert.Equal(t, int64(0), result.RevokedCodeCount)
	assert.Empty(t, result.RevokedRefreshTokenJtis)
	// Non-nil, so the audit payload carries [] rather than null.
	assert.NotNil(t, result.RevokedRefreshTokenJtis)
	// The session still ends. The strict mock proves it: the DeleteUserSession expectation above
	// is registered Once and an unmet expectation fails the test.
	db.AssertNotCalled(t, "UpdateRefreshToken", mock.Anything, mock.Anything)
}

// TestTerminateUserSessionTx_RejectsAnUnusableSession pins the entry preconditions. Both are
// refused before the transaction opens, which the strict mock enforces: no expectations are
// registered at all, so any call whatsoever fails the case.
func TestTerminateUserSessionTx_RejectsAnUnusableSession(t *testing.T) {
	t.Run("nil session", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)

		result, err := TerminateUserSessionTx(db, nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires the session to terminate")
		assert.Equal(t, TerminationResult{}, result)
		assertNotAttempted(t, db, "BeginTransaction")
	})

	t.Run("empty session identifier", func(t *testing.T) {
		db := mocks_data.NewDatabase(t)
		session := terminatedSession()
		session.SessionIdentifier = ""

		result, err := TerminateUserSessionTx(db, session)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires a session identifier")
		assert.Equal(t, TerminationResult{}, result)
		// RevokeCodesBySessionIdentifier refuses an empty identifier itself, so the outcome would
		// be the same three statements later. What this pins is that no transaction was opened
		// and no write attempted, so a bad argument does not read as a database fault.
		assertNotAttempted(t, db, "BeginTransaction")
	})
}

// TestTerminateUserSessionTx_AnyFailureYieldsTheZeroResult walks every failure point and asserts
// the same two things at each: the error reaches the caller, and the result is the ZERO value
// rather than a partially populated one. The second is what stops a caller emitting an audit
// event that claims a revocation the transaction rolled back.
//
// Each row registers only the calls its path reaches. The strict mock does the rest in both
// directions: an unexpected call fails the case, and so does an expectation that was never met.
func TestTerminateUserSessionTx_AnyFailureYieldsTheZeroResult(t *testing.T) {
	boom := errors.New("connection refused")

	cases := []struct {
		name         string
		setup        func(db *mocks_data.Database)
		notAttempted []string
		extraAssert  func(t *testing.T, result TerminationResult)
	}{
		{
			name: "BeginTransaction fails",
			setup: func(db *mocks_data.Database) {
				db.On("BeginTransaction").Return(nil, boom).Once()
			},
			// Not even the rollback: there is no transaction to roll back.
			notAttempted: []string{"RevokeCodesBySessionIdentifier", "RollbackTransaction"},
		},
		{
			name: "the code sweep fails",
			setup: func(db *mocks_data.Database) {
				db.On("BeginTransaction").Return(revokeTx, nil).Once()
				db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).
					Return(int64(0), boom).Once()
				db.On("RollbackTransaction", revokeTx).Return(nil).Once()
			},
			notAttempted: []string{"GetRefreshTokensBySessionIdentifier", "DeleteUserSession",
				"CommitTransaction"},
		},
		{
			// KEEP THIS ROW. It is the one that names the property: the sweep returned 2, the
			// transaction rolls back, and a caller auditing that 2 would record a revocation that
			// never happened. Measured rather than assumed, against a helper mutated to populate
			// the result as it goes: four of the six rows here fail under it, because the shared
			// zero-value assertion in the loop below catches every path where a write had already
			// succeeded. This row is the one that says WHY, and the only one asserting the count
			// itself, so the failure reads as a contract violation rather than a struct mismatch.
			name: "the token query fails after the code sweep revoked two codes",
			setup: func(db *mocks_data.Database) {
				db.On("BeginTransaction").Return(revokeTx, nil).Once()
				db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).
					Return(int64(2), nil).Once()
				db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).
					Return(nil, boom).Once()
				db.On("RollbackTransaction", revokeTx).Return(nil).Once()
			},
			notAttempted: []string{"UpdateRefreshToken", "DeleteUserSession", "CommitTransaction"},
			extraAssert: func(t *testing.T, result TerminationResult) {
				assert.Equal(t, int64(0), result.RevokedCodeCount,
					"the count must not survive a rolled-back transaction")
			},
		},
		{
			name: "a token write fails",
			setup: func(db *mocks_data.Database) {
				tokens := terminationFixture()
				db.On("BeginTransaction").Return(revokeTx, nil).Once()
				db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).
					Return(int64(2), nil).Once()
				db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).
					Return(tokens, nil).Once()
				db.On("UpdateRefreshToken", revokeTx, tokens[0]).Return(boom).Once()
				db.On("RollbackTransaction", revokeTx).Return(nil).Once()
			},
			notAttempted: []string{"DeleteUserSession", "CommitTransaction"},
		},
		{
			name: "the deletion fails",
			setup: func(db *mocks_data.Database) {
				db.On("BeginTransaction").Return(revokeTx, nil).Once()
				db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).
					Return([]*models.RefreshToken{}, nil).Once()
				db.On("DeleteUserSession", revokeTx, terminateSessionId).Return(boom).Once()
				db.On("RollbackTransaction", revokeTx).Return(nil).Once()
			},
			notAttempted: []string{"CommitTransaction"},
		},
		{
			// The one failure whose durable outcome is unknowable, per the helper's comment. The
			// caller still gets the zero result and must still not audit: a commit that reports an
			// error may in fact have applied.
			name: "the commit fails",
			setup: func(db *mocks_data.Database) {
				db.On("BeginTransaction").Return(revokeTx, nil).Once()
				db.On("RevokeCodesBySessionIdentifier", revokeTx, terminateSid).
					Return(int64(1), nil).Once()
				db.On("GetRefreshTokensBySessionIdentifier", revokeTx, terminateSid).
					Return([]*models.RefreshToken{}, nil).Once()
				db.On("DeleteUserSession", revokeTx, terminateSessionId).Return(nil).Once()
				db.On("CommitTransaction", revokeTx).Return(boom).Once()
				db.On("RollbackTransaction", revokeTx).Return(nil).Once()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := mocks_data.NewDatabase(t)
			tc.setup(db)

			result, err := TerminateUserSessionTx(db, terminatedSession())

			require.ErrorIs(t, err, boom)
			assert.Equal(t, TerminationResult{}, result)
			assert.Nil(t, result.RevokedRefreshTokenJtis,
				"the error path returns the zero value, and a caller must not audit it")
			assertNotAttempted(t, db, tc.notAttempted...)
			if tc.extraAssert != nil {
				tc.extraAssert(t, result)
			}
		})
	}
}

// assertNotAttempted fails if any of the named methods appears in the mock's recorded calls. The
// strict mock would already reject an unexpected call; this states which writes each failure path
// must not have reached, so the intent survives a later edit to the expectations.
func assertNotAttempted(t *testing.T, db *mocks_data.Database, methods ...string) {
	t.Helper()
	for _, call := range db.Calls {
		for _, method := range methods {
			assert.NotEqual(t, method, call.Method, "%v must not be attempted on this path", method)
		}
	}
}

// stubRevocationSweepTx registers every database call RevokeUserAuthStateTx makes for a user
// with no live sessions and no refresh tokens, which is the shape a HANDLER test wants: it
// exercises the wiring without restating the sweep table this file already owns exhaustively.
//
// Note it stubs RollbackTransaction as well as CommitTransaction. The deferred rollback runs on
// the success path too, where it is a no-op against a committed transaction, and a test that
// omits it fails on the strict mock.
//
// It also proves the transaction is real: BeginTransaction returns a non-nil tx, so every
// nested call is asserted to receive that exact pointer. A nil one would be rejected by
// RevokeUserAuthState's precondition.
func stubRevocationSweepTx(database *mocks_data.Database, userId int64, newGeneration int64) {
	database.On("BeginTransaction").Return(revokeTx, nil).Once()
	database.On("IncrementUserAuthStateGeneration", revokeTx, userId).
		Return(newGeneration, nil).Once()
	database.On("GetRefreshTokensByUserId", revokeTx, userId).
		Return([]*models.RefreshToken{}, nil).Once()
	database.On("PromoteRefreshTokenGenerations", revokeTx, []int64{}, newGeneration).
		Return(nil).Once()
	database.On("GetUserSessionsByUserId", revokeTx, userId).
		Return([]models.UserSession{}, nil).Once()
	database.On("CommitTransaction", revokeTx).Return(nil).Once()
	database.On("RollbackTransaction", revokeTx).Return(nil).Once()
}
