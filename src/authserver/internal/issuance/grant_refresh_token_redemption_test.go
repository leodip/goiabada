package issuance

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the refresh grant's redemption, in the order IssueRefreshTokenGrant owns it: the
// containment of a replayed token's family (#128), the flow gate (#250), then one transaction that
// takes the token's user row (#131), claims the presented token (#128), checks the family's
// revocation record (#132, #259), re-reads the presented token and mints and inserts the child, and
// the session bump after it commits. These assertions were the token
// handler's until the redemption moved into the issuer (#437); what the minted tokens carry is
// pinned by the TestMint*RefreshTokens cases.
//
// Every statement of the rotation is expected on rotationTx and never on mock.Anything. A wildcard
// would match a read moved back to nil and the case would pass, and on sqlitedb's single connection
// that read waits for the connection the transaction holds until the context expires (#139, #437).

// rotationTx is the transaction the rotation runs in, and containmentTx the one containment does.
var (
	rotationTx    = &sql.Tx{}
	containmentTx = &sql.Tx{}
)

// fakeSessions is the session port a refresh bumps through, recording each bump.
type fakeSessions struct {
	bumps   []bumpCall
	session *record.UserSession
	err     error
	note    func(string)
}

type bumpCall struct {
	sessionIdentifier string
	clientId          int64
	authMethods       string
	acrLevel          record.AcrLevel
	ipAddress         string
}

func (f *fakeSessions) BumpUserSession(_ context.Context, sessionIdentifier string, clientId int64,
	authMethods string, acrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error) {
	f.bumps = append(f.bumps, bumpCall{sessionIdentifier, clientId, authMethods, acrLevel, ipAddress})
	if f.note != nil {
		f.note("bump")
	}
	return f.session, f.err
}

// codeRefreshInput is a refresh of a live token an authorization code minted, bound to a session,
// for a client whose authorization code flow is on.
func codeRefreshInput() *RefreshTokenGrantInput {
	now := time.Now().UTC()
	return &RefreshTokenGrantInput{
		Client: &record.Client{Id: 1, ClientIdentifier: "test-client", AuthorizationCodeEnabled: true},
		RefreshToken: &record.RefreshToken{
			Id:                   7,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			SessionIdentifier:    "sid-1",
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
			Scope:                "openid resource1:read",
			CodeId:               sql.NullInt64{Int64: 9, Valid: true},
			Code: record.Code{
				Id:                9,
				ClientId:          1,
				UserId:            5,
				Scope:             "openid resource1:read",
				AuthenticatedAt:   now.Add(-5 * time.Minute),
				SessionIdentifier: "sid-1",
				AcrLevel:          "urn:goiabada:level1",
				AuthMethods:       "pwd",
				Client:            record.Client{Id: 1, ClientIdentifier: "test-client"},
				User:              record.User{Id: 5, Subject: fake.UUID(), Email: "someone@example.com"},
			},
		},
	}
}

// ropcRefreshInput is a refresh of a live token the password grant minted, for a client whose
// password grant is on.
func ropcRefreshInput() *RefreshTokenGrantInput {
	now := time.Now().UTC()
	ropcOn := true
	return &RefreshTokenGrantInput{
		Client: &record.Client{Id: 1, ClientIdentifier: "ropc-client", ResourceOwnerPasswordCredentialsEnabled: &ropcOn},
		RefreshToken: &record.RefreshToken{
			Id:                   7,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			UserId:               sql.NullInt64{Int64: 5, Valid: true},
			ClientId:             sql.NullInt64{Int64: 1, Valid: true},
			Scope:                "openid resource1:read",
			RefreshTokenType:     "Offline",
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
			AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
			User:                 record.User{Id: 5, Subject: fake.UUID(), Email: "someone@example.com"},
			Client:               record.Client{Id: 1, ClientIdentifier: "ropc-client"},
		},
		IsROPC: true,
	}
}

// armRotation arms the rotation's transaction and the statements that open it, in order: the
// acquisition of the presented token's user row, noted as "acquire", the claim on the presented
// token, noted as "claim", the read of the family's revocation record, noted as "family", which
// answers familyRevoked, and the re-read of the presented token, noted as "reread", which returns the
// generation the token carries now: the one the validator read. The transaction's own edges are
// noted as "begin" and "commit" or "rollback".
func armRotation(mockDB *datamocks.Database, input *RefreshTokenGrantInput, claimed bool, familyRevoked bool,
	note func(string)) *datamocks.RunInTransactionStub {

	return armRotationReading(mockDB, input, input.RefreshToken.AuthStateGeneration, claimed, familyRevoked, note)
}

// armRotationReading is armRotation for a token whose generation has moved since the validator read
// it, which is what a credential change that preserved its session leaves: the re-read returns
// currentGeneration.
func armRotationReading(mockDB *datamocks.Database, input *RefreshTokenGrantInput, currentGeneration int64,
	claimed bool, familyRevoked bool, note func(string)) *datamocks.RunInTransactionStub {

	stub := datamocks.ExpectRunInTransaction(mockDB, rotationTx, note)
	mockDB.On("AcquireUserRow", mock.Anything, rotationTx, refreshOwnerUserId(input)).
		Run(func(mock.Arguments) { note("acquire") }).Return(nil).Once()
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).
		Run(func(mock.Arguments) { note("claim") }).Return(claimed, nil).Once()
	if claimed {
		mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, rotationTx, input.RefreshToken.FirstRefreshTokenJti).
			Run(func(mock.Arguments) { note("family") }).Return(familyRevoked, nil).Once()
	}
	if claimed && !familyRevoked {
		mockDB.On("GetRefreshTokenById", mock.Anything, rotationTx, input.RefreshToken.Id).
			Run(func(mock.Arguments) { note("reread") }).
			Return(&record.RefreshToken{Id: input.RefreshToken.Id, Revoked: true, AuthStateGeneration: currentGeneration}, nil).Once()
	}
	return stub
}

// insertedChild is the refresh token row the mint inserted, captured for the case that asks what it
// was stamped with.
type insertedChild struct {
	row *record.RefreshToken
}

// armRefreshMint arms every read and write minting input's token set makes, all on rotationTx,
// noting "mint" at the first of them and "insert" at the child's, and returns what the insert
// received.
func armRefreshMint(t *testing.T, mockDB *datamocks.Database, input *RefreshTokenGrantInput, note func(string)) *insertedChild {
	t.Helper()
	parent := input.RefreshToken
	inserted := &insertedChild{}
	mockDB.On("GetCurrentSigningKey", mock.Anything, rotationTx).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil).Once()
	mockDB.On("CreateRefreshToken", mock.Anything, rotationTx, mock.AnythingOfType("*record.RefreshToken")).
		Run(func(args mock.Arguments) {
			note("insert")
			inserted.row = args.Get(2).(*record.RefreshToken)
		}).Return(nil).Once()
	mockDB.On("UserHasProfilePicture", mock.Anything, rotationTx, mock.Anything).Return(false, nil).Maybe()
	if input.IsROPC {
		// The mint loads onto the parent it was handed: the presented token as the validator read
		// it, with the generation the rotation re-read under the lock, so the row is matched by id.
		sameToken := mock.MatchedBy(func(rt *record.RefreshToken) bool { return rt.Id == parent.Id })
		mockDB.On("RefreshTokenLoadUser", mock.Anything, rotationTx, sameToken).Run(func(mock.Arguments) { note("mint") }).Return(nil).Once()
		mockDB.On("RefreshTokenLoadClient", mock.Anything, rotationTx, sameToken).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, rotationTx, &parent.User).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, rotationTx, parent.User.Groups).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, rotationTx, &parent.User).Return(nil).Once()
		return inserted
	}
	code := &parent.Code
	now := time.Now().UTC()
	mockDB.On("CodeLoadClient", mock.Anything, rotationTx, code).Run(func(mock.Arguments) { note("mint") }).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, rotationTx, code).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, rotationTx, &code.User).Return(nil).Once()
	mockDB.On("GroupsLoadAttributes", mock.Anything, rotationTx, code.User.Groups).Return(nil).Once()
	mockDB.On("UserLoadAttributes", mock.Anything, rotationTx, &code.User).Return(nil).Once()
	// The max lifetime of a session-bound token is read off the session, on the transaction.
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, rotationTx, "sid-1").Return(&record.UserSession{
		Id: 1, UserId: 5, Started: now.Add(-30 * time.Minute), LastAccessed: now.Add(-5 * time.Minute),
	}, nil).Once()
	return inserted
}

func refreshGrantSettings() *record.Settings {
	return &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
}

// The code-descended shape: one transaction that claims, checks the family and mints and inserts
// the child, then, after it commits, a bump of the session the token is bound to, with no step-up
// and no address, handing the bumped session back for the audit (#243).
func TestIssueRefreshTokenGrant_ClaimsMintsThenBumpsTheSession(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	var order []string
	note := func(what string) { order = append(order, what) }
	sessions := &fakeSessions{session: &record.UserSession{Id: 3, UserId: 5}, note: note}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	input.ScopeRequested = "openid"
	stub := armRotation(mockDB, input, true, false, note)
	armRefreshMint(t, mockDB, input, note)

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.NoError(t, err)
	assert.Equal(t, "openid", response.Scope, "the requested narrowing reaches the mint")
	assert.NotEmpty(t, response.RefreshToken)
	// The claim, the family's record, the mint and the child's insert are inside the transaction; the
	// bump opens a transaction of its own and so follows the commit.
	assert.Equal(t, []string{"begin", "acquire", "claim", "family", "reread", "mint", "insert", "commit", "bump"}, order)
	require.NoError(t, stub.BodyErr)
	require.Len(t, sessions.bumps, 1)
	bump := sessions.bumps[0]
	assert.Equal(t, "sid-1", bump.sessionIdentifier)
	assert.Equal(t, int64(1), bump.clientId, "the session is bumped for the code's client")
	// No step-up and no address: the session keeps its methods, its level and the address its
	// browser was last seen from (#243).
	assert.Empty(t, bump.authMethods)
	assert.Empty(t, bump.acrLevel)
	assert.Empty(t, bump.ipAddress)
	assert.Same(t, sessions.session, outcome.BumpedSession)
	mockDB.AssertExpectations(t)
}

func TestIssueRefreshTokenGrant_ATokenBoundToNoSessionBumpsNothing(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	input.RefreshToken.SessionIdentifier = ""
	armRotation(mockDB, input, true, false, func(string) {})
	armRefreshMint(t, mockDB, input, func(string) {})

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.Nil(t, outcome.BumpedSession)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// A password grant's token has no browser session. The ROPC arm never bumps, even on a row that
// somehow names one, because a session identifier there would be another user's (#106).
func TestIssueRefreshTokenGrant_APasswordGrantsTokenBumpsNothing(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	var order []string
	note := func(what string) { order = append(order, what) }
	sessions := &fakeSessions{note: note}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := ropcRefreshInput()
	input.RefreshToken.SessionIdentifier = "some-other-users-session"
	input.ScopeRequested = "openid"
	armRotation(mockDB, input, true, false, note)
	armRefreshMint(t, mockDB, input, note)

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.NoError(t, err)
	assert.Equal(t, "openid", response.Scope, "the requested narrowing reaches the mint")
	assert.Equal(t, []string{"begin", "acquire", "claim", "family", "reread", "mint", "insert", "commit"}, order)
	assert.Empty(t, sessions.bumps)
	assert.Nil(t, outcome.BumpedSession)
	mockDB.AssertExpectations(t)
}

// Every read the mint makes runs on the rotation's transaction, the claim mapper's picture lookup
// included, for both shapes. On sqlitedb's single connection a read on nil waits for the connection
// the transaction holds until the context expires, and the mapper swallows that failure, so the
// token silently loses its picture claim (#437). The expectations on rotationTx are the assertion:
// the picture read is required (no Maybe) and a read on nil matches none of them.
func TestIssueRefreshTokenGrant_TheMintReadsThePictureOnTheRotationTransaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  func() *RefreshTokenGrantInput
		userId int64
	}{
		{"authorization code token", codeRefreshInput, 5},
		{"ROPC token", ropcRefreshInput, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{session: &record.UserSession{}})

			input := tc.input()
			input.ScopeRequested = "openid profile"
			input.RefreshToken.Scope = "openid profile"
			input.RefreshToken.Code.Scope = "openid profile"
			settings := refreshGrantSettings()
			settings.IncludeOpenIDConnectClaimsInAccessToken = true
			settings.IncludeOpenIDConnectClaimsInIdToken = true

			armRotation(mockDB, input, true, false, func(string) {})
			armRefreshMint(t, mockDB, input, func(string) {})
			mockDB.On("UserHasProfilePicture", mock.Anything, rotationTx, tc.userId).Return(true, nil)

			response, _, err := issuer.IssueRefreshTokenGrant(context.Background(), settings, input)

			require.NoError(t, err)
			assert.NotEmpty(t, response.IdToken)
			mockDB.AssertCalled(t, "UserHasProfilePicture", mock.Anything, rotationTx, tc.userId)
			mockDB.AssertExpectations(t)
		})
	}
}

// A replayed token contains its family and goes no further: no gate, no claim, no mint, no bump.
// Containment is one transaction that writes the family's record first and then revokes the live
// members, so a family is never swept without a record (#132). Both answers come back on the
// refusal, because whether the handler audits the replay depends on them.
func TestIssueRefreshTokenGrant_AReplayContainsItsFamilyAndGoesNoFurther(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *RefreshTokenGrantInput
	}{
		{"authorization code family", codeRefreshInput()},
		{"ROPC family", ropcRefreshInput()},
	} {
		for _, revokedCount := range []int64{0, 2} {
			for _, recorded := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s, %d members revoked, record written %v", tc.name, revokedCount, recorded), func(t *testing.T) {
					mockDB := datamocks.NewDatabase(t)
					sessions := &fakeSessions{}
					issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

					input := *tc.input
					replayed := *input.RefreshToken
					replayed.Revoked = true
					input.RefreshToken = &replayed
					var order []string
					note := func(what string) { order = append(order, what) }
					datamocks.ExpectRunInTransaction(mockDB, containmentTx, note)
					mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
						Run(func(mock.Arguments) { note("record") }).Return(recorded, nil).Once()
					mockDB.On("RevokeRefreshTokenFamily", mock.Anything, containmentTx, "jti-family").
						Run(func(mock.Arguments) { note("revoke") }).Return(revokedCount, nil).Once()

					response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), &input)

					var replayErr *RefreshTokenReplayedError
					require.ErrorAs(t, err, &replayErr)
					assert.Equal(t, revokedCount, replayErr.FamilyRevokedCount)
					assert.Equal(t, recorded, replayErr.FamilyRecorded)
					assert.Contains(t, err.Error(), fmt.Sprintf("containment revoked %d live family members", revokedCount))
					assert.Equal(t, []string{"begin", "record", "revoke", "commit"}, order,
						"the record is written before the sweep, in one transaction")
					assert.Nil(t, response)
					assert.Nil(t, outcome)
					assert.Empty(t, sessions.bumps)
					mockDB.AssertExpectations(t)
				})
			}
		}
	}
}

// Containment that failed revoked nothing, so it is a fault and never a replay refusal, which the
// handler would audit as a containment. Each of its two statements failing is one.
func TestIssueRefreshTokenGrant_AFailedContainmentIsAFault(t *testing.T) {
	failure := errs.New("connection refused")

	for _, tc := range []struct {
		name string
		arm  func(mockDB *datamocks.Database)
	}{
		{"the record's write fails", func(mockDB *datamocks.Database) {
			mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
				Return(false, failure).Once()
		}},
		{"the sweep fails", func(mockDB *datamocks.Database) {
			mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
				Return(true, nil).Once()
			mockDB.On("RevokeRefreshTokenFamily", mock.Anything, containmentTx, "jti-family").Return(int64(0), failure).Once()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

			input := codeRefreshInput()
			input.RefreshToken.Revoked = true
			stub := datamocks.ExpectRunInTransaction(mockDB, containmentTx)
			tc.arm(mockDB)

			response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

			require.ErrorIs(t, err, failure)
			var replayErr *RefreshTokenReplayedError
			assert.NotErrorAs(t, err, &replayErr)
			require.ErrorIs(t, stub.BodyErr, failure, "the transaction rolled back")
			assert.Nil(t, response)
			assert.Nil(t, outcome)
			mockDB.AssertExpectations(t)
		})
	}
}

// Two containments of one new family can both read the record absent, and the second insert then
// loses on the key, which on PostgreSQL aborts its transaction. The containment runs once more, and
// the second attempt finds the record the winner committed, so it is a replay refusal that wrote no
// record (#132).
func TestIssueRefreshTokenGrant_AContainmentThatLosesTheKeyRunsOnceMore(t *testing.T) {
	lostTheKey := errs.Errorf("%w: another containment recorded the family first", data.ErrUniqueViolation)

	t.Run("the second attempt finds the winner's record", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

		input := codeRefreshInput()
		input.RefreshToken.Revoked = true
		first := datamocks.ExpectRunInTransaction(mockDB, containmentTx)
		second := datamocks.ExpectRunInTransaction(mockDB, containmentTx)
		mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
			Return(false, lostTheKey).Once()
		mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
			Return(false, nil).Once()
		mockDB.On("RevokeRefreshTokenFamily", mock.Anything, containmentTx, "jti-family").Return(int64(0), nil).Once()

		_, _, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

		var replayErr *RefreshTokenReplayedError
		require.ErrorAs(t, err, &replayErr)
		assert.False(t, replayErr.FamilyRecorded, "the winner wrote the record, so this containment did not")
		assert.Zero(t, replayErr.FamilyRevokedCount)
		require.ErrorIs(t, first.BodyErr, data.ErrUniqueViolation)
		require.NoError(t, second.BodyErr)
		mockDB.AssertExpectations(t)
	})

	t.Run("a second loss is a fault and is not retried again", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

		input := codeRefreshInput()
		input.RefreshToken.Revoked = true
		datamocks.ExpectRunInTransaction(mockDB, containmentTx)
		datamocks.ExpectRunInTransaction(mockDB, containmentTx)
		mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
			Return(false, lostTheKey).Twice()

		_, _, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

		require.ErrorIs(t, err, data.ErrUniqueViolation)
		var replayErr *RefreshTokenReplayedError
		assert.NotErrorAs(t, err, &replayErr)
		mockDB.AssertExpectations(t)
	})
}

// TestIssueRefreshTokenGrant_FlowGate owns the whole truth table for the rule that a refresh is
// governed by the switch of the flow that ISSUED the token, not by the authorization code flag
// alone. Before this landed every refresh was refused on !AuthorizationCodeEnabled whatever minted
// the token, so an ROPC-only client could never redeem the token ROPC handed it (row 2) and turning
// ROPC off stopped nothing already issued (rows 3 to 5) (#250).
//
// Every row presents a LIVE token, so the gate is what answers rather than containment. An accepted
// row is proved by reaching the claim, stubbed to lose so the row stops there; a refused row reaches
// nothing, so the token is not spent and the operator may turn the switch back on.
func TestIssueRefreshTokenGrant_FlowGate(t *testing.T) {
	ropcOn, ropcOff := true, false

	for _, tc := range []struct {
		name       string
		client     *record.Client
		globalROPC bool
		ropcToken  bool
		refused    bool
	}{
		{"row 1: ROPC token, both flows on, accepted",
			&record.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, true, false},
		{"row 2: ROPC token, ROPC-only client, accepted",
			&record.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, true, false},
		{"row 3: ROPC token, ROPC off on the client, refused",
			&record.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, true, true, true},
		{"row 4: ROPC token, both flows off, refused",
			&record.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, true, true, true},
		// The only row that fails if the gate reads the per-client override alone: the client
		// inherits, and the global switch is what turns ROPC off.
		{"row 5: ROPC token, client inherits, global ROPC off, refused",
			&record.Client{Id: 1, AuthorizationCodeEnabled: true}, false, true, true},
		{"row 6: authorization code token, that flow off, refused",
			&record.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, false, true},
		{"row 7: authorization code token, that flow on, ROPC off, accepted",
			&record.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

			input := codeRefreshInput()
			if tc.ropcToken {
				input = ropcRefreshInput()
			}
			input.Client = tc.client
			settings := refreshGrantSettings()
			settings.ResourceOwnerPasswordCredentialsEnabled = tc.globalROPC
			if !tc.refused {
				armRotation(mockDB, input, false, false, func(string) {})
			}

			response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), settings, input)

			assert.Nil(t, response)
			assert.Nil(t, outcome)
			if tc.refused {
				require.ErrorIs(t, err, ErrRefreshFlowDisabled)
			} else {
				require.ErrorIs(t, err, ErrRefreshTokenNotClaimed, "an accepted row reaches the claim")
			}
			// The strict double: a refused row opens no transaction and reaches neither containment
			// nor the claim.
			mockDB.AssertExpectations(t)
		})
	}
}

// TestIssueRefreshTokenGrant_ContainmentPrecedesTheFlowGate is why the flow gate sits below
// containment: a stolen token replayed while its flow is switched off must still revoke its
// rotation family, and the refusal must be the replay's so the handler audits it. Whether a theft
// is detected must not depend on which switches happen to be on (#250).
func TestIssueRefreshTokenGrant_ContainmentPrecedesTheFlowGate(t *testing.T) {
	ropcOff := false
	for _, tc := range []struct {
		name  string
		input *RefreshTokenGrantInput
	}{
		{"ROPC token replayed while ROPC is off", ropcRefreshInput()},
		{"authorization code token replayed while that flow is off", codeRefreshInput()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

			input := tc.input
			input.Client = &record.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}
			input.RefreshToken.Revoked = true
			settings := refreshGrantSettings()
			settings.ResourceOwnerPasswordCredentialsEnabled = false
			datamocks.ExpectRunInTransaction(mockDB, containmentTx)
			mockDB.On("RecordRefreshTokenFamilyRevoked", mock.Anything, containmentTx, "jti-family", RevokedFamilyReasonReplay).
				Return(true, nil).Once()
			mockDB.On("RevokeRefreshTokenFamily", mock.Anything, containmentTx, "jti-family").Return(int64(2), nil).Once()

			_, _, err := issuer.IssueRefreshTokenGrant(context.Background(), settings, input)

			var replayErr *RefreshTokenReplayedError
			require.ErrorAs(t, err, &replayErr, "the replay answers, not the gate")
			assert.Equal(t, int64(2), replayErr.FamilyRevokedCount)
			require.NotErrorIs(t, err, ErrRefreshFlowDisabled)
			mockDB.AssertExpectations(t)
		})
	}
}

// A refresh whose claim changed no row lost to a concurrent rotation, a concurrent revocation or a
// deleted row, and cannot tell which. It is refused WITHOUT containment, since one of those is a
// rotation whose freshly minted child a cascade would destroy, and it mints and bumps nothing
// (#128). The strict double is the assertion that neither containment nor the family's record was
// touched, and the transaction rolled back.
func TestIssueRefreshTokenGrant_ALostClaimContainsAndMintsNothing(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)
	logs := logtest.CaptureSlog(t)

	input := codeRefreshInput()
	stub := armRotation(mockDB, input, false, false, func(string) {})

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, ErrRefreshTokenNotClaimed)
	require.ErrorIs(t, stub.BodyErr, ErrRefreshTokenNotClaimed)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)

	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelDebug, records[0].Level)
	assert.Equal(t, "refresh token was no longer live at claim time, rejecting", records[0].Message)
	assert.Equal(t, int64(7), records[0].Attrs["refresh_token_id"])
}

func TestIssueRefreshTokenGrant_AClaimFailureIsAFault(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

	input := codeRefreshInput()
	failure := errs.New("connection refused")
	datamocks.ExpectRunInTransaction(mockDB, rotationTx)
	mockDB.On("AcquireUserRow", mock.Anything, rotationTx, int64(5)).Return(nil).Once()
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).Return(false, failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	require.NotErrorIs(t, err, ErrRefreshTokenNotClaimed)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	mockDB.AssertExpectations(t)
}

// The family's record is checked inside the rotation's transaction, below the claim. A family that
// was recorded revoked after the validator read it, by a containment or by a client made public,
// leaves the body as an error: the transaction rolls back, so the claim is undone and no child is
// minted or inserted, and no session is bumped (#132, #259). Both shapes of token.
func TestIssueRefreshTokenGrant_AFamilyRevokedInTheGapRollsTheRotationBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *RefreshTokenGrantInput
	}{
		{"authorization code token", codeRefreshInput()},
		{"ROPC token", ropcRefreshInput()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			sessions := &fakeSessions{}
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)
			var order []string
			note := func(what string) { order = append(order, what) }
			logs := logtest.CaptureSlog(t)

			// The strict double: nothing is minted, so no key is read and no child is inserted.
			stub := armRotation(mockDB, tc.input, true, true, note)

			response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), tc.input)

			require.ErrorIs(t, err, ErrRefreshFamilyRevoked)
			require.NotErrorIs(t, err, ErrRefreshTokenNotClaimed, "it is its own refusal, not a lost claim")
			require.ErrorIs(t, stub.BodyErr, ErrRefreshFamilyRevoked, "the body asked for the rollback")
			assert.Equal(t, []string{"begin", "acquire", "claim", "family", "rollback"}, order)
			assert.Nil(t, response)
			assert.Nil(t, outcome)
			assert.Empty(t, sessions.bumps)
			assert.Empty(t, logs.Records())
			mockDB.AssertExpectations(t)
		})
	}
}

// The record is read below the claim, so a claim that was lost never reads it, and a read that
// fails is a fault that leaves the transaction rolled back with nothing minted.
func TestIssueRefreshTokenGrant_AFailedFamilyReadIsAFault(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	failure := errs.New("connection refused")
	stub := datamocks.ExpectRunInTransaction(mockDB, rotationTx)
	mockDB.On("AcquireUserRow", mock.Anything, rotationTx, int64(5)).Return(nil).Once()
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).Return(true, nil).Once()
	mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, rotationTx, "jti-family").Return(false, failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	require.NotErrorIs(t, err, ErrRefreshFamilyRevoked)
	require.ErrorIs(t, stub.BodyErr, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// A mint that fails after the claim bumps nothing, and rolls the claim back with the transaction:
// the session is kept alive only by a refresh that was answered with tokens.
func TestIssueRefreshTokenGrant_AFailedMintBumpsNothing(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	failure := errs.New("connection refused")
	stub := armRotation(mockDB, input, true, false, func(string) {})
	mockDB.On("CodeLoadClient", mock.Anything, rotationTx, &input.RefreshToken.Code).Return(failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	require.ErrorIs(t, stub.BodyErr, failure, "the claim is rolled back with the failed mint")
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// The same for a password grant's token, whose mint reads its user off the token row.
func TestIssueRefreshTokenGrant_AFailedROPCMintIsAFault(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := ropcRefreshInput()
	failure := errs.New("connection refused")
	stub := armRotation(mockDB, input, true, false, func(string) {})
	mockDB.On("RefreshTokenLoadUser", mock.Anything, rotationTx, input.RefreshToken).Return(failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	require.ErrorIs(t, stub.BodyErr, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// A commit the engine refuses after the body succeeded is a fault: the tokens minted inside are not
// handed out, and no session is bumped for a refresh that did not commit.
func TestIssueRefreshTokenGrant_ARefusedCommitHandsOutNothing(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	commitFailure := errs.New("commit refused")
	datamocks.ExpectRunInTransactionThenFail(mockDB, rotationTx, commitFailure)
	mockDB.On("AcquireUserRow", mock.Anything, rotationTx, int64(5)).Return(nil).Once()
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).Return(true, nil).Once()
	mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, rotationTx, "jti-family").Return(false, nil).Once()
	mockDB.On("GetRefreshTokenById", mock.Anything, rotationTx, input.RefreshToken.Id).
		Return(&record.RefreshToken{Id: input.RefreshToken.Id}, nil).Once()
	armRefreshMint(t, mockDB, input, func(string) {})

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, commitFailure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// The user's row is the rotation's first statement, and it is the token's owner's: the code's for a
// token an authorization code minted, the token's own for a password grant's. Both ids are set
// differently on each input, so a rotation that read the other one takes a different row and fails
// here (#131). The order is pinned by the cases above, which list "acquire" before "claim".
func TestIssueRefreshTokenGrant_TakesTheTokensOwnersRowFirst(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     func() *RefreshTokenGrantInput
		wantOwner int64
	}{
		{"authorization code token: the code's user", func() *RefreshTokenGrantInput {
			input := codeRefreshInput()
			input.RefreshToken.UserId = sql.NullInt64{Int64: 99, Valid: true}
			return input
		}, 5},
		{"ROPC token: the token's user", func() *RefreshTokenGrantInput {
			input := ropcRefreshInput()
			input.RefreshToken.UserId = sql.NullInt64{Int64: 99, Valid: true}
			input.RefreshToken.Code.UserId = 5
			return input
		}, 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{session: &record.UserSession{}})

			input := tc.input()
			var order []string
			note := func(what string) { order = append(order, what) }
			datamocks.ExpectRunInTransaction(mockDB, rotationTx, note)
			mockDB.On("AcquireUserRow", mock.Anything, rotationTx, tc.wantOwner).
				Run(func(mock.Arguments) { note("acquire") }).Return(nil).Once()
			// The claim is lost, so the case stops at it: what it measures is the row taken before.
			mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).
				Run(func(mock.Arguments) { note("claim") }).Return(false, nil).Once()

			_, _, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

			require.ErrorIs(t, err, ErrRefreshTokenNotClaimed)
			assert.Equal(t, []string{"begin", "acquire", "claim", "rollback"}, order)
			mockDB.AssertExpectations(t)
		})
	}
}

// A row that cannot be taken is a fault before anything is claimed: the claim is never attempted,
// which the strict double enforces, and the transaction rolls back (#131).
func TestIssueRefreshTokenGrant_AFailedAcquisitionIsAFaultBeforeTheClaim(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	failure := errs.New("lock wait timeout")
	stub := datamocks.ExpectRunInTransaction(mockDB, rotationTx)
	mockDB.On("AcquireUserRow", mock.Anything, rotationTx, int64(5)).Return(failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	require.NotErrorIs(t, err, ErrRefreshTokenNotClaimed)
	require.ErrorIs(t, stub.BodyErr, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// The child is stamped from the presented token's row as the rotation reads it under the user's
// lock, and the access token it is answered with carries the same number, because a credential
// change that preserved the token's session can have promoted it since the validator read it (#131,
// #106 rule 5). Both shapes. The negative control is the same token unmoved: it is stamped with the
// number the validator saw, so the copy is not simply being replaced by something else.
func TestIssueRefreshTokenGrant_TheChildIsStampedFromTheRowReadUnderTheLock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input func() *RefreshTokenGrantInput
	}{
		{"authorization code token", codeRefreshInput},
		{"ROPC token", ropcRefreshInput},
	} {
		for _, current := range []struct {
			name string
			want int64
		}{
			{"promoted to a later generation since the validator read it", 4},
			{"unmoved since the validator read it", 3},
		} {
			t.Run(tc.name+", "+current.name, func(t *testing.T) {
				mockDB := datamocks.NewDatabase(t)
				issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{session: &record.UserSession{}})

				input := tc.input()
				input.RefreshToken.AuthStateGeneration = 3
				armRotationReading(mockDB, input, current.want, true, false, func(string) {})
				inserted := armRefreshMint(t, mockDB, input, func(string) {})

				response, _, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

				require.NoError(t, err)
				require.NotNil(t, inserted.row)
				assert.Equal(t, current.want, inserted.row.AuthStateGeneration, "the child's generation is the row's as read under the lock")
				assert.EqualValues(t, current.want, parseAccessTokenClaims(t, response.AccessToken)["auth_state_generation"],
					"the access token carries the generation the child was stamped with")
				assert.Equal(t, int64(3), input.RefreshToken.AuthStateGeneration,
					"the validator's copy is not edited: a rerun after a deadlock reads the row again")
				mockDB.AssertExpectations(t)
			})
		}
	}
}

// A presented token that cannot be read back under the lock is a fault with nothing minted and the
// claim rolled back: a missing row, which a claim that succeeded a statement earlier makes
// impossible short of a bug, and a read that fails.
func TestIssueRefreshTokenGrant_ATokenThatCannotBeReadBackIsAFault(t *testing.T) {
	failure := errs.New("connection refused")

	for _, tc := range []struct {
		name string
		row  *record.RefreshToken
		err  error
	}{
		{"the read fails", nil, failure},
		{"the row is gone", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			sessions := &fakeSessions{}
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

			input := codeRefreshInput()
			stub := datamocks.ExpectRunInTransaction(mockDB, rotationTx)
			mockDB.On("AcquireUserRow", mock.Anything, rotationTx, int64(5)).Return(nil).Once()
			mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, rotationTx, input.RefreshToken.Id).Return(true, nil).Once()
			mockDB.On("IsRefreshTokenFamilyRevoked", mock.Anything, rotationTx, "jti-family").Return(false, nil).Once()
			mockDB.On("GetRefreshTokenById", mock.Anything, rotationTx, input.RefreshToken.Id).Return(tc.row, tc.err).Once()

			response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

			require.Error(t, err)
			require.NotErrorIs(t, err, ErrRefreshTokenNotClaimed)
			require.NotErrorIs(t, err, ErrRefreshFamilyRevoked)
			require.Error(t, stub.BodyErr, "the claim is rolled back with the transaction")
			assert.Nil(t, response)
			assert.Nil(t, outcome)
			assert.Empty(t, sessions.bumps)
			// The strict double: nothing was minted, so no key was read and no child inserted.
			mockDB.AssertExpectations(t)
		})
	}
}

// A bump that fails is answered as a fault, as it was when the handler made it: the tokens already
// minted are not handed out.
func TestIssueRefreshTokenGrant_AFailedBumpIsAFault(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	failure := errs.New("connection refused")
	sessions := &fakeSessions{err: failure}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	armRotation(mockDB, input, true, false, func(string) {})
	armRefreshMint(t, mockDB, input, func(string) {})

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.ErrorIs(t, err, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Len(t, sessions.bumps, 1)
	mockDB.AssertExpectations(t)
}
