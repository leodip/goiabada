package issuance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the refresh grant's redemption, in the order IssueRefreshTokenGrant owns it: the
// containment of a replayed token's family (#128), the flow gate (#250), the claim on the presented
// token (#128), the mint and the child's insert, and the session bump. These assertions were the
// token handler's until the redemption moved into the issuer (#437); what the minted tokens carry is
// pinned by the TestMint*RefreshTokens cases.

// fakeSessions is the session port a refresh bumps through, recording each bump.
type fakeSessions struct {
	bumps   []bumpCall
	session *models.UserSession
	err     error
	note    func(string)
}

type bumpCall struct {
	sessionIdentifier string
	clientId          int64
	authMethods       string
	acrLevel          models.AcrLevel
	ipAddress         string
}

func (f *fakeSessions) BumpUserSession(_ context.Context, sessionIdentifier string, clientId int64,
	authMethods string, acrLevel models.AcrLevel, ipAddress string) (*models.UserSession, error) {
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
		Client: &models.Client{Id: 1, ClientIdentifier: "test-client", AuthorizationCodeEnabled: true},
		RefreshToken: &models.RefreshToken{
			Id:                   7,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			SessionIdentifier:    "sid-1",
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
			Scope:                "openid resource1:read",
			CodeId:               sql.NullInt64{Int64: 9, Valid: true},
			Code: models.Code{
				Id:                9,
				ClientId:          1,
				UserId:            5,
				Scope:             "openid resource1:read",
				AuthenticatedAt:   now.Add(-5 * time.Minute),
				SessionIdentifier: "sid-1",
				AcrLevel:          "urn:goiabada:level1",
				AuthMethods:       "pwd",
				Client:            models.Client{Id: 1, ClientIdentifier: "test-client"},
				User:              models.User{Id: 5, Subject: fake.UUID(), Email: "someone@example.com"},
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
		Client: &models.Client{Id: 1, ClientIdentifier: "ropc-client", ResourceOwnerPasswordCredentialsEnabled: &ropcOn},
		RefreshToken: &models.RefreshToken{
			Id:                   7,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			UserId:               sql.NullInt64{Int64: 5, Valid: true},
			ClientId:             sql.NullInt64{Int64: 1, Valid: true},
			Scope:                "openid resource1:read",
			RefreshTokenType:     "Offline",
			MaxLifetime:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
			AuthenticatedAt:      sql.NullTime{Time: now.Add(-time.Hour), Valid: true},
			User:                 models.User{Id: 5, Subject: fake.UUID(), Email: "someone@example.com"},
			Client:               models.Client{Id: 1, ClientIdentifier: "ropc-client"},
		},
		IsROPC: true,
	}
}

// armRefreshMint arms every read and write minting input's token set makes, noting "mint" at the
// first of them and "insert" at the child's.
func armRefreshMint(t *testing.T, mockDB *mocks_data.Database, input *RefreshTokenGrantInput, note func(string)) {
	t.Helper()
	parent := input.RefreshToken
	mockDB.On("GetCurrentSigningKey", mock.Anything, (*sql.Tx)(nil)).Return(&models.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil).Once()
	mockDB.On("CreateRefreshToken", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*models.RefreshToken")).
		Run(func(mock.Arguments) { note("insert") }).Return(nil).Once()
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	if input.IsROPC {
		mockDB.On("RefreshTokenLoadUser", mock.Anything, (*sql.Tx)(nil), parent).Run(func(mock.Arguments) { note("mint") }).Return(nil).Once()
		mockDB.On("RefreshTokenLoadClient", mock.Anything, (*sql.Tx)(nil), parent).Return(nil).Once()
		mockDB.On("UserLoadGroups", mock.Anything, (*sql.Tx)(nil), &parent.User).Return(nil).Once()
		mockDB.On("GroupsLoadAttributes", mock.Anything, (*sql.Tx)(nil), parent.User.Groups).Return(nil).Once()
		mockDB.On("UserLoadAttributes", mock.Anything, (*sql.Tx)(nil), &parent.User).Return(nil).Once()
		return
	}
	code := &parent.Code
	now := time.Now().UTC()
	mockDB.On("CodeLoadClient", mock.Anything, (*sql.Tx)(nil), code).Run(func(mock.Arguments) { note("mint") }).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, (*sql.Tx)(nil), code).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, (*sql.Tx)(nil), &code.User).Return(nil).Once()
	mockDB.On("GroupsLoadAttributes", mock.Anything, (*sql.Tx)(nil), code.User.Groups).Return(nil).Once()
	mockDB.On("UserLoadAttributes", mock.Anything, (*sql.Tx)(nil), &code.User).Return(nil).Once()
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), "sid-1").Return(&models.UserSession{
		Id: 1, UserId: 5, Started: now.Add(-30 * time.Minute), LastAccessed: now.Add(-5 * time.Minute),
	}, nil).Maybe()
}

func refreshGrantSettings() *models.Settings {
	return &models.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		UserSessionIdleTimeoutInSeconds:         1200,
		UserSessionMaxLifetimeInSeconds:         2400,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
		ResourceOwnerPasswordCredentialsEnabled: true,
	}
}

// The code-descended shape: claim, mint, insert the child, then bump the session the token is bound
// to, with no step-up and no address, and hand the bumped session back for the audit (#243).
func TestIssueRefreshTokenGrant_ClaimsMintsThenBumpsTheSession(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	var order []string
	note := func(what string) { order = append(order, what) }
	sessions := &fakeSessions{session: &models.UserSession{Id: 3, UserId: 5}, note: note}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	input.ScopeRequested = "openid"
	armRefreshMint(t, mockDB, input, note)
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).
		Run(func(mock.Arguments) { note("claim") }).Return(true, nil).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.NoError(t, err)
	assert.Equal(t, "openid", response.Scope, "the requested narrowing reaches the mint")
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, []string{"claim", "mint", "insert", "bump"}, order)
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
	mockDB := mocks_data.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	input.RefreshToken.SessionIdentifier = ""
	armRefreshMint(t, mockDB, input, func(string) {})
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(true, nil).Once()

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
	mockDB := mocks_data.NewDatabase(t)
	var order []string
	note := func(what string) { order = append(order, what) }
	sessions := &fakeSessions{note: note}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := ropcRefreshInput()
	input.RefreshToken.SessionIdentifier = "some-other-users-session"
	input.ScopeRequested = "openid"
	armRefreshMint(t, mockDB, input, note)
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).
		Run(func(mock.Arguments) { note("claim") }).Return(true, nil).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	require.NoError(t, err)
	assert.Equal(t, "openid", response.Scope, "the requested narrowing reaches the mint")
	assert.Equal(t, []string{"claim", "mint", "insert"}, order)
	assert.Empty(t, sessions.bumps)
	assert.Nil(t, outcome.BumpedSession)
	mockDB.AssertExpectations(t)
}

// A replayed token contains its family and goes no further: no gate, no claim, no mint, no bump.
// The count comes back on the refusal, because whether the handler audits the replay depends on it.
func TestIssueRefreshTokenGrant_AReplayContainsItsFamilyAndGoesNoFurther(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *RefreshTokenGrantInput
	}{
		{"authorization code family", codeRefreshInput()},
		{"ROPC family", ropcRefreshInput()},
	} {
		for _, revokedCount := range []int64{0, 2} {
			t.Run(fmt.Sprintf("%s, %d members revoked", tc.name, revokedCount), func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				sessions := &fakeSessions{}
				issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

				input := *tc.input
				replayed := *input.RefreshToken
				replayed.Revoked = true
				input.RefreshToken = &replayed
				mockDB.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "jti-family").
					Return(revokedCount, nil).Once()

				response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), &input)

				var replayErr *RefreshTokenReplayedError
				require.ErrorAs(t, err, &replayErr)
				assert.Equal(t, revokedCount, replayErr.FamilyRevokedCount)
				assert.Contains(t, err.Error(), fmt.Sprintf("containment revoked %d live family members", revokedCount))
				assert.Nil(t, response)
				assert.Nil(t, outcome)
				assert.Empty(t, sessions.bumps)
				mockDB.AssertExpectations(t)
			})
		}
	}
}

// Containment that failed revoked nothing, so it is a fault and never a replay refusal, which the
// handler would audit as a containment.
func TestIssueRefreshTokenGrant_AFailedContainmentIsAFault(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

	input := codeRefreshInput()
	input.RefreshToken.Revoked = true
	failure := errs.New("connection refused")
	mockDB.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "jti-family").Return(int64(0), failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, failure)
	var replayErr *RefreshTokenReplayedError
	assert.False(t, errors.As(err, &replayErr))
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	mockDB.AssertExpectations(t)
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
		client     *models.Client
		globalROPC bool
		ropcToken  bool
		refused    bool
	}{
		{"row 1: ROPC token, both flows on, accepted",
			&models.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, true, false},
		{"row 2: ROPC token, ROPC-only client, accepted",
			&models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, true, false},
		{"row 3: ROPC token, ROPC off on the client, refused",
			&models.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, true, true, true},
		{"row 4: ROPC token, both flows off, refused",
			&models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, true, true, true},
		// The only row that fails if the gate reads the per-client override alone: the client
		// inherits, and the global switch is what turns ROPC off.
		{"row 5: ROPC token, client inherits, global ROPC off, refused",
			&models.Client{Id: 1, AuthorizationCodeEnabled: true}, false, true, true},
		{"row 6: authorization code token, that flow off, refused",
			&models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn}, true, false, true},
		{"row 7: authorization code token, that flow on, ROPC off, accepted",
			&models.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

			input := codeRefreshInput()
			if tc.ropcToken {
				input = ropcRefreshInput()
			}
			input.Client = tc.client
			settings := refreshGrantSettings()
			settings.ResourceOwnerPasswordCredentialsEnabled = tc.globalROPC
			if !tc.refused {
				mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(false, nil).Once()
			}

			response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), settings, input)

			assert.Nil(t, response)
			assert.Nil(t, outcome)
			if tc.refused {
				assert.ErrorIs(t, err, ErrRefreshFlowDisabled)
			} else {
				assert.ErrorIs(t, err, ErrRefreshTokenNotClaimed, "an accepted row reaches the claim")
			}
			// The strict double: a refused row reaches neither containment nor the claim.
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
			mockDB := mocks_data.NewDatabase(t)
			issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

			input := tc.input
			input.Client = &models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOff}
			input.RefreshToken.Revoked = true
			settings := refreshGrantSettings()
			settings.ResourceOwnerPasswordCredentialsEnabled = false
			mockDB.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "jti-family").Return(int64(2), nil).Once()

			_, _, err := issuer.IssueRefreshTokenGrant(context.Background(), settings, input)

			var replayErr *RefreshTokenReplayedError
			require.ErrorAs(t, err, &replayErr, "the replay answers, not the gate")
			assert.Equal(t, int64(2), replayErr.FamilyRevokedCount)
			assert.False(t, errors.Is(err, ErrRefreshFlowDisabled))
			mockDB.AssertExpectations(t)
		})
	}
}

// A refresh whose claim changed no row lost to a concurrent rotation, a concurrent revocation or a
// deleted row, and cannot tell which. It is refused WITHOUT containment, since one of those is a
// rotation whose freshly minted child a cascade would destroy, and it mints and bumps nothing
// (#128). The strict double is the assertion that RevokeRefreshTokenFamily was not called.
func TestIssueRefreshTokenGrant_ALostClaimContainsAndMintsNothing(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)
	logs := logtest.CaptureSlog(t)

	input := codeRefreshInput()
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(false, nil).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, ErrRefreshTokenNotClaimed)
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
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, &fakeSessions{})

	input := codeRefreshInput()
	failure := errs.New("connection refused")
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(false, failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, failure)
	assert.False(t, errors.Is(err, ErrRefreshTokenNotClaimed))
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	mockDB.AssertExpectations(t)
}

// A mint that fails after the claim bumps nothing: the session is kept alive only by a refresh that
// was answered with tokens.
func TestIssueRefreshTokenGrant_AFailedMintBumpsNothing(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	failure := errs.New("connection refused")
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(true, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, (*sql.Tx)(nil), &input.RefreshToken.Code).Return(failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// The same for a password grant's token, whose mint reads its user off the token row.
func TestIssueRefreshTokenGrant_AFailedROPCMintIsAFault(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	sessions := &fakeSessions{}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := ropcRefreshInput()
	failure := errs.New("connection refused")
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(true, nil).Once()
	mockDB.On("RefreshTokenLoadUser", mock.Anything, (*sql.Tx)(nil), input.RefreshToken).Return(failure).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Empty(t, sessions.bumps)
	mockDB.AssertExpectations(t)
}

// A bump that fails is answered as a fault, as it was when the handler made it: the tokens already
// minted are not handed out.
func TestIssueRefreshTokenGrant_AFailedBumpIsAFault(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	failure := errs.New("connection refused")
	sessions := &fakeSessions{err: failure}
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, sessions)

	input := codeRefreshInput()
	armRefreshMint(t, mockDB, input, func(string) {})
	mockDB.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), input.RefreshToken.Id).Return(true, nil).Once()

	response, outcome, err := issuer.IssueRefreshTokenGrant(context.Background(), refreshGrantSettings(), input)

	assert.ErrorIs(t, err, failure)
	assert.Nil(t, response)
	assert.Nil(t, outcome)
	assert.Len(t, sessions.bumps, 1)
	mockDB.AssertExpectations(t)
}
