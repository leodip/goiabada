package issuance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 3 of #437 for the implicit grant: the transaction IssueImplicitTx opens, the session row it
// takes first, and what every read after it runs on. Section 5 gives the reason these are unit
// cases and not a database's: this pins the ORDER and the transaction each statement is handed,
// and what an engine then does with them is the data tier's (implicit_issuance_test.go).
//
// Every read is expected on issueTx and never on mock.Anything. A wildcard would match a read
// moved back to nil and the case would pass, and on sqlitedb's single connection that read waits
// for the connection the transaction holds until the context expires (#139, #437).

// armImplicitTransaction arms what IssueImplicitTx does before it signs anything: it opens one
// transaction, issueTx, and takes the session row on it.
func armImplicitTransaction(mockDB *datamocks.Database, sessionIdentifier string) {
	datamocks.ExpectRunInTransaction(mockDB, issueTx)
	mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, sessionIdentifier).Return(true, nil).Once()
}

const implicitBaseURL = "http://localhost:8081"

// implicitFixture is an implicit ceremony that can issue both tokens with the profile claims on, so
// the claim mapper's picture read is reached by the access token and by the ID token.
type implicitFixture struct {
	mockDB   *datamocks.Database
	issuer   *TokenIssuer
	settings *record.Settings
	input    *ImplicitGrantInput
	keyPair  *record.KeyPair
}

func newImplicitFixture(t *testing.T) *implicitFixture {
	t.Helper()

	mockDB := datamocks.NewDatabase(t)
	return &implicitFixture{
		mockDB: mockDB,
		issuer: NewTokenIssuer(mockDB, implicitBaseURL, testDataCipher, nil),
		settings: &record.Settings{
			Issuer:                                  "https://test-issuer.com",
			TokenExpirationInSeconds:                600,
			IncludeOpenIDConnectClaimsInAccessToken: true,
			IncludeOpenIDConnectClaimsInIdToken:     true,
		},
		input: &ImplicitGrantInput{
			Client:              &record.Client{Id: 1, ClientIdentifier: "implicit-client"},
			User:                &record.User{Id: 7, Subject: fake.UUID(), Username: "implicituser", Groups: []record.Group{}},
			Scope:               "openid profile",
			AcrLevel:            record.AcrLevel1,
			AuthMethods:         "pwd",
			SessionIdentifier:   "sid-implicit",
			Nonce:               "implicit-nonce",
			AuthenticatedAt:     time.Now().UTC().Add(-time.Minute),
			AuthStateGeneration: 3,
		},
		keyPair: &record.KeyPair{KeyIdentifier: "test-key-id", PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t))},
	}
}

// expectEveryRead arms the signing read, the three loads and the picture lookup, each on issueTx,
// appending its name to order as it is made.
func (f *implicitFixture) expectEveryRead(order *[]string, hasPicture bool) {
	note := func(name string) func(mock.Arguments) {
		return func(mock.Arguments) { *order = append(*order, name) }
	}
	f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Run(note("signing key")).Return(f.keyPair, nil).Once()
	f.mockDB.On("UserLoadGroups", mock.Anything, issueTx, f.input.User).Run(note("groups")).Return(nil).Once()
	f.mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, f.input.User.Groups).Run(note("group attributes")).Return(nil).Once()
	f.mockDB.On("UserLoadAttributes", mock.Anything, issueTx, f.input.User).Run(note("user attributes")).Return(nil).Once()
	f.mockDB.On("UserHasProfilePicture", mock.Anything, issueTx, f.input.User.Id).Run(note("picture")).Return(hasPicture, nil).Twice()
}

// The whole sequence, in order, on one transaction: begin, the session row, then every read the
// signing makes, then commit. The row is first because it is what orders this ceremony against a
// termination of the session, and it is held to the commit (#139); the picture lookup is made
// twice, once per token, and both are on the transaction (#437).
func TestIssueImplicitTx_TakesTheSessionRowFirstAndReadsOnTheTransaction(t *testing.T) {
	f := newImplicitFixture(t)

	var order []string
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx, func(edge string) { order = append(order, edge) })
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").
		Run(func(mock.Arguments) { order = append(order, "session row") }).Return(true, nil).Once()
	f.expectEveryRead(&order, true)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)
	require.NoError(t, err)
	require.NotNil(t, response)

	assert.Equal(t, []string{
		"begin", "session row", "signing key", "groups", "group attributes", "user attributes",
		"picture", "picture", "commit",
	}, order)
	f.mockDB.AssertExpectations(t)
}

// The picture claim reaches both tokens, which is the observable half of the read being made on
// the transaction: the mapper swallows a failed lookup, so a read that hung on SQLite's one
// connection would drop the claim without an error and only this assertion would notice (#437).
func TestIssueImplicitTx_KeepsThePictureInBothTokens(t *testing.T) {
	f := newImplicitFixture(t)
	var order []string
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Once()
	f.expectEveryRead(&order, true)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)
	require.NoError(t, err)

	publicKey := getTestPublicKey(t)
	want := implicitBaseURL + "/userinfo/picture/" + f.input.User.Subject
	assert.Equal(t, want, verifyAndDecodeToken(t, response.AccessToken, publicKey)["picture"], "access token")
	assert.Equal(t, want, verifyAndDecodeToken(t, response.IdToken, publicKey)["picture"], "ID token")
}

// A user with no picture gets no claim, so the case above is about the lookup and not about the
// claim being unconditional.
func TestIssueImplicitTx_NoPictureNoClaim(t *testing.T) {
	f := newImplicitFixture(t)
	var order []string
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Once()
	f.expectEveryRead(&order, false)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)
	require.NoError(t, err)

	publicKey := getTestPublicKey(t)
	assert.NotContains(t, verifyAndDecodeToken(t, response.AccessToken, publicKey), "picture")
	assert.NotContains(t, verifyAndDecodeToken(t, response.IdToken, publicKey), "picture")
}

// No row is the answer decision 16 gives an ended session, and nothing after the acquisition may
// have run: the mock carries no stub for the signing key, so a read past it fails the case. The
// sentinel is what /auth/issue answers with the level 1 restart, or login_required for a silent
// request (#197).
func TestIssueImplicitTx_NoSessionRowIsRefusedBeforeAnythingIsRead(t *testing.T) {
	f := newImplicitFixture(t)
	stub := datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(false, nil).Once()

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, ErrIssuingSessionGone)
	assert.Nil(t, response, "nothing is signed for a session that is gone")
	assert.ErrorIs(t, stub.BodyErr, ErrIssuingSessionGone, "the body returned the sentinel, so the transaction rolled back")
	f.mockDB.AssertNotCalled(t, "GetCurrentSigningKey", mock.Anything, mock.Anything)
	f.mockDB.AssertNotCalled(t, "UserLoadGroups", mock.Anything, mock.Anything, mock.Anything)
}

// An empty identifier is refused by AcquireUserSessionRow itself, as a caller's bug and not as a
// session that is gone, and the issuer hands that error back as it is: /auth/issue's decision
// refuses a ceremony with no identifier as the gone shape before the issuer is reached (decision 16),
// so an error here is a defect that must be loud rather than a restart that hides it.
func TestIssueImplicitTx_AnEmptySessionIdentifierIsTheCallersErrorNotAGoneSession(t *testing.T) {
	f := newImplicitFixture(t)
	f.input.SessionIdentifier = ""
	refused := errors.New("can't acquire a user session row with an empty session identifier")
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "").Return(false, refused).Once()

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, refused)
	assert.NotErrorIs(t, err, ErrIssuingSessionGone)
	assert.Nil(t, response)
}

// A failed acquisition is not a gone session: the caller answers it with a 500, never with the
// restart, so the two must be told apart.
func TestIssueImplicitTx_AFailedAcquisitionIsNotASessionGone(t *testing.T) {
	f := newImplicitFixture(t)
	boom := errors.New("the row could not be taken")
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(false, boom).Once()

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, boom)
	assert.NotErrorIs(t, err, ErrIssuingSessionGone)
	assert.Nil(t, response)
}

// Each read's failure is returned as the database reported it and nothing is signed after it.
func TestIssueImplicitTx_AFailedReadStopsTheSigning(t *testing.T) {
	boom := errors.New("read failed")

	testCases := []struct {
		name string
		arm  func(f *implicitFixture)
	}{
		{"the signing key", func(f *implicitFixture) {
			f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(nil, boom).Once()
		}},
		{"the user's groups", func(f *implicitFixture) {
			f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(f.keyPair, nil).Once()
			f.mockDB.On("UserLoadGroups", mock.Anything, issueTx, mock.Anything).Return(boom).Once()
		}},
		{"the groups' attributes", func(f *implicitFixture) {
			f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(f.keyPair, nil).Once()
			f.mockDB.On("UserLoadGroups", mock.Anything, issueTx, mock.Anything).Return(nil).Once()
			f.mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, mock.Anything).Return(boom).Once()
		}},
		{"the user's attributes", func(f *implicitFixture) {
			f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(f.keyPair, nil).Once()
			f.mockDB.On("UserLoadGroups", mock.Anything, issueTx, mock.Anything).Return(nil).Once()
			f.mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, mock.Anything).Return(nil).Once()
			f.mockDB.On("UserLoadAttributes", mock.Anything, issueTx, mock.Anything).Return(boom).Once()
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newImplicitFixture(t)
			datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
			f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Once()
			tc.arm(f)

			response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

			require.ErrorIs(t, err, boom)
			assert.Nil(t, response)
		})
	}
}

// A commit the engine refuses leaves the tokens' fate indeterminate for the ceremony's purposes,
// and no response is handed out: the caller answers a 500 rather than tokens (as IssueAuthCodeTx's
// caller does for a code).
func TestIssueImplicitTx_AFailedCommitIsNotAResponse(t *testing.T) {
	f := newImplicitFixture(t)
	boom := errors.New("commit refused")
	datamocks.ExpectRunInTransactionThenFail(f.mockDB, issueTx, boom)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Once()
	var order []string
	f.expectEveryRead(&order, true)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, boom)
	assert.Nil(t, response, "tokens signed inside a transaction that did not commit are not handed out")
}

// A transaction the helper cannot open never reaches the body.
func TestIssueImplicitTx_ATransactionThatCannotOpenIsAnError(t *testing.T) {
	f := newImplicitFixture(t)
	boom := errors.New("cannot begin")
	datamocks.ExpectRunInTransactionRefused(f.mockDB, boom)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.ErrorIs(t, err, boom)
	assert.Nil(t, response)
}

// The deadlock shape: RunInTransaction reruns the body, and the response is the second attempt's
// alone. The user's groups are loaded afresh each time, so nothing the aborted attempt left on the
// input reaches the tokens.
func TestIssueImplicitTx_ARerunBodySignsAgainFromScratch(t *testing.T) {
	f := newImplicitFixture(t)
	datamocks.ExpectRunInTransactionRerun(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Twice()
	f.mockDB.On("GetCurrentSigningKey", mock.Anything, issueTx).Return(f.keyPair, nil).Twice()
	f.mockDB.On("UserLoadGroups", mock.Anything, issueTx, mock.Anything).Return(nil).Twice()
	f.mockDB.On("GroupsLoadAttributes", mock.Anything, issueTx, mock.Anything).Return(nil).Twice()
	f.mockDB.On("UserLoadAttributes", mock.Anything, issueTx, mock.Anything).Return(nil).Twice()
	f.mockDB.On("UserHasProfilePicture", mock.Anything, issueTx, f.input.User.Id).Return(false, nil).Times(4)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
}

// IssueImplicit is the form the data tier holds open across a termination, and like IssueAuthCode it
// refuses to run outside a transaction: the row it takes first is released by an autocommitted
// statement, so without one the ordering would be a comment. The mock has no stubs, so a single
// statement before the refusal fails the case.
func TestIssueImplicit_RequiresATransaction(t *testing.T) {
	f := newImplicitFixture(t)

	response, err := f.issuer.IssueImplicit(context.Background(), nil, f.settings, f.input, true, true)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a transaction")
	assert.Nil(t, response)
}

// The tokens carry what the input says, unchanged by the transaction around them: the session
// identifier as sid, the ceremony's generation, the nonce, the client's lifetime, the scope as the
// response's, and at_hash on the ID token when both are issued.
func TestIssueImplicitTx_SignsWhatTheInputSays(t *testing.T) {
	f := newImplicitFixture(t)
	f.input.Client.TokenExpirationInSeconds = 90
	datamocks.ExpectRunInTransaction(f.mockDB, issueTx)
	f.mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, "sid-implicit").Return(true, nil).Once()
	var order []string
	f.expectEveryRead(&order, false)

	response, err := f.issuer.IssueImplicitTx(context.Background(), f.settings, f.input, true, true)
	require.NoError(t, err)

	assert.Equal(t, int64(90), response.ExpiresIn)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, "openid profile", response.Scope)

	publicKey := getTestPublicKey(t)
	access := verifyAndDecodeToken(t, response.AccessToken, publicKey)
	id := verifyAndDecodeToken(t, response.IdToken, publicKey)
	assert.Equal(t, "sid-implicit", access["sid"])
	assert.Equal(t, "sid-implicit", id["sid"])
	assert.EqualValues(t, 3, access["auth_state_generation"])
	assert.Equal(t, "implicit-nonce", id["nonce"])
	assert.NotEmpty(t, id["at_hash"], "an ID token issued beside an access token carries at_hash (OIDC Core 3.2.2.10)")
}
