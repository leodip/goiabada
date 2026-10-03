package issuance

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertAuthCodeShape pins what createAuthCode emits: a canonical v4 with its hyphens stripped,
// followed by 96 characters of the security alphabet, 128 in all. The prefix is 32 hex digits
// because a UUID is what produces it, so re-inserting the hyphens has to give something the
// generator's own parser accepts. Nothing about the code's format may change while its consumers
// hash a fixed-width secret (#278): the library swap kept the bytes, and this says so.
func assertAuthCodeShape(t *testing.T, authCode string) {
	t.Helper()

	require.Len(t, authCode, 128)

	hyphenated := authCode[0:8] + "-" + authCode[8:12] + "-" + authCode[12:16] + "-" +
		authCode[16:20] + "-" + authCode[20:32]
	parsed, err := uuidtest.Parse(hyphenated)
	require.NoError(t, err, "the first 32 characters must be a canonical UUID with its hyphens removed")
	assert.Equal(t, hyphenated, parsed, "the generator must emit lowercase")

	const securityAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	for i, r := range authCode[32:] {
		assert.Contains(t, securityAlphabet, string(r),
			"character %d of the random suffix is outside the security alphabet", i)
	}
}

func TestCreateAuthCode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	codeIssuer := NewCodeIssuer(mockDB)

	testClient := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

	input := &CreateCodeInput{
		ClientId:            "test-client",
		UserId:              123,
		ConsentedScope:      "openid profile",
		Scope:               "openid profile email",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		RedirectURI:         "https://example.com/callback",
		State:               "state123",
		Nonce:               "nonce456",
		UserAgent:           "Mozilla/5.0",
		ResponseMode:        "query",
		IpAddress:           "127.0.0.1",
		AcrLevel:            models.AcrLevel1,
		AuthMethods:         "pwd",
		SessionIdentifier:   "session123",
	}

	code, err := codeIssuer.createAuthCode(context.Background(), nil, input)

	assert.NoError(t, err)
	assert.NotNil(t, code)
	assert.Equal(t, testClient.Id, code.ClientId)
	assert.Equal(t, input.UserId, code.UserId)
	assert.Equal(t, input.ConsentedScope, code.Scope)
	assert.Equal(t, input.CodeChallenge, code.CodeChallenge.String)
	assert.Equal(t, input.CodeChallengeMethod, code.CodeChallengeMethod.String)
	assert.Equal(t, input.RedirectURI, code.RedirectURI)
	assert.Equal(t, input.State, code.State)
	assert.Equal(t, input.Nonce, code.Nonce)
	assert.Equal(t, input.UserAgent, code.UserAgent)
	assert.Equal(t, input.ResponseMode, code.ResponseMode)
	assert.Equal(t, input.IpAddress, code.IpAddress)
	assert.Equal(t, input.AcrLevel, code.AcrLevel)
	assert.Equal(t, input.AuthMethods, code.AuthMethods)
	assert.Equal(t, input.SessionIdentifier, code.SessionIdentifier)
	assert.False(t, code.Used)
	assertAuthCodeShape(t, code.Code)
	assert.NotEmpty(t, code.CodeHash)
	assert.WithinDuration(t, time.Now(), code.AuthenticatedAt, time.Second)

	mockDB.AssertExpectations(t)
}

// TestCreateAuthCode_BoundsTheUserAgent is decision 5 of #281, and the defect it closes was live:
// codes.user_agent is varchar(512) on three engines and a User-Agent of 513 bytes or more made
// CreateCode fail, so /auth/issue answered 500 to that browser after a completed ceremony. The
// bound sits at this one writer of the column rather than at the handler that reads the header, so
// every future caller is covered by it.
//
// What reaches CreateCode is captured rather than read off the returned struct: the column is what
// refuses the value, and the database is what sees it.
func TestCreateAuthCode_BoundsTheUserAgent(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "a 600-byte header reaches the column at 512 bytes",
			userAgent: strings.Repeat("a", 600),
			want:      strings.Repeat("a", 512),
		},
		{
			name:      "a 4-byte rune straddling byte 512 is dropped whole",
			userAgent: strings.Repeat("a", 510) + "\U0001F600",
			want:      strings.Repeat("a", 510),
		},
		{
			// RFC 9110 10.1.5 admits obs-text, and PostgreSQL and MySQL both refuse the insert
			// outright rather than storing the byte.
			name:      "a lone latin1 byte is repaired to U+FFFD",
			userAgent: "\xe9 Chrome",
			want:      "\uFFFD Chrome",
		},
		{
			name:      "a header inside the width is stored verbatim",
			userAgent: "curl/8.5.0",
			want:      "curl/8.5.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)
			codeIssuer := NewCodeIssuer(mockDB)

			mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)

			var persisted string
			mockDB.On("CreateCode", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Code")).Run(
				func(args mock.Arguments) {
					persisted = args.Get(2).(*models.Code).UserAgent
				}).Return(nil)

			_, err := codeIssuer.createAuthCode(context.Background(), nil, &CreateCodeInput{
				ClientId:          "test-client",
				UserId:            123,
				ConsentedScope:    "openid",
				Scope:             "openid",
				RedirectURI:       "https://example.com/callback",
				UserAgent:         tc.userAgent,
				ResponseMode:      "query",
				IpAddress:         "127.0.0.1",
				AcrLevel:          models.AcrLevel1,
				AuthMethods:       "pwd",
				SessionIdentifier: "session123",
			})

			require.NoError(t, err)
			assert.Equal(t, tc.want, persisted)
			assert.LessOrEqual(t, len(persisted), 512,
				"codes.user_agent is varchar(512) on three engines: a longer value is refused, not truncated")
			mockDB.AssertExpectations(t)
		})
	}
}

func TestCreateAuthCode_DefaultResponseMode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	codeIssuer := NewCodeIssuer(mockDB)

	testClient := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

	input := &CreateCodeInput{
		ClientId: "test-client",
		UserId:   123,
		// ResponseMode is intentionally left empty
		SessionIdentifier: "session123",
	}

	code, err := codeIssuer.createAuthCode(context.Background(), nil, input)

	assert.NoError(t, err)
	assert.NotNil(t, code)
	assert.Equal(t, "query", code.ResponseMode)

	mockDB.AssertExpectations(t)
}

func TestCreateAuthCode_ScopeHandling(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	codeIssuer := NewCodeIssuer(mockDB)

	testClient := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

	testCases := []struct {
		name           string
		consentedScope string
		scope          string
		expectedScope  string
	}{
		{
			name:           "ConsentedScope is used when present",
			consentedScope: "openid profile",
			scope:          "openid profile email",
			expectedScope:  "openid profile",
		},
		{
			name:           "Scope is used when ConsentedScope is empty",
			consentedScope: "",
			scope:          "openid profile email",
			expectedScope:  "openid profile email",
		},
		{
			name:           "Extra whitespace is removed",
			consentedScope: "  openid   profile  ",
			scope:          "",
			expectedScope:  "openid profile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := &CreateCodeInput{
				ClientId:          "test-client",
				UserId:            123,
				ConsentedScope:    tc.consentedScope,
				Scope:             tc.scope,
				SessionIdentifier: "session123",
			}

			code, err := codeIssuer.createAuthCode(context.Background(), nil, input)

			assert.NoError(t, err)
			assert.NotNil(t, code)
			assert.Equal(t, tc.expectedScope, code.Scope)
		})
	}

	mockDB.AssertExpectations(t)
}

func TestCreateAuthCode_DatabaseError(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	codeIssuer := NewCodeIssuer(mockDB)

	testClient := &models.Client{
		Id:               1,
		ClientIdentifier: "test-client",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.Anything, mock.AnythingOfType("*models.Code")).Return(errors.New("database error"))

	input := &CreateCodeInput{
		ClientId:          "test-client",
		UserId:            123,
		SessionIdentifier: "session123",
	}

	code, err := codeIssuer.createAuthCode(context.Background(), nil, input)

	assert.Error(t, err)
	assert.Nil(t, code)
	assert.Contains(t, err.Error(), "database error")

	mockDB.AssertExpectations(t)
}

// TestCreateAuthCode_RefusesAMissingClient is #248 part 5, folded into #139 because that branch
// changed its reachability.
//
// The client this ceremony started against can be deleted while the ceremony is in flight, and
// the lookup here then returns nil, which the line building the code dereferenced for client.Id.
// That was a narrow race before; since #139 issuance takes a SHARED lock on the client row, so a
// deletion that got there first makes this transaction WAIT and then proceed into this lookup,
// and the panic becomes the reliable outcome of losing that race rather than an unlucky one.
//
// A sentinel rather than a wrapped message, because /auth/issue branches on it: a deleted client
// is answered the way a vanished session is, by restarting the browser at level 1 or telling a
// silent request login_required, and not by a 500 that reads as a fault in this server.
func TestCreateAuthCode_RefusesAMissingClient(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	codeIssuer := NewCodeIssuer(mockDB)

	// nil, nil is the shape GetClientByClientIdentifier reports for a client that is not there:
	// an absence rather than a failure.
	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "deleted-client").
		Return((*models.Client)(nil), nil)

	code, err := codeIssuer.createAuthCode(context.Background(), nil, &CreateCodeInput{
		ClientId: "deleted-client", UserId: 123,
		SessionIdentifier: "session123",
	})

	require.ErrorIs(t, err, ErrIssuingClientGone,
		"the caller branches on this error, so it has to be identifiable rather than merely non-nil")
	assert.Nil(t, code, "no code is built for a client that no longer exists")

	// And nothing was written. The insert is what would bind a grant to a registration that is
	// gone, and its foreign key would refuse it anyway, with an error nobody could branch on.
	mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
	mockDB.AssertExpectations(t)
}

// issueTx is an opaque non-nil transaction for the cases below: every statement is matched on it,
// so a statement issued on the pool or on another transaction matches nothing.
var issueTx = &sql.Tx{}

const issueSid = "sid-issuing"

func issueCodeInput() *CreateCodeInput {
	return &CreateCodeInput{
		ClientId:          "test-client",
		UserId:            123,
		Scope:             "openid profile",
		RedirectURI:       "https://example.com/callback",
		AcrLevel:          models.AcrLevel1,
		AuthMethods:       "pwd",
		SessionIdentifier: issueSid,
	}
}

// TestIssueAuthCodeTx_TakesTheSessionRowBeforeTheInsert pins the transaction's shape, which is the
// whole of what the issuer contributes to the #139 property: one RunInTransaction, and inside it
// the acquisition, then the client lookup, then the insert, every one on that transaction. A mock
// recording the sequence is the only place this choice is observable: the acquisition is a
// single-row UPDATE of a column nothing reads. What two real transactions of this shape do to a
// termination is the data tier's, in TestIssuanceOrdering_AgainstTermination, which calls
// IssueAuthCode itself.
func TestIssueAuthCodeTx_TakesTheSessionRowBeforeTheInsert(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	var order []string
	note := func(what string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, what) }
	}
	mocks_data.ExpectRunInTransaction(mockDB, issueTx, func(edge string) { order = append(order, edge) })
	mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Run(note("session row")).Return(true, nil).Once()
	mockDB.On("GetClientByClientIdentifier", mock.Anything, issueTx, "test-client").Run(note("client")).
		Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
	mockDB.On("CreateCode", mock.Anything, issueTx, mock.AnythingOfType("*models.Code")).Run(note("insert")).
		Return(nil).Once()

	code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())

	require.NoError(t, err)
	require.NotNil(t, code)
	assert.Equal(t, issueSid, code.SessionIdentifier, "the code is bound to the session whose row was taken")
	assert.Equal(t, []string{"begin", "session row", "client", "insert", "commit"}, order,
		"the session row is taken first, and all three statements share the one transaction")
}

// TestIssueAuthCodeTx_RefusesOnlyAfterTheRollback holds the second SQLite self-deadlock hazard of
// this move: either refusal reaches the caller only after the transaction has rolled back. The
// caller answers a refusal through the server-side session store on a nil transaction, and on
// SQLite that is the one connection the transaction holds, so a refusal handed back while it was
// open would wait on itself (#139). Nothing is inserted on either row.
func TestIssueAuthCodeTx_RefusesOnlyAfterTheRollback(t *testing.T) {
	cases := []struct {
		name     string
		sentinel error
		setup    func(db *mocks_data.Database)
	}{
		{
			name:     "the session row is gone",
			sentinel: ErrIssuingSessionGone,
			setup: func(db *mocks_data.Database) {
				db.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(false, nil).Once()
			},
		},
		{
			name:     "the client is gone",
			sentinel: ErrIssuingClientGone,
			setup: func(db *mocks_data.Database) {
				db.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(true, nil).Once()
				db.On("GetClientByClientIdentifier", mock.Anything, issueTx, "test-client").Return(nil, nil).Once()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := mocks_data.NewDatabase(t)

			var order []string
			stub := mocks_data.ExpectRunInTransaction(mockDB, issueTx, func(edge string) { order = append(order, edge) })
			tc.setup(mockDB)

			code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())
			order = append(order, "returned")

			require.ErrorIs(t, err, tc.sentinel, "the caller branches on the sentinel, so it must survive the helper")
			assert.Nil(t, code)
			assert.ErrorIs(t, stub.BodyErr, tc.sentinel, "the body hands the sentinel to the helper, which rolls back")
			assert.Equal(t, []string{"begin", "rollback", "returned"}, order,
				"the sentinel reaches the caller only after the rollback")
			mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
		})
	}

	t.Run("a gone session is not looked up any further", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransaction(mockDB, issueTx)
		mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(false, nil).Once()

		_, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())

		require.ErrorIs(t, err, ErrIssuingSessionGone)
		assert.NotErrorIs(t, err, ErrIssuingClientGone, "the two refusals are distinct sentinels")
		mockDB.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})
}

// TestIssueAuthCode_RefusesANilTransaction holds the precondition at entry: on an autocommitted
// statement the acquisition releases the row before the insert, which is the whole of what it buys.
func TestIssueAuthCode_RefusesANilTransaction(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	code, err := NewCodeIssuer(mockDB).IssueAuthCode(context.Background(), nil, issueCodeInput())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a transaction")
	assert.Nil(t, code)
	assert.Empty(t, mockDB.Calls, "no statement may run without the transaction")
}

// TestIssueAuthCodeTx_FailuresAreNotRefusals: a statement that did not run has not established that
// the session is gone, so an acquisition failure comes back as itself, never as a sentinel that
// would restart a ceremony whose session is alive, and so does a commit the engine refuses.
func TestIssueAuthCodeTx_FailuresAreNotRefusals(t *testing.T) {
	boom := errors.New("connection refused")

	t.Run("the acquisition fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		stub := mocks_data.ExpectRunInTransaction(mockDB, issueTx)
		mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(false, boom).Once()

		code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())

		require.ErrorIs(t, err, boom)
		assert.NotErrorIs(t, err, ErrIssuingSessionGone)
		assert.Nil(t, code)
		assert.ErrorIs(t, stub.BodyErr, boom)
		mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("the commit fails", func(t *testing.T) {
		mockDB := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransactionThenFail(mockDB, issueTx, boom)
		mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(true, nil).Once()
		mockDB.On("GetClientByClientIdentifier", mock.Anything, issueTx, "test-client").
			Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
		mockDB.On("CreateCode", mock.Anything, issueTx, mock.AnythingOfType("*models.Code")).Return(nil).Once()

		code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())

		// The code row's fate is indeterminate, so no code is handed out to be delivered.
		require.ErrorIs(t, err, boom)
		assert.Nil(t, code)
	})
}

// TestIssueAuthCodeTx_ARerunReturnsTheCommittingAttemptsCode: a deadlock victim's body is rerun by
// RunInTransaction (#301), and the first attempt's code never committed, so the code returned must
// be the one the second attempt inserted.
func TestIssueAuthCodeTx_ARerunReturnsTheCommittingAttemptsCode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransactionRerun(mockDB, issueTx)
	mockDB.On("AcquireUserSessionRow", mock.Anything, issueTx, issueSid).Return(true, nil).Twice()
	mockDB.On("GetClientByClientIdentifier", mock.Anything, issueTx, "test-client").
		Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Twice()
	var inserted []*models.Code
	mockDB.On("CreateCode", mock.Anything, issueTx, mock.AnythingOfType("*models.Code")).
		Run(func(args mock.Arguments) { inserted = append(inserted, args.Get(2).(*models.Code)) }).
		Return(nil).Twice()

	code, err := NewCodeIssuer(mockDB).IssueAuthCodeTx(context.Background(), issueCodeInput())

	require.NoError(t, err)
	require.Len(t, inserted, 2)
	assert.Same(t, inserted[1], code, "the returned code is the committing attempt's")
	assert.NotEqual(t, inserted[0].Code, code.Code)
}
