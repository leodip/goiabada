package oauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"

	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/uuidutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// assertAuthCodeShape pins what CreateAuthCode emits: a canonical v4 with its hyphens stripped,
// followed by 96 characters of the security alphabet, 128 in all. The prefix is 32 hex digits
// because a UUID is what produces it, so re-inserting the hyphens has to give something the
// generator's own parser accepts. Nothing about the code's format may change while its consumers
// hash a fixed-width secret (#278): the library swap kept the bytes, and this says so.
func assertAuthCodeShape(t *testing.T, authCode string) {
	t.Helper()

	require.Len(t, authCode, 128)

	hyphenated := authCode[0:8] + "-" + authCode[8:12] + "-" + authCode[12:16] + "-" +
		authCode[16:20] + "-" + authCode[20:32]
	parsed, err := uuidutil.Parse(hyphenated)
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

	input := &CreateCodeInput{
		AuthContext: AuthContext{
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
			AcrLevel:            string(enums.AcrLevel1),
			AuthMethods:         "pwd",
		},
		SessionIdentifier: "session123",
	}

	code, err := codeIssuer.CreateAuthCode(nil, input)

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

			mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(
				&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)

			var persisted string
			mockDB.On("CreateCode", mock.Anything, mock.AnythingOfType("*models.Code")).Run(
				func(args mock.Arguments) {
					persisted = args.Get(1).(*models.Code).UserAgent
				}).Return(nil)

			_, err := codeIssuer.CreateAuthCode(nil, &CreateCodeInput{
				AuthContext: AuthContext{
					ClientId:       "test-client",
					UserId:         123,
					ConsentedScope: "openid",
					Scope:          "openid",
					RedirectURI:    "https://example.com/callback",
					UserAgent:      tc.userAgent,
					ResponseMode:   "query",
					IpAddress:      "127.0.0.1",
					AcrLevel:       string(enums.AcrLevel1),
					AuthMethods:    "pwd",
				},
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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

	input := &CreateCodeInput{
		AuthContext: AuthContext{
			ClientId: "test-client",
			UserId:   123,
			// ResponseMode is intentionally left empty
		},
		SessionIdentifier: "session123",
	}

	code, err := codeIssuer.CreateAuthCode(nil, input)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

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
				AuthContext: AuthContext{
					ClientId:       "test-client",
					UserId:         123,
					ConsentedScope: tc.consentedScope,
					Scope:          tc.scope,
				},
				SessionIdentifier: "session123",
			}

			code, err := codeIssuer.CreateAuthCode(nil, input)

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

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(testClient, nil)
	mockDB.On("CreateCode", mock.Anything, mock.AnythingOfType("*models.Code")).Return(errors.New("database error"))

	input := &CreateCodeInput{
		AuthContext: AuthContext{
			ClientId: "test-client",
			UserId:   123,
		},
		SessionIdentifier: "session123",
	}

	code, err := codeIssuer.CreateAuthCode(nil, input)

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
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "deleted-client").
		Return((*models.Client)(nil), nil)

	code, err := codeIssuer.CreateAuthCode(nil, &CreateCodeInput{
		AuthContext:       AuthContext{ClientId: "deleted-client", UserId: 123},
		SessionIdentifier: "session123",
	})

	require.ErrorIs(t, err, ErrIssuingClientGone,
		"the caller branches on this error, so it has to be identifiable rather than merely non-nil")
	assert.Nil(t, code, "no code is built for a client that no longer exists")

	// And nothing was written. The insert is what would bind a grant to a registration that is
	// gone, and its foreign key would refuse it anyway, with an error nobody could branch on.
	mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything)
	mockDB.AssertExpectations(t)
}
