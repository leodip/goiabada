package oauth

import (
	"errors"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/enums"

	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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
	assert.NotEmpty(t, code.Code)
	assert.NotEmpty(t, code.CodeHash)
	assert.WithinDuration(t, time.Now(), code.AuthenticatedAt, time.Second)

	mockDB.AssertExpectations(t)
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
