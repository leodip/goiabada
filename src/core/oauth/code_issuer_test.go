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

	code, err := codeIssuer.CreateAuthCode(input)

	assert.NoError(t, err)
	assert.NotNil(t, code)
	assert.Equal(t, testClient.Id, code.ClientId)
	assert.Equal(t, input.UserId, code.UserId)
	assert.Equal(t, input.ConsentedScope, code.Scope)
	assert.Equal(t, input.CodeChallenge, code.CodeChallenge)
	assert.Equal(t, input.CodeChallengeMethod, code.CodeChallengeMethod)
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

	code, err := codeIssuer.CreateAuthCode(input)

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

			code, err := codeIssuer.CreateAuthCode(input)

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

	code, err := codeIssuer.CreateAuthCode(input)

	assert.Error(t, err)
	assert.Nil(t, code)
	assert.Contains(t, err.Error(), "database error")

	mockDB.AssertExpectations(t)
}
