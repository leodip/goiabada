package validators

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateScopes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	tests := []struct {
		name          string
		scope         string
		mockSetup     func()
		expectedError string
	}{
		{
			name:          "Empty scope",
			scope:         "",
			expectedError: "The 'scope' parameter is missing. Ensure to include one or more scopes, separated by spaces. Scopes can be an OpenID Connect scope, a resource:permission scope, or a combination of both.",
		},
		{
			name:          "Valid OpenID Connect scope",
			scope:         "openid profile email",
			expectedError: "",
		},
		{
			name:          "Valid offline_access scope",
			scope:         "offline_access",
			expectedError: "",
		},
		{
			name:  "Invalid userinfo scope",
			scope: constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
			expectedError: "The 'authserver:userinfo' scope is automatically included in the access token when an OpenID Connect scope is present. " +
				"There's no need to request it explicitly. Please remove it from your request.",
		},
		{
			name:          "Invalid scope format",
			scope:         "invalid:scope:format",
			expectedError: "Invalid scope format: 'invalid:scope:format'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			name:  "Valid resource:permission scope",
			scope: "resource1:permission1",
			mockSetup: func() {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
				mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "permission1"}}, nil)
			},
			expectedError: "",
		},
		{
			name:  "Invalid resource",
			scope: "invalid-resource:permission",
			mockSetup: func() {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "invalid-resource").Return(nil, nil)
			},
			expectedError: "Invalid scope: 'invalid-resource:permission'. Could not find a resource with identifier 'invalid-resource'.",
		},
		{
			name:  "Invalid permission",
			scope: "resource1:invalid-permission",
			mockSetup: func() {
				mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
				mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "valid-permission"}}, nil)
			},
			expectedError: "Scope 'resource1:invalid-permission' is invalid. The resource identified by 'resource1' does not have a permission with identifier 'invalid-permission'.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockSetup != nil {
				tt.mockSetup()
			}

			err := validator.ValidateScopes(context.Background(), tt.scope)

			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr, ok := err.(*customerrors.ErrorDetail)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedError, customErr.GetDescription())
			}
		})
	}
}

func TestValidateClientAndRedirectURI_MissingClientId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateClientAndRedirectURIInput{ClientId: "", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "The client_id parameter is missing.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_NonExistentClient(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "non-existent").Return(nil, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "non-existent", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_DisabledClient(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "disabled-client").Return(&models.Client{Enabled: false}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "disabled-client", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid client_id parameter. The client is disabled.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_ClientWithoutAuthorizationCodeFlow(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "no-auth-code-client").Return(&models.Client{Enabled: true, AuthorizationCodeEnabled: false}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "no-auth-code-client", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid client_id parameter. The client does not support the authorization code flow.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_MissingRedirectURI(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(&models.Client{Enabled: true, AuthorizationCodeEnabled: true}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "valid-client", RedirectURI: ""}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "The redirect_uri parameter is missing.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_ValidClientAndRedirectURI(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	client := &models.Client{
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.RedirectURIs = []models.RedirectURI{{URI: "http://example.com"}}
	}).Return(nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "valid-client", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.NoError(t, err)
}

func TestValidateClientAndRedirectURI_InvalidRedirectURI(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	client := &models.Client{
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.RedirectURIs = []models.RedirectURI{{URI: "http://example.com"}}
	}).Return(nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "valid-client", RedirectURI: "http://invalid.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect URI registered.", customErr.GetDescription())
}

func TestValidateRequest_InvalidResponseType(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "token",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "valid_challenge",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Ensure response_type is set to 'code' as it's the only supported value.", customErr.GetDescription())
}

func TestValidateRequest_InvalidCodeChallengeMethod(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "plain",
		CodeChallenge:       "valid_challenge",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooShort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "short",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooLong(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       string(make([]byte, 129)),
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_InvalidResponseMode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "invalid_mode",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid response_mode parameter. Supported values are: query, fragment, form_post.", customErr.GetDescription())
}

func TestValidateRequest_ValidInput(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "query",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.NoError(t, err)
}

func TestValidateScopes_MultipleScopesInSingleRequest(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "permission1"}}, nil)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource2").Return(&models.Resource{Id: 2}, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(2)).Return([]models.Permission{{PermissionIdentifier: "permission2"}}, nil)

	scope := "openid profile resource1:permission1 resource2:permission2"
	err := validator.ValidateScopes(context.Background(), scope)

	assert.NoError(t, err)
}

func TestValidateScopes_WithLeadingAndTrailingSpaces(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "permission1"}}, nil)

	scope := "  openid  profile  resource1:permission1  "
	err := validator.ValidateScopes(context.Background(), scope)

	assert.NoError(t, err)
}

func TestValidateClientAndRedirectURI_ExtremelyLongClientId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	longClientId := strings.Repeat("a", 1000)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, longClientId).Return(nil, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: longClientId, RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_ExtremelyLongRedirectURI(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	client := &models.Client{
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
		client := args.Get(1).(*models.Client)
		client.RedirectURIs = []models.RedirectURI{{URI: "http://example.com"}}
	}).Return(nil)

	longRedirectURI := "http://example.com/" + strings.Repeat("a", 2000)
	input := ValidateClientAndRedirectURIInput{ClientId: "valid-client", RedirectURI: longRedirectURI}
	err := validator.ValidateClientAndRedirectURI(context.Background(), &input)

	assert.Error(t, err)
	customErr, ok := err.(*customerrors.ErrorDetail)
	assert.True(t, ok)
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect URI registered.", customErr.GetDescription())
}

func TestValidateRequest_EmptyResponseMode(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "",
	}
	err := validator.ValidateRequest(context.Background(), &input)

	assert.NoError(t, err)
}

func TestValidateScopes_MaximumNumberOfScopes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Assuming a theoretical maximum of 100 scopes
	scopes := make([]string, 100)
	for i := 0; i < 100; i++ {
		resourceName := fmt.Sprintf("resource%d", i)
		permissionName := fmt.Sprintf("permission%d", i)
		scopes[i] = fmt.Sprintf("%s:%s", resourceName, permissionName)

		mockDB.On("GetResourceByResourceIdentifier", mock.Anything, resourceName).Return(&models.Resource{Id: int64(i)}, nil)
		mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(i)).Return([]models.Permission{{PermissionIdentifier: permissionName}}, nil)
	}

	scope := strings.Join(scopes, " ")
	err := validator.ValidateScopes(context.Background(), scope)

	assert.NoError(t, err)
}
