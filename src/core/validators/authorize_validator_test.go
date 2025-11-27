package validators

import (
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

			err := validator.ValidateScopes(tt.scope)

			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				customErr := err.(*customerrors.ErrorDetail)
				assert.Equal(t, tt.expectedError, customErr.GetDescription())
			}
		})
	}
}

func TestValidateClientAndRedirectURI_MissingClientId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateClientAndRedirectURIInput{ClientId: "", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The client_id parameter is missing.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_NonExistentClient(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "non-existent").Return(nil, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "non-existent", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_DisabledClient(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "disabled-client").Return(&models.Client{Enabled: false}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "disabled-client", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid client_id parameter. The client is disabled.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_ClientWithoutAuthorizationCodeFlow(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "no-auth-code-client").Return(&models.Client{Enabled: true, AuthorizationCodeEnabled: false}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "no-auth-code-client", RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid client_id parameter. The client does not support the authorization code flow.", customErr.GetDescription())
}

func TestValidateClientAndRedirectURI_MissingRedirectURI(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "valid-client").Return(&models.Client{Enabled: true, AuthorizationCodeEnabled: true}, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: "valid-client", RedirectURI: ""}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
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
	err := validator.ValidateClientAndRedirectURI(&input)

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
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect URI registered.", customErr.GetDescription())
}

func TestValidateRequest_InvalidResponseType(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:        "invalid_type",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "valid_challenge",
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token.", customErr.GetDescription())
}

func TestValidateRequest_ImplicitFlowNotEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "token",
		ImplicitGrantEnabled: false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Contains(t, customErr.GetDescription(), "The client is not authorized to use the implicit grant type.")
	assert.Contains(t, customErr.GetDescription(), "admin console")
}

func TestValidateRequest_InvalidCodeChallengeMethod(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional but provided, invalid method should be rejected
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "plain",
		CodeChallenge:       "valid_challenge",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid code_challenge_method. Only 'S256' is supported.", customErr.GetDescription())
}

func TestValidateRequest_InvalidCodeChallengeMethod_PKCERequired(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is required, missing or invalid method should show different message
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "plain",
		CodeChallenge:       "valid_challenge",
		PKCERequired:        true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "PKCE is required. Ensure code_challenge_method is set to 'S256'.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooShort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional but provided, invalid challenge length should be rejected
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "short",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooShort_PKCERequired(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is required, invalid challenge length shows different message
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "short",
		PKCERequired:        true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooLong(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional but provided, invalid challenge length should be rejected
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       string(make([]byte, 129)),
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallengeTooLong_PKCERequired(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is required, invalid challenge length shows different message
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       string(make([]byte, 129)),
		PKCERequired:        true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
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
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
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
	err := validator.ValidateRequest(&input)

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
	err := validator.ValidateScopes(scope)

	assert.NoError(t, err)
}

func TestValidateScopes_WithLeadingAndTrailingSpaces(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
	mockDB.On("GetResourceByResourceIdentifier", mock.Anything, "resource1").Return(&models.Resource{Id: 1}, nil)
	mockDB.On("GetPermissionsByResourceId", mock.Anything, int64(1)).Return([]models.Permission{{PermissionIdentifier: "permission1"}}, nil)

	scope := "  openid  profile  resource1:permission1  "
	err := validator.ValidateScopes(scope)

	assert.NoError(t, err)
}

func TestValidateClientAndRedirectURI_ExtremelyLongClientId(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	longClientId := strings.Repeat("a", 1000)
	mockDB.On("GetClientByClientIdentifier", mock.Anything, longClientId).Return(nil, nil)

	input := ValidateClientAndRedirectURIInput{ClientId: longClientId, RedirectURI: "http://example.com"}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
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
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
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
	err := validator.ValidateRequest(&input)

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
	err := validator.ValidateScopes(scope)

	assert.NoError(t, err)
}

// ============================================================================
// PKCE Optional Tests - Testing the optional PKCE behavior
// ============================================================================

func TestValidateRequest_PKCEOptional_NoPKCEParams_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional and no PKCE params provided, should succeed
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "",
		CodeChallenge:       "",
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_PKCEOptional_ValidPKCEParams_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional and valid PKCE params provided, should succeed
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_PKCEOptional_OnlyCodeChallenge_Fails(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional but only code_challenge is provided (partial PKCE),
	// should fail because pkceProvided is true but method is invalid
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "Invalid code_challenge_method. Only 'S256' is supported.", customErr.GetDescription())
}

func TestValidateRequest_PKCEOptional_OnlyCodeChallengeMethod_Fails(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is optional but only code_challenge_method is provided (partial PKCE),
	// should fail because pkceProvided is true but challenge is missing/invalid
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "",
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_PKCERequired_NoPKCEParams_Fails(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is required and no PKCE params provided, should fail
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "",
		CodeChallenge:       "",
		ResponseMode:        "query",
		PKCERequired:        true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "PKCE is required. Ensure code_challenge_method is set to 'S256'.", customErr.GetDescription())
}

func TestValidateRequest_PKCERequired_ValidPKCEParams_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// When PKCE is required and valid PKCE params provided, should succeed
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
		ResponseMode:        "query",
		PKCERequired:        true,
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_CodeChallenge_Exactly43Chars_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Boundary test: exactly 43 characters should be valid
	codeChallenge := strings.Repeat("a", 43)
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       codeChallenge,
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_CodeChallenge_Exactly42Chars_Fails(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Boundary test: 42 characters should be invalid (just under minimum)
	codeChallenge := strings.Repeat("a", 42)
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       codeChallenge,
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_CodeChallenge_Exactly128Chars_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Boundary test: exactly 128 characters should be valid
	codeChallenge := strings.Repeat("a", 128)
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       codeChallenge,
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_CodeChallenge_Exactly129Chars_Fails(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Boundary test: 129 characters should be invalid (just over maximum)
	codeChallenge := strings.Repeat("a", 129)
	input := ValidateRequestInput{
		ResponseType:        "code",
		CodeChallengeMethod: "S256",
		CodeChallenge:       codeChallenge,
		ResponseMode:        "query",
		PKCERequired:        false,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The code_challenge parameter is incorrect. It should be 43 to 128 characters long.", customErr.GetDescription())
}

func TestValidateRequest_ValidResponseModes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	validModes := []string{"query", "fragment", "form_post"}

	for _, mode := range validModes {
		t.Run(fmt.Sprintf("ResponseMode_%s", mode), func(t *testing.T) {
			input := ValidateRequestInput{
				ResponseType:        "code",
				CodeChallengeMethod: "S256",
				CodeChallenge:       "a_valid_code_challenge_that_meets_length_requirements",
				ResponseMode:        mode,
				PKCERequired:        false,
			}
			err := validator.ValidateRequest(&input)

			assert.NoError(t, err)
		})
	}
}

// ============================================================================
// Implicit Flow Tests
// ============================================================================

func TestValidateRequest_ImplicitFlow_ResponseTypeToken_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_ResponseTypeIdToken_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "test-nonce-123",
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_ResponseTypeIdTokenToken_Success(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "test-nonce-123",
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_ResponseTypeTokenIdToken_OrderIndependent(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Test that "token id_token" works the same as "id_token token"
	input := ValidateRequestInput{
		ResponseType:         "token id_token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "test-nonce-123",
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_IdToken_RequiresOpenIdScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token",
		ImplicitGrantEnabled: true,
		Scope:                "profile email", // Missing "openid" scope
		Nonce:                "test-nonce-123",
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "The 'openid' scope is required when requesting an id_token.", customErr.GetDescription())
}

func TestValidateRequest_ImplicitFlow_IdTokenToken_RequiresOpenIdScope(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token token",
		ImplicitGrantEnabled: true,
		Scope:                "profile", // Missing "openid" scope
		Nonce:                "test-nonce-123",
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The 'openid' scope is required when requesting an id_token.", customErr.GetDescription())
}

func TestValidateRequest_ImplicitFlow_IdToken_RequiresNonce(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "", // Missing nonce
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "The 'nonce' parameter is required for implicit flow when requesting an id_token.", customErr.GetDescription())
}

func TestValidateRequest_ImplicitFlow_IdTokenToken_RequiresNonce(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType:         "id_token token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "", // Missing nonce
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "The 'nonce' parameter is required for implicit flow when requesting an id_token.", customErr.GetDescription())
}

func TestValidateRequest_ImplicitFlow_Token_DoesNotRequireNonce(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// response_type=token does NOT require nonce (only id_token does)
	input := ValidateRequestInput{
		ResponseType:         "token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		Nonce:                "", // No nonce - should still work for token-only
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_NoPKCERequired(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// Implicit flow should NOT require PKCE (PKCE is for authorization code flow only)
	input := ValidateRequestInput{
		ResponseType:         "token",
		ImplicitGrantEnabled: true,
		Scope:                "openid",
		PKCERequired:         true, // Even if PKCE is "required", it shouldn't affect implicit flow
		// No CodeChallenge or CodeChallengeMethod provided
	}
	err := validator.ValidateRequest(&input)

	assert.NoError(t, err)
}

func TestValidateRequest_ImplicitFlow_ClientNotEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	testCases := []struct {
		name         string
		responseType string
	}{
		{"token", "token"},
		{"id_token", "id_token"},
		{"id_token token", "id_token token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := ValidateRequestInput{
				ResponseType:         tc.responseType,
				ImplicitGrantEnabled: false,
				Scope:                "openid",
				Nonce:                "test-nonce",
			}
			err := validator.ValidateRequest(&input)

			assert.Error(t, err)
			customErr := err.(*customerrors.ErrorDetail)
			assert.Equal(t, "unauthorized_client", customErr.GetCode())
			assert.Contains(t, customErr.GetDescription(), "The client is not authorized to use the implicit grant type.")
			assert.Contains(t, customErr.GetDescription(), "admin console")
		})
	}
}

func TestValidateRequest_UnsupportedResponseTypeCombination_CodeToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// "code token" is a hybrid flow - not supported
	input := ValidateRequestInput{
		ResponseType:         "code token",
		ImplicitGrantEnabled: true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "unsupported_response_type", customErr.GetCode())
	assert.Contains(t, customErr.GetDescription(), "Supported values: code, token, id_token, id_token token")
}

func TestValidateRequest_UnsupportedResponseTypeCombination_CodeIdToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// "code id_token" is a hybrid flow - not supported
	input := ValidateRequestInput{
		ResponseType:         "code id_token",
		ImplicitGrantEnabled: true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "unsupported_response_type", customErr.GetCode())
}

func TestValidateRequest_UnsupportedResponseTypeCombination_CodeIdTokenToken(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	// "code id_token token" is a hybrid flow - not supported
	input := ValidateRequestInput{
		ResponseType:         "code id_token token",
		ImplicitGrantEnabled: true,
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "unsupported_response_type", customErr.GetCode())
}

func TestValidateRequest_MissingResponseType(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	input := ValidateRequestInput{
		ResponseType: "",
	}
	err := validator.ValidateRequest(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Equal(t, "invalid_request", customErr.GetCode())
	assert.Equal(t, "The response_type parameter is missing.", customErr.GetDescription())
}

func TestValidateRequest_AllSupportedResponseTypes(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	testCases := []struct {
		name           string
		responseType   string
		isImplicitFlow bool
		requiresNonce  bool
	}{
		{"code", "code", false, false},
		{"token", "token", true, false},
		{"id_token", "id_token", true, true},
		{"id_token token", "id_token token", true, true},
		{"token id_token", "token id_token", true, true}, // Order independence
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := ValidateRequestInput{
				ResponseType:         tc.responseType,
				ImplicitGrantEnabled: true,
				Scope:                "openid",
				Nonce:                "test-nonce",
			}
			if !tc.isImplicitFlow {
				// For code flow, provide PKCE
				input.CodeChallengeMethod = "S256"
				input.CodeChallenge = "a_valid_code_challenge_that_meets_length_requirements"
			}

			err := validator.ValidateRequest(&input)
			assert.NoError(t, err, "response_type=%s should be valid", tc.responseType)
		})
	}
}

func TestValidateClientAndRedirectURI_ImplicitFlow_DoesNotRequireAuthCodeEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "implicit-only-client",
		Enabled:                  true,
		AuthorizationCodeEnabled: false, // Auth code disabled
		RedirectURIs: []models.RedirectURI{
			{ClientId: 1, URI: "https://example.com/callback"},
		},
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "implicit-only-client").Return(client, nil)
	mockDB.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil)

	// For implicit flow, AuthorizationCodeEnabled is not required
	input := ValidateClientAndRedirectURIInput{
		ClientId:     "implicit-only-client",
		RedirectURI:  "https://example.com/callback",
		ResponseType: "token", // Implicit flow
	}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.NoError(t, err)
	mockDB.AssertExpectations(t)
}

func TestValidateClientAndRedirectURI_AuthCodeFlow_RequiresAuthCodeEnabled(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewAuthorizeValidator(mockDB)

	client := &models.Client{
		Id:                       1,
		ClientIdentifier:         "implicit-only-client",
		Enabled:                  true,
		AuthorizationCodeEnabled: false, // Auth code disabled
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, "implicit-only-client").Return(client, nil)

	// For auth code flow, AuthorizationCodeEnabled IS required
	input := ValidateClientAndRedirectURIInput{
		ClientId:     "implicit-only-client",
		RedirectURI:  "https://example.com/callback",
		ResponseType: "code", // Authorization code flow
	}
	err := validator.ValidateClientAndRedirectURI(&input)

	assert.Error(t, err)
	customErr := err.(*customerrors.ErrorDetail)
	assert.Contains(t, customErr.GetDescription(), "does not support the authorization code flow")
	mockDB.AssertExpectations(t)
}
