package apiclient

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

type ApiClient interface {
	SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error)
	GetUserById(accessToken string, userId int64) (*models.User, error)
	UpdateUserEnabled(accessToken string, userId int64, enabled bool) (*models.User, error)
	UpdateUserProfile(accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*models.User, error)
	UpdateUserAddress(accessToken string, userId int64, request *api.UpdateUserAddressRequest) (*models.User, error)
	UpdateUserEmail(accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*models.User, error)
	UpdateUserPhone(accessToken string, userId int64, request *api.UpdateUserPhoneRequest) (*models.User, error)
	UpdateUserPassword(accessToken string, userId int64, request *api.UpdateUserPasswordRequest) (*models.User, error)
	UpdateUserOTP(accessToken string, userId int64, request *api.UpdateUserOTPRequest) (*models.User, error)
	CreateUserAdmin(accessToken string, request *api.CreateUserAdminRequest) (*models.User, error)
	DeleteUser(accessToken string, userId int64) error
	GetUserAttributesByUserId(accessToken string, userId int64) ([]models.UserAttribute, error)
	GetUserAttributeById(accessToken string, attributeId int64) (*models.UserAttribute, error)
	CreateUserAttribute(accessToken string, request *api.CreateUserAttributeRequest) (*models.UserAttribute, error)
	UpdateUserAttribute(accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*models.UserAttribute, error)
	DeleteUserAttribute(accessToken string, attributeId int64) error
	GetUserSessionsByUserId(accessToken string, userId int64) ([]api.EnhancedUserSessionResponse, error)
    DeleteUserSessionById(accessToken string, sessionId int64) error
    GetClientSessionsByClientId(accessToken string, clientId int64, page, size int) ([]api.EnhancedUserSessionResponse, error)
	GetUserSession(accessToken string, sessionIdentifier string) (*models.UserSession, error)
	UpdateUserSession(accessToken string, sessionIdentifier string, request *api.UpdateUserSessionRequest) (*models.UserSession, error)
	GetUserConsents(accessToken string, userId int64) ([]models.UserConsent, error)
	DeleteUserConsent(accessToken string, consentId int64) error
	GetAllGroups(accessToken string) ([]models.Group, error)
	CreateGroup(accessToken string, request *api.CreateGroupRequest) (*models.Group, error)
	GetGroupById(accessToken string, groupId int64) (*models.Group, int, error)
	UpdateGroup(accessToken string, groupId int64, request *api.UpdateGroupRequest) (*models.Group, error)
	DeleteGroup(accessToken string, groupId int64) error
	GetUserGroups(accessToken string, userId int64) (*models.User, []models.Group, error)
	UpdateUserGroups(accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*models.User, []models.Group, error)
	GetGroupMembers(accessToken string, groupId int64, page, size int) ([]models.User, int, error)
	AddUserToGroup(accessToken string, groupId int64, userId int64) error
	RemoveUserFromGroup(accessToken string, groupId int64, userId int64) error
	SearchUsersWithGroupAnnotation(accessToken, query string, groupId int64, page, size int) ([]api.UserWithGroupMembershipResponse, int, error)
	GetUserPermissions(accessToken string, userId int64) (*models.User, []models.Permission, error)
	UpdateUserPermissions(accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error
	GetGroupPermissions(accessToken string, groupId int64) (*models.Group, []models.Permission, error)
	UpdateGroupPermissions(accessToken string, groupId int64, request *api.UpdateGroupPermissionsRequest) error
    GetAllResources(accessToken string) ([]models.Resource, error)
    GetResourceById(accessToken string, resourceId int64) (*models.Resource, error)
    UpdateResource(accessToken string, resourceId int64, request *api.UpdateResourceRequest) (*models.Resource, error)
    DeleteResource(accessToken string, resourceId int64) error
    GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error)
    UpdateResourcePermissions(accessToken string, resourceId int64, request *api.UpdateResourcePermissionsRequest) error
    CreateResource(accessToken string, request *api.CreateResourceRequest) (*models.Resource, error)
    GetPhoneCountries(accessToken string) ([]api.PhoneCountryResponse, error)
    GetGroupAttributesByGroupId(accessToken string, groupId int64) ([]models.GroupAttribute, error)
    GetGroupAttributeById(accessToken string, attributeId int64) (*models.GroupAttribute, error)
    CreateGroupAttribute(accessToken string, request *api.CreateGroupAttributeRequest) (*models.GroupAttribute, error)
    UpdateGroupAttribute(accessToken string, attributeId int64, request *api.UpdateGroupAttributeRequest) (*models.GroupAttribute, error)
    DeleteGroupAttribute(accessToken string, attributeId int64) error
    GetAllClients(accessToken string) ([]api.ClientResponse, error)
    GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error)
    CreateClient(accessToken string, request *api.CreateClientRequest) (*api.ClientResponse, error)
    UpdateClient(accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error)
    UpdateClientAuthentication(accessToken string, clientId int64, request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error)
    UpdateClientOAuth2Flows(accessToken string, clientId int64, request *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error)
    DeleteClient(accessToken string, clientId int64) error
    UpdateClientRedirectURIs(accessToken string, clientId int64, request *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error)
    UpdateClientWebOrigins(accessToken string, clientId int64, request *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error)
    GetClientPermissions(accessToken string, clientId int64) (*api.ClientResponse, []models.Permission, error)
    UpdateClientPermissions(accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error
    UpdateClientTokens(accessToken string, clientId int64, request *api.UpdateClientTokensRequest) (*api.ClientResponse, error)
    SearchGroupsWithPermissionAnnotation(accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error)
    // Users with permission
    GetUsersByPermission(accessToken string, permissionId int64, page, size int) ([]models.User, int, error)
    // Users search annotated with permission flag
    SearchUsersWithPermissionAnnotation(accessToken string, permissionId int64, query string, page, size int) ([]api.UserWithPermissionResponse, int, error)
    // Settings - General
    GetSettingsGeneral(accessToken string) (*api.SettingsGeneralResponse, error)
    UpdateSettingsGeneral(accessToken string, request *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error)
}

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
}

type APIError struct {
	Message    string
	Code       string
	StatusCode int
}

func (e *APIError) Error() string {
	return e.Message
}

func parseAPIError(resp *http.Response, body []byte) *APIError {
	// Try to parse as JSON error response
	var errorResp api.ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil {
		return &APIError{
			Message:    errorResp.Error.Message,
			Code:       errorResp.Error.Code,
			StatusCode: resp.StatusCode,
		}
	}

	// Fall back to plain text error (for backward compatibility)
	return &APIError{
		Message:    string(body),
		Code:       "UNKNOWN_ERROR",
		StatusCode: resp.StatusCode,
	}
}

func NewAuthServerClient() *AuthServerClient {
	authServerBaseURL := config.GetAuthServer().BaseURL

	return &AuthServerClient{
		baseURL:    authServerBaseURL,
		httpClient: &http.Client{},
	}
}
