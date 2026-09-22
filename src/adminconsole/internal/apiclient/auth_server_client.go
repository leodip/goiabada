package apiclient

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
)

type ApiClient interface {
	SearchUsersPaginated(ctx context.Context, accessToken, query string, page, pageSize int) ([]api.UserResponse, int, error)
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	UpdateUserEnabled(ctx context.Context, accessToken string, userId int64, enabled bool) (*api.UserResponse, error)
	UpdateUserProfile(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
	UpdateUserAddress(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserAddressRequest) (*api.UserResponse, error)
	UpdateUserEmail(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserEmailRequest) (*api.UserResponse, error)
	UpdateUserPhone(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPhoneRequest) (*api.UserResponse, error)
	UpdateUserPassword(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPasswordRequest) (*api.UserResponse, error)
	UpdateUserOTP(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserOTPRequest) (*api.UserResponse, error)
	CreateUserAdmin(ctx context.Context, accessToken string, request *api.CreateUserAdminRequest) (*api.UserResponse, error)
	DeleteUser(ctx context.Context, accessToken string, userId int64) error
	GetUserProfilePicture(ctx context.Context, accessToken string, userId int64) (*ProfilePictureInfo, error)
	GetUserAttributesByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserAttributeResponse, error)
	GetUserAttributeById(ctx context.Context, accessToken string, attributeId int64) (*api.UserAttributeResponse, error)
	CreateUserAttribute(ctx context.Context, accessToken string, request *api.CreateUserAttributeRequest) (*api.UserAttributeResponse, error)
	UpdateUserAttribute(ctx context.Context, accessToken string, attributeId int64, request *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error)
	DeleteUserAttribute(ctx context.Context, accessToken string, attributeId int64) error
	GetUserSessionsByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserSessionDetailResponse, error)
	DeleteUserSessionById(ctx context.Context, accessToken string, sessionId int64) error
	GetClientSessionsByClientId(ctx context.Context, accessToken string, clientId int64, page, size int) (*api.GetClientSessionsResponse, error)
	GetAccountSessions(ctx context.Context, accessToken string) ([]api.UserSessionDetailResponse, error)
	DeleteAccountSession(ctx context.Context, accessToken string, sessionId int64) error
	GetUserConsents(ctx context.Context, accessToken string, userId int64) ([]api.UserConsentResponse, error)
	DeleteUserConsent(ctx context.Context, accessToken string, consentId int64) error
	GetAllGroups(ctx context.Context, accessToken string) ([]api.GroupResponse, error)
	CreateGroup(ctx context.Context, accessToken string, request *api.CreateGroupRequest) (*api.GroupResponse, error)
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
	UpdateGroup(ctx context.Context, accessToken string, groupId int64, request *api.UpdateGroupRequest) (*api.GroupResponse, error)
	DeleteGroup(ctx context.Context, accessToken string, groupId int64) error
	GetUserGroups(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.GroupResponse, error)
	UpdateUserGroups(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserGroupsRequest) (*api.UserResponse, []api.GroupResponse, error)
	GetGroupMembers(ctx context.Context, accessToken string, groupId int64, page, size int) ([]api.UserResponse, int, error)
	AddUserToGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error
	RemoveUserFromGroup(ctx context.Context, accessToken string, groupId int64, userId int64) error
	SearchUsersWithGroupAnnotation(ctx context.Context, accessToken, query string, groupId int64, page, size int) ([]api.UserWithGroupMembershipResponse, int, error)
	GetUserPermissions(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, []api.PermissionResponse, error)
	UpdateUserPermissions(ctx context.Context, accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error
	GetGroupPermissions(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, []api.PermissionResponse, error)
	UpdateGroupPermissions(ctx context.Context, accessToken string, groupId int64, request *api.UpdateGroupPermissionsRequest) error
	GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error)
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
	UpdateResource(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourceRequest) (*api.ResourceResponse, error)
	DeleteResource(ctx context.Context, accessToken string, resourceId int64) error
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
	UpdateResourcePermissions(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourcePermissionsRequest) error
	CreateResource(ctx context.Context, accessToken string, request *api.CreateResourceRequest) (*api.ResourceResponse, error)
	GetPhoneCountries(ctx context.Context, accessToken string) ([]api.PhoneCountryResponse, error)
	GetGroupAttributesByGroupId(ctx context.Context, accessToken string, groupId int64) ([]api.GroupAttributeResponse, error)
	GetGroupAttributeById(ctx context.Context, accessToken string, attributeId int64) (*api.GroupAttributeResponse, error)
	CreateGroupAttribute(ctx context.Context, accessToken string, request *api.CreateGroupAttributeRequest) (*api.GroupAttributeResponse, error)
	UpdateGroupAttribute(ctx context.Context, accessToken string, attributeId int64, request *api.UpdateGroupAttributeRequest) (*api.GroupAttributeResponse, error)
	DeleteGroupAttribute(ctx context.Context, accessToken string, attributeId int64) error
	GetAllClients(ctx context.Context, accessToken string) ([]api.ClientResponse, error)
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	CreateClient(ctx context.Context, accessToken string, request *api.CreateClientRequest) (*api.ClientResponse, error)
	UpdateClient(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientSettingsRequest) (*api.ClientResponse, error)
	UpdateClientAuthentication(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientAuthenticationRequest) (*api.ClientResponse, error)
	UpdateClientOAuth2Flows(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientOAuth2FlowsRequest) (*api.ClientResponse, error)
	DeleteClient(ctx context.Context, accessToken string, clientId int64) error
	UpdateClientRedirectURIs(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientRedirectURIsRequest) (*api.ClientResponse, error)
	UpdateClientWebOrigins(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientWebOriginsRequest) (*api.ClientResponse, error)
	GetClientPermissions(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error)
	UpdateClientPermissions(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientPermissionsRequest) error
	UpdateClientTokens(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientTokensRequest) (*api.ClientResponse, error)
	SearchGroupsWithPermissionAnnotation(ctx context.Context, accessToken string, permissionId int64, page, size int) ([]api.GroupWithPermissionResponse, int, error)
	// Users with permission
	GetUsersByPermission(ctx context.Context, accessToken string, permissionId int64, page, size int) ([]api.UserResponse, int, error)
	// Users search annotated with permission flag
	SearchUsersWithPermissionAnnotation(ctx context.Context, accessToken string, permissionId int64, query string, page, size int) ([]api.UserWithPermissionResponse, int, error)
	// Settings - General
	GetSettingsGeneral(ctx context.Context, accessToken string) (*api.SettingsGeneralResponse, error)
	UpdateSettingsGeneral(ctx context.Context, accessToken string, request *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error)
	// Settings - Email
	GetSettingsEmail(ctx context.Context, accessToken string) (*api.SettingsEmailResponse, error)
	UpdateSettingsEmail(ctx context.Context, accessToken string, request *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error)
	SendTestEmail(ctx context.Context, accessToken string, request *api.SendTestEmailRequest) error
	// Settings - Sessions
	GetSettingsSessions(ctx context.Context, accessToken string) (*api.SettingsSessionsResponse, error)
	UpdateSettingsSessions(ctx context.Context, accessToken string, request *api.UpdateSettingsSessionsRequest) (*api.SettingsSessionsResponse, error)
	// Settings - Tokens
	GetSettingsTokens(ctx context.Context, accessToken string) (*api.SettingsTokensResponse, error)
	UpdateSettingsTokens(ctx context.Context, accessToken string, request *api.UpdateSettingsTokensRequest) (*api.SettingsTokensResponse, error)
	// Settings - UI Theme
	GetSettingsUITheme(ctx context.Context, accessToken string) (*api.SettingsUIThemeResponse, error)
	UpdateSettingsUITheme(ctx context.Context, accessToken string, request *api.UpdateSettingsUIThemeRequest) (*api.SettingsUIThemeResponse, error)
	// Settings - Keys
	GetSettingsKeys(ctx context.Context, accessToken string) ([]api.SettingsSigningKeyResponse, error)
	RotateSettingsKeys(ctx context.Context, accessToken string) error
	DeleteSettingsKey(ctx context.Context, accessToken string, id int64) error
	// Settings - Audit Logs
	GetSettingsAuditLogs(ctx context.Context, accessToken string) (*api.SettingsAuditLogsResponse, error)
	UpdateSettingsAuditLogs(ctx context.Context, accessToken string, request *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error)
	GetAuditLogsPaginated(ctx context.Context, accessToken string, page, pageSize int, auditEvent string, requestId string) (*api.GetAuditLogsResponse, error)
	GetAuditEventTypes(ctx context.Context, accessToken string) (*api.GetAuditEventTypesResponse, error)
	// Account (self-service)
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountProfile(ctx context.Context, accessToken string, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
	UpdateAccountEmail(ctx context.Context, accessToken string, request *api.UpdateAccountEmailRequest) (*api.UserResponse, error)
	UpdateAccountPhone(ctx context.Context, accessToken string, request *api.UpdateAccountPhoneRequest) (*api.UserResponse, error)
	UpdateAccountAddress(ctx context.Context, accessToken string, request *api.UpdateUserAddressRequest) (*api.UserResponse, error)
	UpdateAccountPassword(ctx context.Context, accessToken string, request *api.UpdateAccountPasswordRequest) (*api.UserResponse, error)
	SendAccountEmailVerification(ctx context.Context, accessToken string) (*api.AccountEmailVerificationSendResponse, error)
	VerifyAccountEmail(ctx context.Context, accessToken string, request *api.VerifyAccountEmailRequest) (*api.UserResponse, error)
	// Account - OTP
	GetAccountOTPEnrollment(ctx context.Context, accessToken string) (*api.AccountOTPEnrollmentResponse, error)
	UpdateAccountOTP(ctx context.Context, accessToken string, request *api.UpdateAccountOTPRequest) (*api.UserResponse, error)
	// Account - Consents
	GetAccountConsents(ctx context.Context, accessToken string) ([]api.UserConsentResponse, error)
	RevokeAccountConsent(ctx context.Context, accessToken string, consentId int64) error
	CreateAccountLogoutRequest(ctx context.Context, accessToken string, request *api.AccountLogoutRequest) (*api.AccountLogoutFormPostResponse, *api.AccountLogoutRedirectResponse, error)
	// Account - Profile Picture
	GetAccountProfilePicture(ctx context.Context, accessToken string) (*ProfilePictureInfo, error)
	UploadAccountProfilePicture(ctx context.Context, accessToken string, pictureData []byte, filename string) (*ProfilePictureUploadResponse, error)
	DeleteAccountProfilePicture(ctx context.Context, accessToken string) error
	// Admin - User Profile Picture
	UploadUserProfilePicture(ctx context.Context, accessToken string, userId int64, pictureData []byte, filename string) (*ProfilePictureUploadResponse, error)
	DeleteUserProfilePicture(ctx context.Context, accessToken string, userId int64) error
	// Admin - Client Logo
	GetClientLogo(ctx context.Context, accessToken string, clientId int64) (*ClientLogoInfo, error)
	UploadClientLogo(ctx context.Context, accessToken string, clientId int64, logoData []byte, filename string) (*ClientLogoUploadResponse, error)
	DeleteClientLogo(ctx context.Context, accessToken string, clientId int64) error
}

type AuthServerClient struct {
	baseURL    string
	httpClient *http.Client
}

// APIError mirrors the flat ErrorResponse envelope returned by the
// admin/account API. Code and Message are populated from the wire's
// error_code and error_description fields respectively. Consumers route
// on StatusCode (4xx vs 5xx) rather than on an in-body category.
type APIError struct {
	Code       string         // "error_code" — stable identifier (UPPER_SNAKE for legacy, dotted lowercase for catalog-keyed)
	ErrorArgs  map[string]any // "error_args" — substitutions for the localized message
	Message    string         // "error_description" — rendered English text
	StatusCode int
}

func (e *APIError) Error() string {
	return e.Message
}

func parseAPIError(resp *http.Response, body []byte) *APIError {
	// Try to parse as JSON error response
	var errorResp api.ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err == nil && (errorResp.ErrorCode != "" || errorResp.ErrorDescription != "") {
		return &APIError{
			Code:       errorResp.ErrorCode,
			ErrorArgs:  errorResp.ErrorArgs,
			Message:    errorResp.ErrorDescription,
			StatusCode: resp.StatusCode,
		}
	}

	// Fall back to plain text error (for backward compatibility)
	return &APIError{
		Code:       "UNKNOWN_ERROR",
		Message:    string(body),
		StatusCode: resp.StatusCode,
	}
}

func NewAuthServerClient(authServerBaseURL string) *AuthServerClient {
	return &AuthServerClient{
		baseURL: authServerBaseURL,
		httpClient: &http.Client{
			Timeout: generalAPITimeout,
		},
	}
}
