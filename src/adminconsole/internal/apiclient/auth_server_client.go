package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
	GetUserPermissions(accessToken string, userId int64) (*models.User, []models.Permission, error)
	UpdateUserPermissions(accessToken string, userId int64, request *api.UpdateUserPermissionsRequest) error
	GetAllResources(accessToken string) ([]models.Resource, error)
	GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error)
	GetPhoneCountries(accessToken string) ([]api.PhoneCountryResponse, error)
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

func (c *AuthServerClient) debugLog(method, url string, reqBody []byte, resp *http.Response, respBody []byte, duration time.Duration, err error) {
	if !config.GetAdminConsole().DebugAPIRequests {
		return
	}

	// Sanitize auth header for logging
	authHeader := "None"
	if resp != nil && resp.Request != nil {
		if auth := resp.Request.Header.Get("Authorization"); auth != "" {
			if strings.HasPrefix(auth, "Bearer ") {
				authHeader = "Bearer ***"
			} else {
				authHeader = "*** (unknown type)"
			}
		}
	}

	// Log request
	slog.Info(fmt.Sprintf("[DEBUG API] → %s %s", method, url))
	slog.Info(fmt.Sprintf("[DEBUG API]   Headers: Authorization: %s", authHeader))

	// Log request body (if applicable)
	if len(reqBody) > 0 {
		var prettyReq bytes.Buffer
		if json.Indent(&prettyReq, reqBody, "[DEBUG API]   ", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Request Body:\n%s", prettyReq.String()))
		}
	}

	// Log response
	if resp != nil {
		if err != nil {
			slog.Info(fmt.Sprintf("[DEBUG API] ← ERROR %s (%s)", resp.Status, duration))
			slog.Info(fmt.Sprintf("[DEBUG API]   Error: %v", err))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API] ← %d %s (%s)", resp.StatusCode, resp.Status, duration))
		}
	} else if err != nil {
		slog.Info(fmt.Sprintf("[DEBUG API] ← ERROR (%s)", duration))
		slog.Info(fmt.Sprintf("[DEBUG API]   Error: %v", err))
	}

	// Log response body
	if len(respBody) > 0 {
		var prettyResp bytes.Buffer
		if json.Indent(&prettyResp, respBody, "[DEBUG API]   ", "  ") == nil {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body:\n%s", prettyResp.String()))
		} else {
			slog.Info(fmt.Sprintf("[DEBUG API]   Response Body: %s", string(respBody)))
		}
	}

	slog.Info("[DEBUG API]") // Empty line for separation
}

func NewAuthServerClient() *AuthServerClient {
	authServerBaseURL := config.GetAuthServer().BaseURL

	return &AuthServerClient{
		baseURL:    authServerBaseURL,
		httpClient: &http.Client{},
	}
}