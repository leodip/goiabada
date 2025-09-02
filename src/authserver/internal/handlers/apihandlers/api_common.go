package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
)

// Response types
type SuccessResponse struct {
	Success bool `json:"success"`
}

type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

type UsersSearchResponse struct {
	Users []models.User `json:"users"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Size  int           `json:"size"`
	Query string        `json:"query"`
}

type UserResponse struct {
	User *models.User `json:"user"`
}

// Request types for user CRUD operations
type CreateUserRequest struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	PasswordHash  string `json:"passwordHash,omitempty"`
	GivenName     string `json:"givenName,omitempty"`
	MiddleName    string `json:"middleName,omitempty"`
	FamilyName    string `json:"familyName,omitempty"`
}

type UpdateUserEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

type CreateUserAdminRequest struct {
	Email           string `json:"email"`
	EmailVerified   bool   `json:"emailVerified"`
	GivenName       string `json:"givenName"`
	MiddleName      string `json:"middleName"`
	FamilyName      string `json:"familyName"`
	SetPasswordType string `json:"setPasswordType"`    // "now" or "email"
	Password        string `json:"password,omitempty"` // if "now"
}

type CreateUserAdminResponse struct {
	User *models.User `json:"user"`
}

// Request types for user profile management
type UpdateUserProfileRequest struct {
	Username            string `json:"username"`
	GivenName           string `json:"givenName"`
	MiddleName          string `json:"middleName"`
	FamilyName          string `json:"familyName"`
	Nickname            string `json:"nickname"`
	Website             string `json:"website"`
	Gender              string `json:"gender"`
	DateOfBirth         string `json:"dateOfBirth"`
	ZoneInfoCountryName string `json:"zoneInfoCountryName"`
	ZoneInfo            string `json:"zoneInfo"`
	Locale              string `json:"locale"`
}

type UpdateUserAddressRequest struct {
	AddressLine1      string `json:"addressLine1"`
	AddressLine2      string `json:"addressLine2"`
	AddressLocality   string `json:"addressLocality"`
	AddressRegion     string `json:"addressRegion"`
	AddressPostalCode string `json:"addressPostalCode"`
	AddressCountry    string `json:"addressCountry"`
}

// Request/Response types for user attributes
type UserAttributesResponse struct {
	Attributes []models.UserAttribute `json:"attributes"`
}

type UserAttributeResponse struct {
	Attribute *models.UserAttribute `json:"attribute"`
}

type CreateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
	UserId               int64  `json:"userId"`
}

type UpdateUserAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

// Helper functions
func writeJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	errorResp := ErrorResponse{
		Error: struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}{
			Message: message,
			Code:    code,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}

func writeValidationError(w http.ResponseWriter, err error) {
	if valErr, ok := err.(*customerrors.ErrorDetail); ok {
		writeJSONError(w, valErr.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
	} else {
		writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
	}
}
