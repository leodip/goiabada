package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/user"
	"github.com/leodip/goiabada/core/validators"
)

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

func HandleAPIUsersSearchGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware
		// Token is available in context if needed via GetValidatedToken(r)

		// Parse query parameters
		pageStr := r.URL.Query().Get("page")
		sizeStr := r.URL.Query().Get("size")
		query := r.URL.Query().Get("query")

		// Default values
		page := 1
		size := 10

		// Parse page
		if pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		// Parse size with reasonable limits
		if sizeStr != "" {
			if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 200 {
				size = s
			}
		}

		// Search users
		users, total, err := database.SearchUsersPaginated(nil, query, page, size)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := UsersSearchResponse{
			Users: users,
			Total: total,
			Page:  page,
			Size:  size,
			Query: query,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserGet - GET /api/v1/admin/users/{id}
func HandleAPIUserGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := UserResponse{
			User: user,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserCreatePost - POST /api/v1/admin/users/create
func HandleAPIUserCreatePost(
	httpHelper handlers.HttpHelper,
	database data.Database,
	userCreator handlers.UserCreator,
	emailValidator *validators.EmailValidator,
	profileValidator *validators.ProfileValidator,
	passwordValidator *validators.PasswordValidator,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
	emailSender handlers.EmailSender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Decode the request body
		var req CreateUserAdminRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get settings from context
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Validate required fields
		if req.Email == "" {
			writeJSONError(w, "Email is required", "EMAIL_REQUIRED", http.StatusBadRequest)
			return
		}

		// Normalize and validate email
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))

		// Email format validation
		err := emailValidator.ValidateEmailAddress(req.Email)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Email length validation
		if len(req.Email) > 60 {
			writeJSONError(w, "The email address cannot exceed a maximum length of 60 characters", "EMAIL_TOO_LONG", http.StatusBadRequest)
			return
		}

		// Check for duplicate email
		existingUser, err := database.GetUserByEmail(nil, req.Email)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			writeJSONError(w, "This email address is already registered", "EMAIL_ALREADY_EXISTS", http.StatusConflict)
			return
		}

		// Name validations
		err = profileValidator.ValidateName(req.GivenName, "given name")
		if err != nil {
			writeValidationError(w, err)
			return
		}

		err = profileValidator.ValidateName(req.MiddleName, "middle name")
		if err != nil {
			writeValidationError(w, err)
			return
		}

		err = profileValidator.ValidateName(req.FamilyName, "family name")
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Password handling
		var passwordHash string
		if req.SetPasswordType == "now" || !settings.SMTPEnabled {
			if req.Password == "" {
				writeJSONError(w, "Password is required", "PASSWORD_REQUIRED", http.StatusBadRequest)
				return
			}

			// Validate password
			err = passwordValidator.ValidatePassword(r.Context(), req.Password)
			if err != nil {
				writeValidationError(w, err)
				return
			}

			// Hash password
			passwordHash, err = hashutil.HashPassword(req.Password)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
		}

		// Sanitize names
		req.GivenName = strings.TrimSpace(req.GivenName)
		req.MiddleName = strings.TrimSpace(req.MiddleName)
		req.FamilyName = strings.TrimSpace(req.FamilyName)

		// Create user using UserCreator
		createdUser, err := userCreator.CreateUser(&user.CreateUserInput{
			Email:         req.Email,
			EmailVerified: req.EmailVerified,
			PasswordHash:  passwordHash,
			GivenName:     req.GivenName,
			MiddleName:    req.MiddleName,
			FamilyName:    req.FamilyName,
		})
		if err != nil {
			// Check if it's a duplicate email error from UserCreator
			if strings.Contains(err.Error(), "email") && strings.Contains(strings.ToLower(err.Error()), "already") {
				writeJSONError(w, "This email address is already registered", "EMAIL_ALREADY_EXISTS", http.StatusConflict)
			} else {
				writeJSONError(w, "Failed to create user", "USER_CREATION_FAILED", http.StatusInternalServerError)
			}
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditCreatedUser, map[string]interface{}{
			"email":        createdUser.Email,
			"loggedInUser": loggedInUser,
		})

		// Handle email flow if needed
		if settings.SMTPEnabled && req.SetPasswordType == "email" {
			verificationCode := stringutil.GenerateSecurityRandomString(32)
			verificationCodeEncrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// Update user with reset code
			createdUser.ForgotPasswordCodeEncrypted = verificationCodeEncrypted
			utcNow := time.Now().UTC()
			createdUser.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: utcNow, Valid: true}
			err = database.UpdateUser(nil, createdUser)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// Prepare and send email
			name := createdUser.GetFullName()
			if len(name) == 0 {
				name = createdUser.Email
			}

			bind := map[string]interface{}{
				"name": name,
				"link": config.GetAuthServer().BaseURL + "/reset-password?email=" + createdUser.Email + "&code=" + verificationCode,
			}

			buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", bind)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			input := &communication.SendEmailInput{
				To:       createdUser.Email,
				Subject:  settings.AppName + " - create a password for your new account",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				writeJSONError(w, "Failed to send email", "EMAIL_SEND_FAILED", http.StatusInternalServerError)
				return
			}
		}

		// Create response
		response := CreateUserAdminResponse{
			User: createdUser,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserEnabledPut - PUT /api/v1/admin/users/{id}/enabled
func HandleAPIUserEnabledPut(
	httpHelper handlers.HttpHelper,
	database data.Database,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req UpdateUserEnabledRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get existing user
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Update only the enabled field
		user.Enabled = req.Enabled

		// Update user in database
		err = database.UpdateUser(nil, user)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedUserDetails, map[string]interface{}{
			"userId":       userId,
			"loggedInUser": loggedInUser,
		})

		// Get the updated user to return
		updatedUser, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := UserResponse{
			User: updatedUser,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserDelete - DELETE /api/v1/admin/users/{id}
func HandleAPIUserDelete(
	httpHelper handlers.HttpHelper,
	database data.Database,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Check if user exists before deleting
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete user from database
		err = database.DeleteUser(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditDeletedUser, map[string]interface{}{
			"userId":       userId,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := SuccessResponse{
			Success: true,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserProfilePut - PUT /api/v1/admin/users/{id}/profile
func HandleAPIUserProfilePut(
	httpHelper handlers.HttpHelper,
	database data.Database,
	profileValidator *validators.ProfileValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req UpdateUserProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Parse zoneInfo if provided
		zoneInfoCountry := req.ZoneInfoCountryName
		zoneInfo := req.ZoneInfo

		// Validate profile data
		input := &validators.ValidateProfileInput{
			Username:            strings.TrimSpace(req.Username),
			GivenName:           strings.TrimSpace(req.GivenName),
			MiddleName:          strings.TrimSpace(req.MiddleName),
			FamilyName:          strings.TrimSpace(req.FamilyName),
			Nickname:            strings.TrimSpace(req.Nickname),
			Website:             strings.TrimSpace(req.Website),
			Gender:              req.Gender,
			DateOfBirth:         strings.TrimSpace(req.DateOfBirth),
			ZoneInfoCountryName: zoneInfoCountry,
			ZoneInfo:            zoneInfo,
			Locale:              req.Locale,
			Subject:             user.Subject.String(),
		}

		err = profileValidator.ValidateProfile(input)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Update user fields
		user.Username = inputSanitizer.Sanitize(input.Username)
		user.GivenName = inputSanitizer.Sanitize(input.GivenName)
		user.MiddleName = inputSanitizer.Sanitize(input.MiddleName)
		user.FamilyName = inputSanitizer.Sanitize(input.FamilyName)
		user.Nickname = inputSanitizer.Sanitize(input.Nickname)
		user.Website = input.Website

		// Handle gender
		if len(input.Gender) > 0 {
			i, err := strconv.Atoi(input.Gender)
			if err == nil {
				user.Gender = enums.Gender(i).String()
			}
		} else {
			user.Gender = ""
		}

		// Handle date of birth
		if len(input.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, err := time.Parse(layout, input.DateOfBirth)
			if err == nil {
				user.BirthDate = sql.NullTime{Time: parsedTime, Valid: true}
			}
		} else {
			user.BirthDate = sql.NullTime{Valid: false}
		}

		user.ZoneInfoCountryName = input.ZoneInfoCountryName
		user.ZoneInfo = input.ZoneInfo
		user.Locale = input.Locale

		// Update user in database
		err = database.UpdateUser(nil, user)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedUserProfile, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := UserResponse{
			User: user,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserAddressPut - PUT /api/v1/admin/users/{id}/address
func HandleAPIUserAddressPut(
	httpHelper handlers.HttpHelper,
	database data.Database,
	addressValidator *validators.AddressValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req UpdateUserAddressRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate address data
		input := &validators.ValidateAddressInput{
			AddressLine1:      strings.TrimSpace(req.AddressLine1),
			AddressLine2:      strings.TrimSpace(req.AddressLine2),
			AddressLocality:   strings.TrimSpace(req.AddressLocality),
			AddressRegion:     strings.TrimSpace(req.AddressRegion),
			AddressPostalCode: strings.TrimSpace(req.AddressPostalCode),
			AddressCountry:    strings.TrimSpace(req.AddressCountry),
		}

		err = addressValidator.ValidateAddress(input)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Update user address fields
		user.AddressLine1 = inputSanitizer.Sanitize(input.AddressLine1)
		user.AddressLine2 = inputSanitizer.Sanitize(input.AddressLine2)
		user.AddressLocality = inputSanitizer.Sanitize(input.AddressLocality)
		user.AddressRegion = inputSanitizer.Sanitize(input.AddressRegion)
		user.AddressPostalCode = inputSanitizer.Sanitize(input.AddressPostalCode)
		user.AddressCountry = inputSanitizer.Sanitize(input.AddressCountry)

		// Update user in database
		err = database.UpdateUser(nil, user)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedUserAddress, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := UserResponse{
			User: user,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}
