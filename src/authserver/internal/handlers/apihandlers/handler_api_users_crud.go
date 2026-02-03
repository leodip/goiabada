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
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/user"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIUserGet - GET /api/v1/admin/users/{id}
func HandleAPIUserGet(
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
		response := api.GetUserResponse{
			User: *api.ToUserResponse(user),
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserPasswordPut - PUT /api/v1/admin/users/{id}/password
func HandleAPIUserPasswordPut(
	database data.Database,
	passwordValidator *validators.PasswordValidator,
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
		var req api.UpdateUserPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.NewPassword == "" {
			writeJSONError(w, "New password is required", "PASSWORD_REQUIRED", http.StatusBadRequest)
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

		// Validate password
		err = passwordValidator.ValidatePassword(r.Context(), req.NewPassword)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Hash password
		passwordHash, err := hashutil.HashPassword(req.NewPassword)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Update user
		user.PasswordHash = passwordHash
		user.ForgotPasswordCodeEncrypted = nil
		user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}

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
		auditLogger.Log(constants.AuditUpdatedUserAuthentication, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Get the updated user to return
		updatedUser, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := api.UpdateUserResponse{
			User: *api.ToUserResponse(updatedUser),
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserOTPPut - PUT /api/v1/admin/users/{id}/otp
func HandleAPIUserOTPPut(
	database data.Database,
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
		var req api.UpdateUserOTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Check if trying to enable OTP (not supported)
		if req.Enabled {
			writeJSONError(w, "Enabling OTP is not supported through this endpoint", "OTP_ENABLE_NOT_SUPPORTED", http.StatusBadRequest)
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

		// Only proceed if user currently has OTP enabled and we're disabling it
		if !user.OTPEnabled {
			writeJSONError(w, "User does not have OTP enabled", "OTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		// Disable OTP
		user.OTPEnabled = false
		user.OTPSecret = ""

		err = database.UpdateUser(nil, user)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Log audit event
		auditLogger.Log(constants.AuditDisabledOTP, map[string]interface{}{
			"userId": user.Id,
		})

		// Get the updated user to return
		updatedUser, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := api.UpdateUserResponse{
			User: *api.ToUserResponse(updatedUser),
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
	auditLogger handlers.AuditLogger,
	emailSender handlers.EmailSender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Decode the request body
		var req api.CreateUserAdminRequest
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
		response := api.CreateUserResponse{
			User: *api.ToUserResponse(createdUser),
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
	database data.Database,
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
		var req api.UpdateUserEnabledRequest
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
		response := api.UpdateUserResponse{
			User: *api.ToUserResponse(updatedUser),
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
	database data.Database,
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
		response := api.SuccessResponse{
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
