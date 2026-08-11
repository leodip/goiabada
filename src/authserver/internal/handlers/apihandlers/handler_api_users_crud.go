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
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
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
			writeValidationError(w, r, err)
			return
		}

		// Hash password
		passwordHash, err := hashutil.HashPassword(req.NewPassword)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// The fourth site, unmentioned by the issue (#106 decision 2). An admin setting
		// someone else's password revokes everything with no exceptSid: the admin's own
		// session is unaffected because it belongs to a different user, and the target's
		// sessions are exactly what must go.
		//
		// Narrow write, not a full-row UpdateUser: the model was loaded before validation, so
		// writing every column back would undo a concurrent disable (decision 14).
		result, err := handlers.RevokeUserAuthStateTx(database, user.Id, "", func(tx *sql.Tx) error {
			return database.SetUserPasswordHash(tx, user.Id, passwordHash)
		})
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

		// Both events, after commit. The pre-existing one is unchanged (decision 7).
		auditLogger.Log(constants.AuditUpdatedUserAuthentication, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})
		handlers.LogRevokedUserAuthState(auditLogger, user.Id,
			handlers.RevocationReasonAdminPasswordSet, loggedInUser, result)

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

		// Disable OTP. Clearing the secret, turning otp_enabled off and resetting the
		// consumed-step marker are one atomic operation, shared with the account API's disable
		// branch (#111 decisions 4 and 13); disableUserOTP carries the reasoning.
		err = disableUserOTP(database, user)
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
			writeValidationError(w, r, err)
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
		err = profileValidator.ValidateName(req.GivenName, i18n.ErrCodeProfileGivenNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		err = profileValidator.ValidateName(req.MiddleName, i18n.ErrCodeProfileMiddleNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		err = profileValidator.ValidateName(req.FamilyName, i18n.ErrCodeProfileFamilyNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
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
				writeValidationError(w, r, err)
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
			verificationCodeEncrypted, err := encryption.EncryptData(verificationCode)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// The hash is how the reset link finds this row again, since the link carries
			// the code and no email address (#112). The encryption above stays: it is what
			// proves a submitted code matches, where the hash only locates the row.
			verificationCodeHash, err := hashutil.HashString(verificationCode)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// Update user with reset code
			createdUser.ForgotPasswordCodeEncrypted = verificationCodeEncrypted
			createdUser.ForgotPasswordCodeHash = verificationCodeHash
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
				"link": handlers.ResetPasswordLink(verificationCode),
			}

			// Newly-created user has no stored Locale yet; render the
			// "set your password" email in English. Once the user logs in
			// and chooses a locale, subsequent emails honor it.
			emailReq := r.WithContext(i18n.EmailContext(r.Context(), createdUser.Locale))
			buf, err := httpHelper.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", bind)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			input := &communication.SendEmailInput{
				To:       createdUser.Email,
				Subject:  i18n.T(emailReq.Context(), "email.newuser_set_password.subject", map[string]any{"appName": settings.AppName}),
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

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// This endpoint serves BOTH directions, so the write is a compare-and-set and the
		// revocation is conditional on it (#106 findings 4 and 21, decision 14).
		//
		// Only the enabled-to-disabled transition revokes. Enabling must not, since there is
		// no credential change to invalidate, and re-disabling an already-disabled account
		// must not either: it would advance the generation and evict sessions that a previous
		// disable already dealt with, so a repeated request would not be idempotent.
		// TrySetUserEnabled reports whether it actually flipped the row, and that report is
		// the condition. Both directions use it, so neither stays on the full-row UpdateUser
		// that decision 14 rules out.
		// The transaction is opened here rather than through RevokeUserAuthStateTx, because
		// this is the one site whose sweep is conditional on its own write, and the helper's
		// contract is "write then always sweep". Threading a skip through it would put a
		// behaviour switch in a primitive three other sites share, which is what decision 8
		// rejected.
		disableWithRevocation := func() (handlers.RevocationResult, bool, error) {
			tx, err := database.BeginTransaction()
			if err != nil {
				return handlers.RevocationResult{}, false, err
			}
			defer database.RollbackTransaction(tx) //nolint:errcheck

			transitioned, err := database.TrySetUserEnabled(tx, userId, true, false)
			if err != nil {
				return handlers.RevocationResult{}, false, err
			}
			if !transitioned {
				// Already disabled. Nothing was written, so there is nothing to commit and
				// nothing to sweep; the deferred rollback discards the empty transaction.
				return handlers.RevocationResult{}, false, nil
			}

			result, err := handlers.RevokeUserAuthState(database, tx, userId, "")
			if err != nil {
				return handlers.RevocationResult{}, false, err
			}
			if err := database.CommitTransaction(tx); err != nil {
				return handlers.RevocationResult{}, false, err
			}
			return result, true, nil
		}

		var result handlers.RevocationResult
		transitioned := false

		if req.Enabled {
			// Enabling. Narrow write, no revocation, no new event. Uses the same
			// compare-and-set so this direction does not stay on the full-row UpdateUser.
			if _, err = database.TrySetUserEnabled(nil, userId, false, true); err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
		} else {
			result, transitioned, err = disableWithRevocation()
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
		}

		// Unchanged in both directions, per decision 7: the endpoint's existing event still
		// fires for every successful request, including the ones that revoke nothing.
		auditLogger.Log(constants.AuditUpdatedUserDetails, map[string]interface{}{
			"userId":       userId,
			"loggedInUser": loggedInUser,
		})

		// Only on a real disable transition, and only after its commit.
		if transitioned {
			handlers.LogRevokedUserAuthState(auditLogger, userId,
				handlers.RevocationReasonAccountDisabled, loggedInUser, result)
		}

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
