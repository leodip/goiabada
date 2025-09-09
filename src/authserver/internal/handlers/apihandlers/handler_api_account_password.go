package apihandlers

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strings"

    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/hashutil"
    "github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountPasswordPut - PUT /api/v1/account/password
func HandleAPIAccountPasswordPut(
    httpHelper handlers.HttpHelper,
    database data.Database,
    passwordValidator *validators.PasswordValidator,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Token and scope are enforced by middleware; extract validated token
        jwtToken, ok := middleware.GetValidatedToken(r)
        if !ok {
            writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
            return
        }

        subject := jwtToken.GetStringClaim("sub")
        if strings.TrimSpace(subject) == "" {
            writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
            return
        }

        // Decode request
        var req api.UpdateAccountPasswordRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
            return
        }

        // Validate required fields
        if strings.TrimSpace(req.CurrentPassword) == "" {
            writeJSONError(w, "Current password is required.", "CURRENT_PASSWORD_REQUIRED", http.StatusBadRequest)
            return
        }
        if strings.TrimSpace(req.NewPassword) == "" {
            writeJSONError(w, "New password is required.", "PASSWORD_REQUIRED", http.StatusBadRequest)
            return
        }

        // Load user
        user, err := database.GetUserBySubject(nil, subject)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if user == nil {
            writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
            return
        }

        // Verify current password
        if !hashutil.VerifyPasswordHash(user.PasswordHash, req.CurrentPassword) {
            writeJSONError(w, "Authentication failed. Check your current password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
            return
        }

        // Validate new password against policy
        if err := passwordValidator.ValidatePassword(r.Context(), req.NewPassword); err != nil {
            writeValidationError(w, err)
            return
        }

        // Hash and update
        passwordHash, err := hashutil.HashPassword(req.NewPassword)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        user.PasswordHash = passwordHash
        user.ForgotPasswordCodeEncrypted = nil
        user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}

        if err := database.UpdateUser(nil, user); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditChangedPassword, map[string]interface{}{
            "userId":       user.Id,
            "loggedInUser": subject,
        })

        // Response
        resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

