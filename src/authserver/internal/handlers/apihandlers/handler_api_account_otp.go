package apihandlers

import (
    "encoding/json"
    "net/http"
    "strings"

    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/hashutil"
    "github.com/leodip/goiabada/core/models"
    "github.com/pquerna/otp/totp"
)

// HandleAPIAccountOTPEnrollmentGet - GET /api/v1/account/otp/enrollment
func HandleAPIAccountOTPEnrollmentGet(
    httpHelper handlers.HttpHelper,
    database data.Database,
    otpSecretGenerator handlers.OtpSecretGenerator,
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

        // If already enabled, cannot enroll
        if user.OTPEnabled {
            writeJSONError(w, "OTP is already enabled", "OTP_ALREADY_ENABLED", http.StatusBadRequest)
            return
        }

        // Generate enrollment QR and secret
        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        base64Image, secretKey, err := otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.AccountOTPEnrollmentResponse{Base64Image: base64Image, SecretKey: secretKey}
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

// HandleAPIAccountOTPPut - PUT /api/v1/account/otp
func HandleAPIAccountOTPPut(
    httpHelper handlers.HttpHelper,
    database data.Database,
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

        // Decode request body
        var req api.UpdateAccountOTPRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
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

        // Verify password for both enable and disable operations
        if strings.TrimSpace(req.Password) == "" {
            writeJSONError(w, "Authentication failed. Check your password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
            return
        }
        if !hashutil.VerifyPasswordHash(user.PasswordHash, req.Password) {
            writeJSONError(w, "Authentication failed. Check your password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
            return
        }

        // Branch by operation
        if req.Enabled {
            // Enable OTP
            if user.OTPEnabled {
                writeJSONError(w, "OTP is already enabled", "OTP_ALREADY_ENABLED", http.StatusBadRequest)
                return
            }
            if strings.TrimSpace(req.SecretKey) == "" || strings.TrimSpace(req.OtpCode) == "" {
                writeJSONError(w, "OTP code and secret are required to enable.", "OTP_CODE_AND_SECRET_REQUIRED", http.StatusBadRequest)
                return
            }

            // Basic validation/sanitization
            // Normalize secret: uppercase, strip spaces
            normalizedSecret := strings.ToUpper(strings.ReplaceAll(req.SecretKey, " ", ""))
            // Secret must be base32-like and of reasonable length
            // 16..64 chars covers typical 80..320 bits
            isValidSecret := func(s string) bool {
                if len(s) < 16 || len(s) > 64 {
                    return false
                }
                for i := 0; i < len(s); i++ {
                    ch := s[i]
                    if !((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7')) {
                        return false
                    }
                }
                return true
            }
            if !isValidSecret(normalizedSecret) {
                writeJSONError(w, "Invalid OTP secret format.", "INVALID_OTP_SECRET", http.StatusBadRequest)
                return
            }
            // OTP code must be 6 digits
            if len(req.OtpCode) != 6 {
                writeJSONError(w, "Invalid OTP code.", "INVALID_OTP_CODE", http.StatusBadRequest)
                return
            }
            for i := 0; i < 6; i++ {
                if req.OtpCode[i] < '0' || req.OtpCode[i] > '9' {
                    writeJSONError(w, "Invalid OTP code.", "INVALID_OTP_CODE", http.StatusBadRequest)
                    return
                }
            }

            if !totp.Validate(req.OtpCode, normalizedSecret) {
                writeJSONError(w, "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app.", "INVALID_OTP_CODE", http.StatusBadRequest)
                return
            }

            user.OTPSecret = normalizedSecret
            user.OTPEnabled = true

            if err := database.UpdateUser(nil, user); err != nil {
                writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
                return
            }

            auditLogger.Log(constants.AuditEnabledOTP, map[string]interface{}{
                "userId": user.Id,
            })
        } else {
            // Disable OTP
            if !user.OTPEnabled {
                writeJSONError(w, "User does not have OTP enabled", "OTP_NOT_ENABLED", http.StatusBadRequest)
                return
            }

            user.OTPSecret = ""
            user.OTPEnabled = false

            if err := database.UpdateUser(nil, user); err != nil {
                writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
                return
            }

            auditLogger.Log(constants.AuditDisabledOTP, map[string]interface{}{
                "userId": user.Id,
            })
        }

        // Flag session Level2AuthConfigHasChanged = true for this sid if present
        sid := jwtToken.GetStringClaim("sid")
        if strings.TrimSpace(sid) != "" {
            userSession, err := database.GetUserSessionBySessionIdentifier(nil, sid)
            if err == nil && userSession != nil {
                userSession.Level2AuthConfigHasChanged = true
                _ = database.UpdateUserSession(nil, userSession)
            }
        }

        // Get updated user and respond
        updated, err := database.GetUserById(nil, user.Id)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.UpdateUserResponse{User: *api.ToUserResponse(updated)}
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}
