package apihandlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/otp"
)

// HandleAPIAccountOTPEnrollmentGet - GET /api/v1/account/otp/enrollment
func HandleAPIAccountOTPEnrollmentGet(
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
					if (ch < 'A' || ch > 'Z') && (ch < '2' || ch > '7') {
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

			// A replayed code must be indistinguishable from a wrong one to the caller, so
			// both branches below write this same body (#111).
			incorrectOtpCode := "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app."

			step, matched := otp.MatchStep(req.OtpCode, normalizedSecret, time.Now().UTC())
			if !matched {
				writeJSONError(w, incorrectOtpCode, "INVALID_OTP_CODE", http.StatusBadRequest)
				return
			}

			// requireOTPEnabled is false here: this is enrollment establishing the
			// authenticator rather than a verification asserting it, and otp_enabled is
			// still off until the write below (#111 decision 10). It can only be off: the
			// OTP_ALREADY_ENABLED check above refuses an enable when it is on. The claim
			// comes first deliberately, as at the browser enrollment site: if the write
			// then fails, a code is burned and the user retries with the next one, whereas
			// the reverse order would leave OTP enabled on a request that was refused.
			consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
			if !consumed {
				// No AuditAuthFailedOtp beside it, unlike the browser sites: this endpoint
				// emits nothing when a code is simply wrong, and enabling OTP is not an
				// authentication ceremony. Decision 5 puts the replay event alongside the
				// existing failure event, and here there is none.
				auditLogger.Log(constants.AuditOTPCodeReplayDetected, map[string]interface{}{
					"userId": user.Id,
					"step":   step,
				})
				writeJSONError(w, incorrectOtpCode, "INVALID_OTP_CODE", http.StatusBadRequest)
				return
			}

			if err := user.SetOTPSecret(normalizedSecret); err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
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

			if err := disableUserOTP(database, user); err != nil {
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

// disableUserOTP removes a user's authenticator: it clears the secret, turns otp_enabled off and
// returns the consumed-step marker to 0. The marker belongs to the authenticator being removed, and
// UpdateUser cannot carry it because the column is dont-update, which is why it takes a second write
// (#111 decision 4). The reset is also the only in-product remedy if a clock jump strands a user's
// marker in the future: without it, disabling OTP and re-enrolling would claim against the same
// poisoned marker and fail too.
//
// **The two writes commit together, and that is the point of this function** (#111 decision 13).
// Committed separately, which is how they were written before that decision, they leave a window in
// which the row reads otp_enabled = false with the old marker still standing. The window is between
// two committed statements, not inside one: no engine this server supports exposes an uncommitted
// write to an outside reader, so a transaction is the remedy rather than the hazard. An enrollment
// landing in that window loads the disabled state, matches a code and
// claims its step successfully, and then this reset erases the claim: the row settles at
// otp_enabled = 1 with last_otp_step = 0 and a code already consumed, so that code is claimable
// again at the browser prompt for the rest of its acceptance window. A concurrent enrollment sees
// either the pre-disable state, where OTP_ALREADY_ENABLED refuses it at the account API and decision
// 10's requireOTPEnabled refuses it at the browser verification branch, or the fully disabled state
// including the reset, where its claim stands. Neither method needed a transaction on its own; the
// pair does.
//
// The order inside the transaction is decision 10's, otp_enabled cleared before the marker. The
// commit boundary is now what closes that window rather than the ordering, since no reader outside
// the transaction observes either write until both have landed, but the order is kept: it costs
// nothing and it is the order the two disable sites have always written in.
//
// Shared by the two sites decision 4 names, HandleAPIAccountOTPPut's disable branch and
// HandleAPIUserOTPPut. There is no third: the browser flow enrolls but never disables.
func disableUserOTP(database data.Database, user *models.User) error {
	user.ClearOTPSecret()
	user.OTPEnabled = false

	tx, err := database.BeginTransaction()
	if err != nil {
		return err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	if err := database.UpdateUser(tx, user); err != nil {
		return err
	}
	if err := database.ResetUserOTPStep(tx, user.Id); err != nil {
		return err
	}
	return database.CommitTransaction(tx)
}
