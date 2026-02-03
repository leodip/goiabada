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
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountPhonePut - PUT /api/v1/account/phone
func HandleAPIAccountPhonePut(
	database data.Database,
	phoneValidator *validators.PhoneValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
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

		// Parse request body
		var req api.UpdateAccountPhoneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Load current user
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate phone input
		input := &validators.ValidatePhoneInput{
			PhoneCountryUniqueId: req.PhoneCountryUniqueId,
			PhoneNumber:          strings.TrimSpace(req.PhoneNumber),
		}
		if err := phoneValidator.ValidatePhone(input); err != nil {
			writeValidationError(w, err)
			return
		}

		// Resolve phone country if provided
		var callingCode string
		if len(input.PhoneCountryUniqueId) > 0 {
			pcs := phonecountries.Get()
			found := false
			for _, c := range pcs {
				if c.UniqueId == input.PhoneCountryUniqueId {
					callingCode = c.CallingCode
					found = true
					break
				}
			}
			if !found {
				writeJSONError(w, "Phone country is invalid: "+input.PhoneCountryUniqueId, "INVALID_PHONE_COUNTRY", http.StatusBadRequest)
				return
			}
		}

		// Apply updates; always mark phone as unverified on change
		if strings.TrimSpace(input.PhoneNumber) == "" {
			user.PhoneNumberCountryUniqueId = ""
			user.PhoneNumberCountryCallingCode = ""
			user.PhoneNumber = ""
			user.PhoneNumberVerified = false
		} else {
			user.PhoneNumberCountryUniqueId = input.PhoneCountryUniqueId
			user.PhoneNumberCountryCallingCode = callingCode
			user.PhoneNumber = inputSanitizer.Sanitize(input.PhoneNumber)
			user.PhoneNumberVerified = false
		}

		// Persist
		if err := database.UpdateUser(nil, user); err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit (self-service)
		auditLogger.Log(constants.AuditUpdatedOwnPhone, map[string]interface{}{
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
