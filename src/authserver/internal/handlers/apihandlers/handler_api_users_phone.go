package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIPhoneCountriesGet - GET /api/v1/admin/phone-countries
func HandleAPIPhoneCountriesGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get phone countries
		phoneCountries := phonecountries.Get()

		// Convert to API response
		phoneCountryResponses := make([]api.PhoneCountryResponse, len(phoneCountries))
		for i, pc := range phoneCountries {
			phoneCountryResponses[i] = api.PhoneCountryResponse{
				UniqueId:    pc.UniqueId,
				CallingCode: pc.CallingCode,
				Name:        pc.Name,
			}
		}

		response := api.GetPhoneCountriesResponse{
			PhoneCountries: phoneCountryResponses,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserPhonePut - PUT /api/v1/admin/users/{id}/phone
func HandleAPIUserPhonePut(
	database data.Database,
	phoneValidator *validators.PhoneValidator,
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
		var req api.UpdateUserPhoneRequest
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

		// Validate phone data
		input := &validators.ValidatePhoneInput{
			PhoneCountryUniqueId: req.PhoneCountryUniqueId,
			PhoneNumber:          strings.TrimSpace(req.PhoneNumber),
		}

		err = phoneValidator.ValidatePhone(input)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Get phone countries for country lookup
		phoneCountries := phonecountries.Get()
		var phoneCountry phonecountries.PhoneCountry
		found := false
		for _, c := range phoneCountries {
			if c.UniqueId == input.PhoneCountryUniqueId {
				found = true
				phoneCountry = c
				break
			}
		}

		if !found && len(input.PhoneCountryUniqueId) > 0 {
			writeJSONError(w, "Phone country is invalid: "+input.PhoneCountryUniqueId, "INVALID_PHONE_COUNTRY", http.StatusBadRequest)
			return
		}

		// Update user phone fields
		if strings.TrimSpace(input.PhoneNumber) == "" {
			user.PhoneNumberCountryUniqueId = ""
			user.PhoneNumberCountryCallingCode = ""
			user.PhoneNumber = ""
			user.PhoneNumberVerified = false
		} else {
			user.PhoneNumberCountryUniqueId = input.PhoneCountryUniqueId
			user.PhoneNumberCountryCallingCode = phoneCountry.CallingCode
			user.PhoneNumber = inputSanitizer.Sanitize(input.PhoneNumber)
			user.PhoneNumberVerified = req.PhoneNumberVerified
		}

		if len(strings.TrimSpace(user.PhoneNumber)) == 0 {
			user.PhoneNumberVerified = false
		}

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
		auditLogger.Log(constants.AuditUpdatedUserPhone, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := api.UpdateUserResponse{
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
