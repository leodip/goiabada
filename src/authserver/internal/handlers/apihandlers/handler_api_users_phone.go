package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/phonecountries"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// HandlePhoneCountriesGet - GET /api/v1/admin/phone-countries
func HandlePhoneCountriesGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get phone countries
		phoneCountries := phonecountries.All()

		// Convert to API response
		phoneCountryResponses := make([]api.PhoneCountryResponse, len(phoneCountries))
		for i, pc := range phoneCountries {
			phoneCountryResponses[i] = api.PhoneCountryResponse{
				UniqueId:    pc.UniqueId,
				Alpha2:      pc.Alpha2,
				Emoji:       pc.Emoji,
				CallingCode: pc.CallingCode,
				Name:        pc.Name,
			}
		}

		response := api.GetPhoneCountriesResponse{
			PhoneCountries: phoneCountryResponses,
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// usersPhoneDatabase is what the administrator's user phone endpoint needs: the user row, and
// the narrow write of its phone columns. It embeds what the administrative policy reads to judge
// whether the user is an administrator.
type usersPhoneDatabase interface {
	userTargetPolicyDatabase
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	SetUserPhone(ctx context.Context, tx *sql.Tx, user *record.User) error
}

// HandleUserPhonePut - PUT /api/v1/admin/users/{id}/phone
func HandleUserPhonePut(
	database usersPhoneDatabase,
	phoneValidator *accountvalidation.PhoneValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req api.UpdateUserPhoneRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate phone data
		input := &accountvalidation.ValidatePhoneInput{
			PhoneCountryUniqueId: req.PhoneCountryUniqueId,
			PhoneNumber:          strings.TrimSpace(req.PhoneNumber),
		}

		err = phoneValidator.ValidatePhone(input)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Look up the phone country
		phoneCountry, found := phonecountries.ByUniqueID(input.PhoneCountryUniqueId)
		if !found && len(input.PhoneCountryUniqueId) > 0 {
			writeJSONError(w, "Phone country is invalid: "+input.PhoneCountryUniqueId, "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
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
			user.PhoneNumber = input.PhoneNumber
			user.PhoneNumberVerified = req.PhoneNumberVerified
		}

		if len(strings.TrimSpace(user.PhoneNumber)) == 0 {
			user.PhoneNumberVerified = false
		}

		// Only the phone columns: writing back the row read above would undo a disable, a
		// password change or an OTP change made since (#471).
		err = database.SetUserPhone(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventUpdatedUserPhone, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := api.UpdateUserResponse{
			User: *apimapping.ToUserResponse(user),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
