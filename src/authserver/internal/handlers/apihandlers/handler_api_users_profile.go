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
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIUserProfilePut - PUT /api/v1/admin/users/{id}/profile
func HandleAPIUserProfilePut(
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
		var req api.UpdateUserProfileRequest
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

// HandleAPIUserAddressPut - PUT /api/v1/admin/users/{id}/address
func HandleAPIUserAddressPut(
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
		var req api.UpdateUserAddressRequest
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
