package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/gender"
)

// usersProfileDatabase is what the administrator's user profile endpoint needs: the user row.
type usersProfileDatabase interface {
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// HandleAPIUserProfilePut - PUT /api/v1/admin/users/{id}/profile
func HandleAPIUserProfilePut(
	database usersProfileDatabase,
	profileValidator *accountvalidation.ProfileValidator,
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
		var req api.UpdateUserProfileRequest
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

		// Parse zoneInfo if provided
		zoneInfoCountry := req.ZoneInfoCountryName
		zoneInfo := req.ZoneInfo

		// Validate profile data
		input := &accountvalidation.ValidateProfileInput{
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
			Subject:             user.Subject,
		}

		err = profileValidator.ValidateProfile(r.Context(), input)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Update user fields
		user.Username = input.Username
		user.GivenName = input.GivenName
		user.MiddleName = input.MiddleName
		user.FamilyName = input.FamilyName
		user.Nickname = input.Nickname
		user.Website = input.Website

		// Handle gender
		if len(input.Gender) > 0 {
			i, parseErr := strconv.Atoi(input.Gender)
			if parseErr == nil {
				user.Gender = gender.Gender(i).String()
			}
		} else {
			user.Gender = ""
		}

		// Handle date of birth
		if len(input.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, parseErr := time.Parse(layout, input.DateOfBirth)
			if parseErr == nil {
				user.BirthDate = sql.NullTime{Time: parsedTime, Valid: true}
			}
		} else {
			user.BirthDate = sql.NullTime{Valid: false}
		}

		user.ZoneInfoCountryName = input.ZoneInfoCountryName
		user.ZoneInfo = input.ZoneInfo
		user.Locale = input.Locale

		// Update user in database
		err = database.UpdateUser(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedUserProfile, map[string]interface{}{
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

// HandleAPIUserAddressPut - PUT /api/v1/admin/users/{id}/address
func HandleAPIUserAddressPut(
	database usersProfileDatabase,
	addressValidator *accountvalidation.AddressValidator,
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
		var req api.UpdateUserAddressRequest
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

		// Validate address data
		input := &accountvalidation.ValidateAddressInput{
			AddressLine1:      strings.TrimSpace(req.AddressLine1),
			AddressLine2:      strings.TrimSpace(req.AddressLine2),
			AddressLocality:   strings.TrimSpace(req.AddressLocality),
			AddressRegion:     strings.TrimSpace(req.AddressRegion),
			AddressPostalCode: strings.TrimSpace(req.AddressPostalCode),
			AddressCountry:    strings.TrimSpace(req.AddressCountry),
		}

		err = addressValidator.ValidateAddress(input)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Update user address fields
		user.AddressLine1 = input.AddressLine1
		user.AddressLine2 = input.AddressLine2
		user.AddressLocality = input.AddressLocality
		user.AddressRegion = input.AddressRegion
		user.AddressPostalCode = input.AddressPostalCode
		user.AddressCountry = input.AddressCountry

		// Update user in database
		err = database.UpdateUser(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedUserAddress, map[string]interface{}{
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
