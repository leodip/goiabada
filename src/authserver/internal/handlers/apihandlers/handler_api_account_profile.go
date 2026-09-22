package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/gender"
)

// accountProfileDatabase is what the account profile endpoints need: the caller's own user row.
type accountProfileDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// HandleAPIAccountProfileGet - GET /api/v1/account/profile
func HandleAPIAccountProfileGet(
	database accountProfileDatabase,
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

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		resp := api.GetUserResponse{User: *apimapping.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPIAccountProfilePut - PUT /api/v1/account/profile
func HandleAPIAccountProfilePut(
	database accountProfileDatabase,
	profileValidator *accountvalidation.ProfileValidator,
	auditLogger AuditLogger,
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

		// Parse request body
		var req api.UpdateUserProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

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
			ZoneInfoCountryName: req.ZoneInfoCountryName,
			ZoneInfo:            req.ZoneInfo,
			Locale:              req.Locale,
			Subject:             user.Subject,
		}

		if err := profileValidator.ValidateProfile(r.Context(), input); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Update user fields with sanitized values
		user.Username = input.Username
		user.GivenName = input.GivenName
		user.MiddleName = input.MiddleName
		user.FamilyName = input.FamilyName
		user.Nickname = input.Nickname
		user.Website = input.Website

		if len(input.Gender) > 0 {
			if i, err := strconv.Atoi(input.Gender); err == nil && gender.IsGenderValid(i) {
				user.Gender = gender.Gender(i).String()
			}
		} else {
			user.Gender = ""
		}

		if len(input.DateOfBirth) > 0 {
			layout := "2006-01-02"
			if parsed, err := time.Parse(layout, input.DateOfBirth); err == nil {
				user.BirthDate = sql.NullTime{Time: parsed, Valid: true}
			}
		} else {
			user.BirthDate = sql.NullTime{Valid: false}
		}

		user.ZoneInfoCountryName = input.ZoneInfoCountryName
		user.ZoneInfo = input.ZoneInfo
		user.Locale = input.Locale

		if err := database.UpdateUser(r.Context(), nil, user); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit
		auditLogger.Log(r.Context(), audit.AuditUpdatedOwnProfile, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		// Response
		resp := api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
