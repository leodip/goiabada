package apihandlers

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/enums"
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountProfileGet - GET /api/v1/account/profile
func HandleAPIAccountProfileGet(
    database data.Database,
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

        user, err := database.GetUserBySubject(nil, subject)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if user == nil {
            writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
            return
        }

        resp := api.GetUserResponse{User: *api.ToUserResponse(user)}
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

// HandleAPIAccountProfilePut - PUT /api/v1/account/profile
func HandleAPIAccountProfilePut(
    database data.Database,
    profileValidator *validators.ProfileValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
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

        // Parse request body
        var req api.UpdateUserProfileRequest
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
            ZoneInfoCountryName: req.ZoneInfoCountryName,
            ZoneInfo:            req.ZoneInfo,
            Locale:              req.Locale,
            Subject:             user.Subject.String(),
        }

        if err := profileValidator.ValidateProfile(input); err != nil {
            writeValidationError(w, err)
            return
        }

        // Update user fields with sanitized values
        user.Username = inputSanitizer.Sanitize(input.Username)
        user.GivenName = inputSanitizer.Sanitize(input.GivenName)
        user.MiddleName = inputSanitizer.Sanitize(input.MiddleName)
        user.FamilyName = inputSanitizer.Sanitize(input.FamilyName)
        user.Nickname = inputSanitizer.Sanitize(input.Nickname)
        user.Website = input.Website

        if len(input.Gender) > 0 {
            if i, err := strconv.Atoi(input.Gender); err == nil && enums.IsGenderValid(i) {
                user.Gender = enums.Gender(i).String()
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

        if err := database.UpdateUser(nil, user); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedOwnProfile, map[string]interface{}{
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

