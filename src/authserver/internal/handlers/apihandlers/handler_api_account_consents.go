package apihandlers

import (
    "net/http"
    "strconv"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
)

// GET /api/v1/account/consents
func HandleAPIAccountConsentsGet(
    httpHelper handlers.HttpHelper,
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
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

        consents, err := database.GetConsentsByUserId(nil, user.Id)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        if err := database.UserConsentsLoadClients(nil, consents); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.GetUserConsentsResponse{Consents: api.ToUserConsentResponses(consents)}
        w.Header().Set("Content-Type", "application/json")
        httpHelper.EncodeJson(w, r, resp)
    }
}

// DELETE /api/v1/account/consents/{id}
func HandleAPIAccountConsentDelete(
    httpHelper handlers.HttpHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
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

        idStr := chi.URLParam(r, "id")
        if idStr == "" {
            writeJSONError(w, "Consent ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }
        consentId, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            writeJSONError(w, "Invalid consent ID format", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        consent, err := database.GetUserConsentById(nil, consentId)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if consent == nil {
            writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        // Ownership check: must belong to current user
        if consent.UserId != user.Id {
            writeJSONError(w, "Forbidden", "FORBIDDEN", http.StatusForbidden)
            return
        }

        if err := database.DeleteUserConsent(nil, consentId); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        auditLogger.Log(constants.AuditDeletedOwnUserConsent, map[string]interface{}{
            "userId":       user.Id,
            "consentId":    consentId,
            "loggedInUser": subject,
        })

        resp := api.SuccessResponse{Success: true}
        w.Header().Set("Content-Type", "application/json")
        httpHelper.EncodeJson(w, r, resp)
    }
}

