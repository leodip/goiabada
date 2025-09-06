package apihandlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func HandleAPIUserConsentsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user consents
		userConsents, err := database.GetConsentsByUserId(nil, user.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Load client details for consents
		err = database.UserConsentsLoadClients(nil, userConsents)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		response := api.GetUserConsentsResponse{
			Consents: api.ToUserConsentResponses(userConsents),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

func HandleAPIUserConsentDelete(
	httpHelper handlers.HttpHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		// Get the consent to check if it exists and get user info for audit
		consent, err := database.GetUserConsentById(nil, consentId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if consent == nil {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the consent
		err = database.DeleteUserConsent(nil, consentId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditDeletedUserConsent, map[string]interface{}{
			"userId":       consent.UserId,
			"consentId":    consentId,
			"loggedInUser": r.Context().Value("subject"),
		})

		response := api.SuccessResponse{Success: true}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}
