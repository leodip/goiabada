package apihandlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPIClientsGet - GET /api/v1/admin/clients
func HandleAPIClientsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		clients, err := database.GetAllClients(nil)
		if err != nil {
			slog.Error("AuthServer API: Database error getting all clients", "error", err)
			writeJSONError(w, "Failed to get clients", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Load RedirectURIs and WebOrigins for each client
		for i := range clients {
			err = database.ClientLoadRedirectURIs(nil, &clients[i])
			if err != nil {
				slog.Error("AuthServer API: Database error loading client redirect URIs", "error", err, "clientId", clients[i].Id)
				writeJSONError(w, "Failed to load client redirect URIs", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			err = database.ClientLoadWebOrigins(nil, &clients[i])
			if err != nil {
				slog.Error("AuthServer API: Database error loading client web origins", "error", err, "clientId", clients[i].Id)
				writeJSONError(w, "Failed to load client web origins", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
		}

		clientResponses := api.ToClientResponses(clients, false) // false = don't include secrets

		response := api.GetClientsResponse{
			Clients: clientResponses,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}

// HandleAPIClientGet - GET /api/v1/admin/clients/{id}
func HandleAPIClientGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(nil, id)
		if err != nil {
			slog.Error("AuthServer API: Database error getting client by ID", "error", err, "clientId", id)
			writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Load RedirectURIs and WebOrigins
		err = database.ClientLoadRedirectURIs(nil, client)
		if err != nil {
			slog.Error("AuthServer API: Database error loading client redirect URIs", "error", err, "clientId", client.Id)
			writeJSONError(w, "Failed to load client redirect URIs", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		err = database.ClientLoadWebOrigins(nil, client)
		if err != nil {
			slog.Error("AuthServer API: Database error loading client web origins", "error", err, "clientId", client.Id)
			writeJSONError(w, "Failed to load client web origins", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		clientResponse := api.ToClientResponse(client, false) // Don't include encrypted secret yet

		// Decrypt client secret if it exists
		if client.ClientSecretEncrypted != nil {
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				slog.Error("AuthServer API: Failed to decrypt client secret", "error", err, "clientId", client.Id)
				writeJSONError(w, "Failed to decrypt client secret", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			clientResponse.ClientSecret = clientSecretDecrypted
		}

		response := api.GetClientResponse{
			Client: *clientResponse,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}
