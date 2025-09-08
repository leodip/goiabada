package apihandlers

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "strconv"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/encryption"
    "github.com/leodip/goiabada/core/enums"
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/validators"
    "github.com/leodip/goiabada/core/stringutil"
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

// HandleAPIClientCreatePost - POST /api/v1/admin/clients
func HandleAPIClientCreatePost(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    identifierValidator *validators.IdentifierValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        var req api.CreateClientRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Validate client identifier present
        if strings.TrimSpace(req.ClientIdentifier) == "" {
            writeJSONError(w, "Client identifier is required.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Validate description length
        const maxLengthDescription = 100
        if len(req.Description) > maxLengthDescription {
            writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Validate identifier format
        if err := identifierValidator.ValidateIdentifier(req.ClientIdentifier, true); err != nil {
            writeValidationError(w, err)
            return
        }

        // Check uniqueness
        existingClient, err := database.GetClientByClientIdentifier(nil, req.ClientIdentifier)
        if err != nil {
            slog.Error("AuthServer API: Database error checking client existence by identifier", "error", err, "clientIdentifier", req.ClientIdentifier)
            writeJSONError(w, "Failed to check client existence", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if existingClient != nil {
            writeJSONError(w, "The client identifier is already in use.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Generate and encrypt client secret
        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        clientSecret := stringutil.GenerateSecurityRandomString(60)
        clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
        if err != nil {
            slog.Error("AuthServer API: Failed to encrypt client secret", "error", err)
            writeJSONError(w, "Failed to create client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Create client model mimicking current implementation defaults
        client := &models.Client{
            ClientIdentifier:                        strings.TrimSpace(inputSanitizer.Sanitize(req.ClientIdentifier)),
            Description:                             strings.TrimSpace(inputSanitizer.Sanitize(req.Description)),
            ClientSecretEncrypted:                   clientSecretEncrypted,
            IsPublic:                                false,
            ConsentRequired:                         false,
            Enabled:                                 true,
            DefaultAcrLevel:                         enums.AcrLevel2Optional,
            AuthorizationCodeEnabled:                req.AuthorizationCodeEnabled,
            ClientCredentialsEnabled:                req.ClientCredentialsEnabled,
            IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
        }

        if err := database.CreateClient(nil, client); err != nil {
            slog.Error("AuthServer API: Database error creating client", "error", err)
            writeJSONError(w, "Failed to create client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit log
        auditLogger.Log(constants.AuditCreatedClient, map[string]interface{}{
            "clientId":         client.Id,
            "clientIdentifier": client.ClientIdentifier,
            "loggedInUser":     authHelper.GetLoggedInSubject(r),
        })

        // Load related fields for response consistency (fail if these operations fail)
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after create", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after create", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        resp := api.CreateClientResponse{
            Client: *api.ToClientResponse(client, false),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        httpHelper.EncodeJson(w, r, resp)
    }
}
