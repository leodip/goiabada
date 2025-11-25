package apihandlers

import (
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "net/url"
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

		clientResponses := api.ToClientResponses(clients)

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

        // Do not include permissions in this endpoint for consistency with users/groups

        clientResponse := api.ToClientResponse(client)

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

// HandleAPIClientDelete - DELETE /api/v1/admin/clients/{id}
func HandleAPIClientDelete(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for deletion", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to delete a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        if err := database.DeleteClient(nil, client.Id); err != nil {
            slog.Error("AuthServer API: Database error deleting client", "error", err, "clientId", client.Id, "clientIdentifier", client.ClientIdentifier)
            writeJSONError(w, "Failed to delete client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        auditLogger.Log(constants.AuditDeletedClient, map[string]interface{}{
            "clientId":         client.Id,
            "clientIdentifier": client.ClientIdentifier,
            "loggedInUser":     authHelper.GetLoggedInSubject(r),
        })

        resp := api.SuccessResponse{Success: true}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
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
            Client: *api.ToClientResponse(client),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPIClientUpdatePut - PUT /api/v1/admin/clients/{id}
func HandleAPIClientUpdatePut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    identifierValidator *validators.IdentifierValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var updateReq api.UpdateClientSettingsRequest
        if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Validate client identifier
        if strings.TrimSpace(updateReq.ClientIdentifier) == "" {
            writeJSONError(w, "Client identifier is required.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Validate description length
        const maxLengthDescription = 100
        if len(updateReq.Description) > maxLengthDescription {
            writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Validate identifier format
        if err := identifierValidator.ValidateIdentifier(updateReq.ClientIdentifier, true); err != nil {
            writeValidationError(w, err)
            return
        }

        // Check uniqueness excluding current client
        existingClient, err := database.GetClientByClientIdentifier(nil, updateReq.ClientIdentifier)
        if err != nil {
            slog.Error("AuthServer API: Database error checking client existence by identifier for update", "error", err, "clientIdentifier", updateReq.ClientIdentifier, "clientId", client.Id)
            writeJSONError(w, "Failed to check client existence", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if existingClient != nil && existingClient.Id != client.Id {
            writeJSONError(w, "The client identifier is already in use.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // ACR level validation depending on AuthorizationCodeEnabled
        if !client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultAcrLevel) != "" {
            writeJSONError(w, "Default ACR level is not applicable when authorization code flow is disabled.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Update fields
        client.ClientIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.ClientIdentifier))
        client.Description = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.Description))
        client.Enabled = updateReq.Enabled
        client.ConsentRequired = updateReq.ConsentRequired

        if client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultAcrLevel) != "" {
            acrLevel, err := enums.AcrLevelFromString(updateReq.DefaultAcrLevel)
            if err != nil {
                writeJSONError(w, "Invalid default ACR level", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            client.DefaultAcrLevel = acrLevel
        }

        if err := database.UpdateClient(nil, client); err != nil {
            slog.Error("AuthServer API: Database error updating client", "error", err, "clientId", client.Id, "clientIdentifier", client.ClientIdentifier)
            writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Load related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit log
        auditLogger.Log(constants.AuditUpdatedClientSettings, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        response := api.UpdateClientResponse{
            Client: *api.ToClientResponse(client),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, response)
    }
}

// HandleAPIClientAuthenticationPut - PUT /api/v1/admin/clients/{id}/authentication
// Changes client's public/confidential mode and client secret.
func HandleAPIClientAuthenticationPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for authentication update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateClientAuthenticationRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        if req.IsPublic {
            // Switching to public: remove secret and disable client credentials
            client.IsPublic = true
            client.ClientSecretEncrypted = nil
            client.ClientCredentialsEnabled = false
        } else {
            // Confidential: require strong secret
            if err := validateClientSecret(req.ClientSecret); err != nil {
                writeJSONError(w, "Invalid client secret. Please generate a new one.", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }

            settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
            enc, err := encryption.EncryptText(req.ClientSecret, settings.AESEncryptionKey)
            if err != nil {
                slog.Error("AuthServer API: Failed to encrypt client secret", "error", err, "clientId", client.Id)
                writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
            client.IsPublic = false
            client.ClientSecretEncrypted = enc
            // Preserve ClientCredentialsEnabled as-is
        }

        if err := database.UpdateClient(nil, client); err != nil {
            slog.Error("AuthServer API: Database error updating client authentication", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Load related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after auth update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after auth update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedClientAuthentication, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.UpdateClientResponse{Client: *api.ToClientResponse(client)}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// validateClientSecret enforces a strong secret suitable for confidential clients.
func validateClientSecret(secret string) error {
    // Length policy: min 60, max 255
    if len(secret) < 60 || len(secret) > 255 {
        return fmt.Errorf("invalid length")
    }
    // Allowed charset: 0-9 a-z A-Z - _ .
    for i := 0; i < len(secret); i++ {
        c := secret[i]
        if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.' {
            continue
        }
        return fmt.Errorf("invalid character")
    }
    return nil
}

// HandleAPIClientOAuth2FlowsPut - PUT /api/v1/admin/clients/{id}/oauth2-flows
// Updates which OAuth2 flows are enabled for the client.
func HandleAPIClientOAuth2FlowsPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for oauth2 flows update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateClientOAuth2FlowsRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Apply changes with current business rules
        client.AuthorizationCodeEnabled = req.AuthorizationCodeEnabled
        client.ClientCredentialsEnabled = req.ClientCredentialsEnabled
        client.PKCERequired = req.PKCERequired
        if client.IsPublic {
            // Public clients cannot use client credentials flow
            client.ClientCredentialsEnabled = false
        }

        if err := database.UpdateClient(nil, client); err != nil {
            slog.Error("AuthServer API: Database error updating client OAuth2 flows", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Load related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after oauth2 flows update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after oauth2 flows update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedClientOAuth2Flows, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.UpdateClientResponse{Client: *api.ToClientResponse(client)}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPIClientRedirectURIsPut - PUT /api/v1/admin/clients/{id}/redirect-uris
// Replaces the full set of redirect URIs for the client. The server validates
// inputs, enforces business rules, computes add/remove, and returns the updated client.
func HandleAPIClientRedirectURIsPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for redirect URIs update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        if !client.AuthorizationCodeEnabled {
            writeJSONError(w, "Authorization code flow is disabled for this client.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateClientRedirectURIsRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Validate list and entries
        seen := make(map[string]struct{})
        normalized := make([]string, 0, len(req.RedirectURIs))
        for _, raw := range req.RedirectURIs {
            uri := strings.TrimSpace(raw)
            if uri == "" {
                writeJSONError(w, "Redirect URI cannot be empty", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            if _, err := url.ParseRequestURI(uri); err != nil {
                writeJSONError(w, fmt.Sprintf("Invalid redirect URI: %s", uri), "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            if _, exists := seen[uri]; exists {
                writeJSONError(w, "Duplicate redirect URIs are not allowed", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            seen[uri] = struct{}{}
            normalized = append(normalized, uri)
        }

        // Load existing redirect URIs
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs before update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client redirect URIs", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        existingSet := make(map[string]int64)
        for _, ru := range client.RedirectURIs {
            existingSet[ru.URI] = ru.Id
        }

        desiredSet := seen

        // Add new URIs
        for _, uri := range normalized {
            if _, ok := existingSet[uri]; !ok {
                if err := database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: uri}); err != nil {
                    slog.Error("AuthServer API: Database error creating redirect URI", "error", err, "clientId", client.Id, "uri", uri)
                    writeJSONError(w, "Failed to update redirect URIs", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Delete removed URIs
        for uri, rid := range existingSet {
            if _, ok := desiredSet[uri]; !ok {
                if err := database.DeleteRedirectURI(nil, rid); err != nil {
                    slog.Error("AuthServer API: Database error deleting redirect URI", "error", err, "clientId", client.Id, "uri", uri)
                    writeJSONError(w, "Failed to update redirect URIs", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Reload related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after redirect URIs update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedRedirectURIs, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.UpdateClientResponse{Client: *api.ToClientResponse(client)}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPIClientWebOriginsPut - PUT /api/v1/admin/clients/{id}/web-origins
// Replaces the full set of web origins for the client. The server validates
// inputs (http/https only), enforces business rules, computes add/remove, and
// returns the updated client.
func HandleAPIClientWebOriginsPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for web origins update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        if !client.AuthorizationCodeEnabled {
            writeJSONError(w, "Authorization code flow is disabled for this client.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateClientWebOriginsRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Validate list and entries: non-empty, valid URL, http/https scheme, no duplicates (case-insensitive)
        seen := make(map[string]struct{})
        normalized := make([]string, 0, len(req.WebOrigins))
        for _, raw := range req.WebOrigins {
            val := strings.TrimSpace(raw)
            if val == "" {
                writeJSONError(w, "Web origin cannot be empty", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            parsed, err := url.ParseRequestURI(val)
            if err != nil {
                writeJSONError(w, fmt.Sprintf("Invalid web origin: %s", val), "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            if parsed.Scheme != "http" && parsed.Scheme != "https" {
                writeJSONError(w, "Web origin must use http or https scheme", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            // Normalize to lowercase for storage and uniqueness
            lower := strings.ToLower(val)
            if _, exists := seen[lower]; exists {
                writeJSONError(w, "Duplicate web origins are not allowed", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            seen[lower] = struct{}{}
            normalized = append(normalized, lower)
        }

        // Load existing web origins
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins before update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client web origins", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        existingSet := make(map[string]int64)
        for _, wo := range client.WebOrigins {
            existingSet[strings.ToLower(wo.Origin)] = wo.Id
        }

        desiredSet := seen

        // Add new origins
        for _, origin := range normalized {
            if _, ok := existingSet[origin]; !ok {
                if err := database.CreateWebOrigin(nil, &models.WebOrigin{ClientId: client.Id, Origin: origin}); err != nil {
                    slog.Error("AuthServer API: Database error creating web origin", "error", err, "clientId", client.Id, "origin", origin)
                    writeJSONError(w, "Failed to update web origins", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Delete removed origins
        for origin, wid := range existingSet {
            if _, ok := desiredSet[origin]; !ok {
                if err := database.DeleteWebOrigin(nil, wid); err != nil {
                    slog.Error("AuthServer API: Database error deleting web origin", "error", err, "clientId", client.Id, "origin", origin)
                    writeJSONError(w, "Failed to update web origins", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Reload related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after web origins update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedWebOrigins, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.UpdateClientResponse{Client: *api.ToClientResponse(client)}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPIClientTokensPut - PUT /api/v1/admin/clients/{id}/tokens
// Updates token-related settings for a client.
func HandleAPIClientTokensPut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
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
            slog.Error("AuthServer API: Database error getting client by ID for tokens update", "error", err, "clientId", id)
            writeJSONError(w, "Failed to get client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        if client.IsSystemLevelClient() {
            writeJSONError(w, "Trying to edit a system level client", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateClientTokensRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
            return
        }

        // Validate numbers: >= 0 and <= 160000000
        const maxValue = 160000000
        if req.TokenExpirationInSeconds < 0 || req.TokenExpirationInSeconds > maxValue {
            writeJSONError(w, fmt.Sprintf("Token expiration in seconds must be between 0 and %d.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }
        if req.RefreshTokenOfflineIdleTimeoutInSeconds < 0 || req.RefreshTokenOfflineIdleTimeoutInSeconds > maxValue {
            writeJSONError(w, fmt.Sprintf("Refresh token offline - idle timeout in seconds must be between 0 and %d.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }
        if req.RefreshTokenOfflineMaxLifetimeInSeconds < 0 || req.RefreshTokenOfflineMaxLifetimeInSeconds > maxValue {
            writeJSONError(w, fmt.Sprintf("Refresh token offline - max lifetime in seconds must be between 0 and %d.", maxValue), "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }
        if req.RefreshTokenOfflineIdleTimeoutInSeconds > req.RefreshTokenOfflineMaxLifetimeInSeconds {
            writeJSONError(w, "Refresh token offline - idle timeout cannot be greater than max lifetime.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Validate three-state setting
        if _, err := enums.ThreeStateSettingFromString(strings.TrimSpace(req.IncludeOpenIDConnectClaimsInAccessToken)); err != nil {
            writeJSONError(w, "Invalid value for includeOpenIDConnectClaimsInAccessToken.", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Apply updates
        client.TokenExpirationInSeconds = req.TokenExpirationInSeconds
        client.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
        client.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
        client.IncludeOpenIDConnectClaimsInAccessToken = strings.TrimSpace(req.IncludeOpenIDConnectClaimsInAccessToken)

        if err := database.UpdateClient(nil, client); err != nil {
            slog.Error("AuthServer API: Database error updating client tokens", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Reload related fields for response consistency
        if err := database.ClientLoadRedirectURIs(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client redirect URIs after tokens update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if err := database.ClientLoadWebOrigins(nil, client); err != nil {
            slog.Error("AuthServer API: Database error loading client web origins after tokens update", "error", err, "clientId", client.Id)
            writeJSONError(w, "Failed to load client data", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditUpdatedClientTokens, map[string]interface{}{
            "clientId":     client.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        resp := api.UpdateClientResponse{Client: *api.ToClientResponse(client)}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}
