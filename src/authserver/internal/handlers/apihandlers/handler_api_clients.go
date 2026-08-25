package apihandlers

import (
	"database/sql"
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
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/urlutil"
	"github.com/leodip/goiabada/core/validators"
	"github.com/pkg/errors"
)

// updateClientNotOwningAuthenticationMode writes a client through an endpoint that changes some
// other part of it. Three of them exist (general settings, OAuth2 flows, token settings) and none
// of them means to touch how the client authenticates, but UpdateClient writes every mutable
// column, so each one silently carries is_public and client_secret_encrypted from the copy it
// loaded at the top of the request back into the row.
//
// That is a lost update with a security consequence, which is why it is closed here rather than
// left to the general concurrency of the endpoint. A save whose loaded copy said "public" and
// whose row now says "confidential" restores public mode and deletes the newer secret, and the
// handler doing it has no revocation of its own, so the client's outstanding grants stay
// redeemable with nothing presented. The confidential-to-public flip is the only write allowed to
// change this, and it revokes (#245, final review finding 1).
//
// So the two authentication-owned columns are re-read INSIDE the transaction and copied over
// whatever the caller is holding, which makes the change structurally impossible rather than
// merely unintended.
//
// REFRESHING THE MODE IS NOT ENOUGH ON ITS OWN, because two other columns are derived from it.
// A public client must carry pkce_required true and client_credentials_enabled false, and every
// one of these endpoints writes both columns from its own snapshot. So a save that loaded the
// client while it was confidential, with PKCE optional and client credentials on, would preserve
// the refreshed public mode and restore both forbidden values underneath it. The server would
// still refuse client credentials and still require PKCE at runtime, because both rules are read
// at the point of use, but the stored row, the admin API's response and the console would all
// report the opposite of what the server does, which is the display lie decision 2 exists to
// prevent. applyPublicClientInvariants therefore runs on every caller's behalf, after the
// refresh and before the write (#245, final review round 2 finding 2).
//
// It does not close the lost update on the columns each endpoint DOES own: two concurrent saves
// of the same section still last-write-wins, which is how every entity in this codebase behaves
// and is a separate, wider question.
func updateClientNotOwningAuthenticationMode(database data.Database, client *models.Client) error {
	tx, err := database.BeginTransaction()
	if err != nil {
		return err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	current, err := database.GetClientById(tx, client.Id)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.WithStack(errors.New("client no longer exists"))
	}
	client.IsPublic = current.IsPublic
	client.ClientSecretEncrypted = current.ClientSecretEncrypted

	applyPublicClientInvariants(client)

	if err := database.UpdateClient(tx, client); err != nil {
		return err
	}
	return database.CommitTransaction(tx)
}

// applyPublicClientInvariants forces the two columns a public client is not allowed to
// contradict. One definition, called by every writer that can persist them, because the defect
// this closes was the same rule living at one write site and not the others.
//
// Both are storage-side corrections rather than enforcement: the server already refuses client
// credentials for a public client and already requires its PKCE whatever these columns hold. What
// they buy is that the row, the API response built from it and the admin console's rendering of
// it all say what the server will actually do. A stale false or a nil pkce_required is handed
// straight back to a reader, and under a global-off deployment nil renders as "inherit from the
// global setting (currently: optional)", which is the display lie decision 2 exists to prevent
// (#245).
func applyPublicClientInvariants(client *models.Client) {
	if !client.IsPublic {
		return
	}
	// Public clients cannot use the client credentials flow.
	client.ClientCredentialsEnabled = false
	// A public client always requires PKCE, so a caller's own value is not read for one:
	// normalized rather than refused with a 400, so the two public-client rules behave the same
	// way. It is not silent, because these endpoints answer with the updated client and a caller
	// who sent false reads back true.
	pkceRequired := true
	client.PKCERequired = &pkceRequired
}

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
			clientSecretDecrypted, err := encryption.DecryptData(client.ClientSecretEncrypted)
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

		// Sanitize and validate display name
		sanitizedDisplayName := strings.TrimSpace(inputSanitizer.Sanitize(req.DisplayName))
		const maxLengthDisplayName = 100
		if len(sanitizedDisplayName) > maxLengthDisplayName {
			writeJSONError(w, "The display name cannot exceed a maximum length of "+strconv.Itoa(maxLengthDisplayName)+" characters.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate identifier format
		if err := identifierValidator.ValidateIdentifier(req.ClientIdentifier, true); err != nil {
			writeValidationError(w, r, err)
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
		clientSecret := stringutil.GenerateSecurityRandomString(60)
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		if err != nil {
			slog.Error("AuthServer API: Failed to encrypt client secret", "error", err)
			writeJSONError(w, "Failed to create client", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Create client model mimicking current implementation defaults
		client := &models.Client{
			ClientIdentifier:                        strings.TrimSpace(inputSanitizer.Sanitize(req.ClientIdentifier)),
			Description:                             strings.TrimSpace(inputSanitizer.Sanitize(req.Description)),
			DisplayName:                             sanitizedDisplayName,
			ShowDisplayName:                         sanitizedDisplayName != "",
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

		// Sanitize and prepare the new identifier value
		sanitizedClientIdentifier := strings.TrimSpace(inputSanitizer.Sanitize(updateReq.ClientIdentifier))

		// The identifier is checked only when the request actually submits a different one, and
		// that is load bearing rather than an optimisation. A client that registered itself is
		// given "dcr_" plus a UUID, which is 40 characters, and ValidateIdentifier caps an
		// identifier at 38: re-checking an unchanged value therefore rejected every update to every
		// self-registered client, whatever the request was trying to change. That made the escape
		// hatch this change depends on unusable, since turning consent off for one reviewed client
		// is done on the same form (#108, decision 17).
		//
		// Compared byte for byte against what is stored, deliberately, rather than against the
		// sanitized value. "  same-identifier  " has always been refused as an invalid format and
		// still is; only a request submitting exactly what is already there skips the check. That
		// also makes the skip provably safe: an identifier that is already stored passed this same
		// validator, so it holds no character the sanitizer would touch, and the assignment below
		// writes back the bytes that are already in the row.
		//
		// Skipping the uniqueness query alongside it changes nothing either: it excludes the
		// current client, so an unchanged identifier can only ever match the row being updated.
		if updateReq.ClientIdentifier != client.ClientIdentifier {
			// Validate identifier format
			if err := identifierValidator.ValidateIdentifier(updateReq.ClientIdentifier, true); err != nil {
				writeValidationError(w, r, err)
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
		}

		// ACR level validation depending on AuthorizationCodeEnabled
		if !client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultAcrLevel) != "" {
			writeJSONError(w, "Default ACR level is not applicable when authorization code flow is disabled.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate website URL (optional field)
		websiteURL := strings.TrimSpace(updateReq.WebsiteURL)
		if websiteURL != "" {
			const maxLengthWebsiteURL = 256
			if len(websiteURL) > maxLengthWebsiteURL {
				writeJSONError(w, "The website URL cannot exceed a maximum length of "+strconv.Itoa(maxLengthWebsiteURL)+" characters.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			parsed, err := url.ParseRequestURI(websiteURL)
			if err != nil {
				writeJSONError(w, "Invalid website URL.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				writeJSONError(w, "Website URL must use http or https scheme.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		}

		// System-level client protection: block identifier changes
		if client.IsSystemLevelClient() && sanitizedClientIdentifier != client.ClientIdentifier {
			writeJSONError(w, "The identifier of a system-level client cannot be changed.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Self-registered client protection: block identifier changes too. Until the created_via_dcr
		// column existed, the dcr_ identifier prefix was the only record that a client had
		// registered itself, so renaming one here erased that fact permanently: migration 000029
		// backfills from the prefix, and a client renamed before the upgrade is left unmarked, with
		// consent off, still issuing codes with no consent screen. The column makes new renames
		// harmless to the backfill, and blocking the rename keeps the prefix and the column saying
		// the same thing for anything that still reads a client identifier, a log line or an
		// operator's eye included (#108, decision 16).
		//
		// It blocks the rename and nothing else. Every other setting on a self-registered client
		// stays editable, Consent required above all: unticking it for one reviewed client is the
		// escape hatch this whole change rests on, so a guard that refused the update outright
		// would take away the remedy along with the risk.
		if client.CreatedViaDCR && sanitizedClientIdentifier != client.ClientIdentifier {
			writeJSONError(w, "The identifier of a self-registered client cannot be changed.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client.ClientIdentifier = sanitizedClientIdentifier
		client.Description = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.Description))
		client.WebsiteURL = websiteURL
		client.DisplayName = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.DisplayName))

		// Validate display name length after sanitization
		const maxLengthDisplayName = 100
		if len(client.DisplayName) > maxLengthDisplayName {
			writeJSONError(w, "The display name cannot exceed a maximum length of "+strconv.Itoa(maxLengthDisplayName)+" characters.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client.Enabled = updateReq.Enabled
		client.ConsentRequired = updateReq.ConsentRequired
		client.ShowLogo = updateReq.ShowLogo
		client.ShowDisplayName = updateReq.ShowDisplayName
		client.ShowDescription = updateReq.ShowDescription
		client.ShowWebsiteURL = updateReq.ShowWebsiteURL

		if client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultAcrLevel) != "" {
			acrLevel, err := enums.AcrLevelFromString(updateReq.DefaultAcrLevel)
			if err != nil {
				writeJSONError(w, "Invalid default ACR level", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			client.DefaultAcrLevel = acrLevel
		}

		if err := updateClientNotOwningAuthenticationMode(database, client); err != nil {
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

		var req api.UpdateClientAuthenticationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		if req.IsPublic {
			// Switching to public: remove secret and disable client credentials
			client.IsPublic = true
			client.ClientSecretEncrypted = nil
			// Client credentials off and PKCE required, from the one definition every writer
			// that can persist those two columns shares (#245).
			applyPublicClientInvariants(client)
		} else {
			// Confidential: require strong secret
			if err := validateClientSecret(req.ClientSecret); err != nil {
				writeJSONError(w, "Invalid client secret. Please generate a new one.", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}

			enc, err := encryption.EncryptData(req.ClientSecret)
			if err != nil {
				slog.Error("AuthServer API: Failed to encrypt client secret", "error", err, "clientId", client.Id)
				writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			client.IsPublic = false
			client.ClientSecretEncrypted = enc
			// Preserve ClientCredentialsEnabled as-is
		}

		// The confidential-to-public transition is the one that REMOVES the requirement for the
		// client to authenticate, so it is the one that revokes: every grant this client holds
		// was issued on the understanding that redeeming it took a secret, and after this write
		// nothing is presented at all. The reverse transition closes a window rather than opening
		// one, and rotating a confidential client's secret leaves the requirement in place;
		// revoking on either would sign real users out to protect against nothing (#245).
		//
		// The client write and the revocation share one transaction so the secret cannot be
		// destroyed while the grants it was protecting survive. The audit event is emitted after
		// the commit, because a logged revocation that then rolled back would be a false record.
		//
		// WHICH TRANSITION THIS IS, IS DECIDED INSIDE THAT TRANSACTION, against the row as it
		// stands rather than against the copy loaded above. The two are not the same client: a
		// concurrent request can make this client confidential and issue it a grant between the
		// load and the write, and a classification taken from the stale copy then reads "already
		// public", skips the revocation, and commits a public client holding grants that were
		// issued while a secret was required. Reading it here costs one query inside a
		// transaction the flip already opens (#245, final review finding 1).
		if req.IsPublic {
			var becamePublic bool
			result, err := handlers.RevokeClientGrantsTx(database, client.Id, func(tx *sql.Tx) (bool, error) {
				current, err := database.GetClientById(tx, client.Id)
				if err != nil {
					return false, err
				}
				if current == nil {
					return false, errors.WithStack(errors.New("client no longer exists"))
				}
				becamePublic = !current.IsPublic
				if err := database.UpdateClient(tx, client); err != nil {
					return false, err
				}
				return becamePublic, nil
			})
			if err != nil {
				slog.Error("AuthServer API: Database error updating client authentication", "error", err, "clientId", client.Id)
				writeJSONError(w, "Failed to update client", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			// Only a write that really performed the transition gets the event. A save of an
			// already-public client revoked nothing and must not claim to.
			if becamePublic {
				handlers.LogRevokedClientGrants(auditLogger, client.Id,
					handlers.RevocationReasonClientBecamePublic, authHelper.GetLoggedInSubject(r), result)
			}
		} else if err := database.UpdateClient(nil, client); err != nil {
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

		var req api.UpdateClientOAuth2FlowsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Apply changes with current business rules
		client.AuthorizationCodeEnabled = req.AuthorizationCodeEnabled
		client.ClientCredentialsEnabled = req.ClientCredentialsEnabled
		client.PKCERequired = req.PKCERequired
		client.ImplicitGrantEnabled = req.ImplicitGrantEnabled
		client.ResourceOwnerPasswordCredentialsEnabled = req.ResourceOwnerPasswordCredentialsEnabled

		// The two public-client rules are applied by the writer below, inside the write's
		// transaction and against the is_public the row really carries. They cannot run out
		// here: this endpoint reloads the client at the top of the request, and a client that
		// became public in between would have its two rules skipped and be saved with client
		// credentials on and PKCE off, which is the state this whole change exists to make
		// unreachable (#245, final review finding 1).
		if err := updateClientNotOwningAuthenticationMode(database, client); err != nil {
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
			// url.ParseRequestURI above accepts "//evil.example/cb", "/relative/cb",
			// "http://host/cb#frag" and "https:///evil.example/cb", every one of which is
			// later emitted verbatim into a Location header. RFC 6749 section 3.1.2 is what
			// refuses them, through the same predicate dynamic registration and the
			// authorization endpoint use. Ordered after the parse and before the duplicate
			// check, mirroring the dynamic registration gate.
			//
			// Only the absolute-URI rule crosses over from dynamic registration, not that
			// endpoint's scheme denylist or excluded-character set. The absolute-URI rule is
			// a protocol requirement and binds an administrator exactly as it binds an
			// anonymous registrant; the other two exist because that caller is anonymous,
			// and an administrator has legitimate reasons to register a custom scheme (#122).
			//
			// Accepted cost: this PUT replaces the whole set, so a deployment still holding a
			// legacy non-absolute row cannot save this page until the administrator removes
			// that URI from the list. The message names the offending value, and taking that
			// remediation also deletes the row.
			if !urlutil.IsAbsoluteRedirectURI(uri) {
				writeJSONError(w, fmt.Sprintf("Redirect URI must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host): %s", uri), "VALIDATION_ERROR", http.StatusBadRequest)
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

		// Validate three-state settings
		if _, err := enums.ThreeStateSettingFromString(strings.TrimSpace(req.IncludeOpenIDConnectClaimsInAccessToken)); err != nil {
			writeJSONError(w, "Invalid value for includeOpenIDConnectClaimsInAccessToken.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		if _, err := enums.ThreeStateSettingFromString(strings.TrimSpace(req.IncludeOpenIDConnectClaimsInIdToken)); err != nil {
			writeJSONError(w, "Invalid value for includeOpenIDConnectClaimsInIdToken.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply updates
		client.TokenExpirationInSeconds = req.TokenExpirationInSeconds
		client.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
		client.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
		client.IncludeOpenIDConnectClaimsInAccessToken = strings.TrimSpace(req.IncludeOpenIDConnectClaimsInAccessToken)
		client.IncludeOpenIDConnectClaimsInIdToken = strings.TrimSpace(req.IncludeOpenIDConnectClaimsInIdToken)

		if err := updateClientNotOwningAuthenticationMode(database, client); err != nil {
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
