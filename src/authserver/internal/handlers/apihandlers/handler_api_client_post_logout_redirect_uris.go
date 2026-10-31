package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleClientPostLogoutRedirectURIsPut - PUT /api/v1/admin/clients/{id}/post-logout-redirect-uris
//
// Replaces the whole of a client's sign-out redirect URIs, the addresses a sign-out may send the
// browser back to, and answers the updated client. It is the redirect URI save with the other list
// (#147 decisions 4 and 5): the same redirect-flow gate, the same entry and list rules through
// normalizeURIList, the same administrator-client ceiling, and the same transaction, which answers
// 409 when the stored list is not the one the caller loaded. It never reads or writes a redirect
// URI, so a sign-out landing page saved here never becomes a place an authorization code is sent.
func HandleClientPostLogoutRedirectURIsPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for sign-out redirect URIs update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// A sign-out returns from a sign-in made through a browser, and the authorization code
		// and implicit flows are the only ones that make one: a client with neither has no
		// sign-out to return from. The gate is the redirect URI save's, read the same way.
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !client.AuthorizationCodeEnabled && !client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientPostLogoutRedirectURIsNoRedirectFlow, nil))
			return
		}

		var req api.UpdateClientPostLogoutRedirectURIsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required: absent or null decodes to nil and is
		// refused, [] means the caller read an empty list (#428).
		if req.ExpectedPostLogoutRedirectURIs == nil {
			writeJSONError(w, "expectedPostLogoutRedirectURIs is required: send the sign-out redirect URIs as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		expected, loaded := loadedURIList(req.ExpectedPostLogoutRedirectURIs)

		normalized, refusal := normalizeURIList(req.PostLogoutRedirectURIs, loaded, postLogoutRedirectURIRefusals)
		if refusal != nil {
			writeValidationError(w, r, refusal)
			return
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		key := func(row record.PostLogoutRedirectURI) string { return strings.TrimSpace(row.URI) }
		rowId := func(row record.PostLogoutRedirectURI) int64 { return row.Id }

		// One transaction, as the redirect URI save's: a failure part way through commits nothing,
		// and the stored list is read on it, compared with the loaded one and planned from on every
		// attempt, so a deadlock victim rerun whole writes the same plan and nothing reaches the
		// response from inside it (#264, #301, #428).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			if loadErr := database.ClientLoadPostLogoutRedirectURIs(r.Context(), tx, client); loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client sign-out redirect URIs before update")
			}
			if !sameSet(client.PostLogoutRedirectURIs, key, expected) {
				return errListChanged
			}

			insert, remove := replaceSet(client.PostLogoutRedirectURIs, key, rowId, normalized)
			for _, removed := range remove {
				if deleteErr := database.DeletePostLogoutRedirectURI(r.Context(), tx, removed); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting sign-out redirect URI %d", removed)
				}
			}
			for _, uri := range insert {
				if createErr := database.CreatePostLogoutRedirectURI(r.Context(), tx, &record.PostLogoutRedirectURI{ClientId: client.Id, URI: uri}); createErr != nil {
					return errs.Wrap(createErr, "database error creating sign-out redirect URI")
				}
			}
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "client_id", client.Id)
			return
		}

		// Audit, once the save has committed.
		auditLogger.Log(r.Context(), audit.EventUpdatedPostLogoutRedirectURIs, map[string]interface{}{
			"client_id":      client.Id,
			"logged_in_user": callerSubject(r),
		})

		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after sign-out redirect URIs update"), "client_id", client.Id)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after update"), "client_id", client.Id)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after sign-out redirect URIs update"), "client_id", client.Id)
			return
		}

		writeJSON(w, r, http.StatusOK, api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)})
	}
}
