package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleClientDPoPPut - PUT /api/v1/admin/clients/{id}/dpop
//
// Sets a client's "Require DPoP for token requests", RFC 9449 section 5.2's
// dpop_bound_access_tokens, and answers the client as stored (#42 decision 12). While it is on, the
// token endpoint refuses the client's token requests without a DPoP proof, and the authorization
// endpoint refuses it the response types that return an access token (decision 13).
//
// dpopBoundAccessTokens is required: absent or null is refused rather than read as false, so a body
// that says nothing cannot switch the requirement off. The admin console calls the auth server with
// Bearer tokens, so its own client is refused it on, 400 with a localized validation error, as that
// client's other protected settings are; off is what it already is, and is saved. The route takes
// the scopes of the client's other settings, and the administrator-client ceiling applies as on
// every client save. The column has this one writer beside CreateClient (dont-update), so the
// write needs no row lock: it writes a fixed value and no other save writes the column back. It is
// recorded as updated_client_dpop as soon as it is written, before the reads answering it can fail.
func HandleClientDPoPPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for dpop update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientDPoPRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		if req.DPoPBoundAccessTokens == nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDPoPBoundAccessTokensRequired, nil))
			return
		}
		required := *req.DPoPBoundAccessTokens

		if client.IsSystemLevelClient() && required {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDPoPAdminConsoleNotAllowed, nil))
			return
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		if err = database.SetClientDPoPBoundAccessTokens(r.Context(), nil, client.Id, required); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client dpop requirement"), "client_id", client.Id)
			return
		}

		// The write ran outside any transaction, so it has committed: it is recorded now, before the
		// reads building the answer, whose failure answers 500 but does not undo the change.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientDPoP, map[string]interface{}{
			"client_id":                client.Id,
			"client_identifier":        client.ClientIdentifier,
			"dpop_bound_access_tokens": required,
			"logged_in_user":           callerSubject(r),
		})

		// The answer is the row as stored, read back after the write.
		client, err = database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client after dpop update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		if err = database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after dpop update"), "client_id", client.Id)
			return
		}
		if err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after dpop update"), "client_id", client.Id)
			return
		}
		if err = database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after dpop update"), "client_id", client.Id)
			return
		}

		writeJSON(w, r, http.StatusOK, api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)})
	}
}
