package apihandlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// The two ways the row read under the client's lock refuses a save the earlier read let through.
var (
	// errBackchannelLogoutHTTPNotAllowed is an http URI on a client that may no longer have one: one
	// made public since it was loaded.
	errBackchannelLogoutHTTPNotAllowed = errors.New("an http back-channel logout URI on a client that may not have one")
	// errBackchannelLogoutURICeiling is a save below authserver:manage that, compared with the row,
	// sets the URI or changes it: another save changed the URI since this one's caller loaded it.
	errBackchannelLogoutURICeiling = errors.New("a back-channel logout URI change reserved to authserver:manage")
)

// HandleClientBackchannelLogoutPut - PUT /api/v1/admin/clients/{id}/backchannel-logout
//
// Sets a client's back-channel logout URI, where the auth server POSTs a logout token when a session
// the client was on ends, and whether the client requires the session identifier in every one
// (OpenID Connect Back-Channel Logout 1.0 section 2.2), and answers the client (#784 decision 9).
//
// Both fields are required, so a body cannot clear what it does not mention. An empty URI clears
// it. A URI follows decision 6's rule, urlmatch.CheckBackchannelLogoutURI: https on any client,
// http only on a confidential one an administrator created (urlmatch.BackchannelLogoutHTTPAllowed),
// the same rule the sender holds a stored URI to, decided again on the row read under the client's
// lock, as the other client saves decide what they preserve. A URI is refused for a
// client with neither the authorization code nor the implicit flow, as the sign-out redirect URIs
// are: such a client signs nobody in, so no session it is on can end.
//
// Only an authserver:manage token sets a URI or changes the stored one, since an administrator's URI
// reaches any address the auth server can (#784 decision 15); clearing it, or changing the flag
// alone, stays open to authserver:manage-clients. The refusal is decided before the transaction
// against the row as read, and the comparison is made again under the lock, as the decision
// compares it: a save below authserver:manage carrying back a URI another save changed meanwhile
// would set a URI the ceiling never judged, and is refused as the first comparison refuses, 403
// MANAGE_SCOPE_REQUIRED and administrator_change_refused, once the transaction has rolled back. The
// administrator-client ceiling comes first, as on every client save.
// updated_client_backchannel_logout is recorded once the save has committed.
func HandleClientBackchannelLogoutPut(
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
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for back-channel logout update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientBackchannelLogoutRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		// Absent or null is refused rather than read as empty or false: a body that leaves a field
		// out must not clear it.
		if req.BackchannelLogoutURI == nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURIRequired, nil))
			return
		}
		if req.BackchannelLogoutSessionRequired == nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutSessionRequiredRequired, nil))
			return
		}
		uri := strings.TrimSpace(*req.BackchannelLogoutURI)
		sessionRequired := *req.BackchannelLogoutSessionRequired

		if uri != "" {
			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				writeInternalServerError(w, r, reqctx.ErrNoSettings)
				return
			}
			if !client.AuthorizationCodeEnabled && !client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled) {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutNoSignInFlow, nil))
				return
			}
			if refusal := backchannelLogoutURIRefusal(uri, client); refusal != nil {
				writeValidationError(w, r, refusal)
				return
			}
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1), and only
		// authserver:manage sets or changes the URI (#784 decision 15).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}
		if !backchannelLogoutURICeilingAllows(w, r, auditLogger, client, uri) {
			return
		}
		holdsManage := callerHoldsManage(r)

		// Opened through RunInTransaction, so a deadlock reruns the acquisition, the read and the
		// write together; each attempt decides from the row read under its own lock and writes
		// fixed values, and nothing reaches the response from inside it (#301).
		var saved *record.Client
		// httpRefusal is the refusal of an http URI the row under the lock no longer allows, and
		// refusedRow the row the ceiling refused under the lock, each assigned by the attempt that
		// returned its error.
		var httpRefusal *i18n.LocalizedError
		var refusedRow *record.Client
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			httpRefusal, refusedRow = nil, nil
			if acquireErr := database.AcquireClientRow(r.Context(), tx, client.Id); acquireErr != nil {
				return acquireErr
			}
			current, readErr := database.GetClientById(r.Context(), tx, client.Id)
			if readErr != nil {
				return readErr
			}
			if current == nil {
				return errs.New("client no longer exists")
			}
			if uri != "" && urlmatch.CheckBackchannelLogoutURI(uri, urlmatch.BackchannelLogoutHTTPAllowed(current.IsPublic, current.CreatedViaDCR)) == urlmatch.BackchannelLogoutURIPlainHTTP {
				httpRefusal = backchannelLogoutHTTPRefusal(uri, current)
				return errBackchannelLogoutHTTPNotAllowed
			}
			if !holdsManage && backchannelLogoutURIChangeReserved(current.BackchannelLogoutURI, uri) {
				refusedRow = current
				return errBackchannelLogoutURICeiling
			}
			if setErr := database.SetClientBackchannelLogout(r.Context(), tx, client.Id, uri, sessionRequired); setErr != nil {
				return setErr
			}
			current.BackchannelLogoutURI = uri
			current.BackchannelLogoutSessionRequired = sessionRequired
			saved = current
			return nil
		})
		switch {
		case errors.Is(err, errBackchannelLogoutHTTPNotAllowed):
			writeValidationError(w, r, httpRefusal)
			return
		case errors.Is(err, errBackchannelLogoutURICeiling):
			// The same ceiling as before the transaction, judging the row read under the lock, so the
			// same refusal and record, written now that the transaction has rolled back.
			if !backchannelLogoutURICeilingAllows(w, r, auditLogger, refusedRow, uri) {
				return
			}
			writeInternalServerError(w, r, errs.New("the back-channel logout URI ceiling refused under the client's row and allowed after it"), "client_id", client.Id)
			return
		case err != nil:
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client back-channel logout"), "client_id", client.Id)
			return
		}

		// The save has committed: it is recorded now, before the reads building the answer, whose
		// failure answers 500 but does not undo the change.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientBackchannelLogout, map[string]interface{}{
			"client_id":      saved.Id,
			"logged_in_user": callerSubject(r),
		})

		if err := database.ClientLoadRedirectURIs(r.Context(), nil, saved); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after back-channel logout update"), "client_id", saved.Id)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, saved); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after back-channel logout update"), "client_id", saved.Id)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, saved); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after back-channel logout update"), "client_id", saved.Id)
			return
		}

		writeJSON(w, r, http.StatusOK, api.UpdateClientResponse{Client: *apimapping.ToClientResponse(saved)})
	}
}

// backchannelLogoutURIRefusal is the admin API's refusal of a back-channel logout URI that breaks
// decision 6's rule for client, in the request's language, or nil for one it admits.
func backchannelLogoutURIRefusal(uri string, client *record.Client) *i18n.LocalizedError {
	switch urlmatch.CheckBackchannelLogoutURI(uri, urlmatch.BackchannelLogoutHTTPAllowed(client.IsPublic, client.CreatedViaDCR)) {
	case urlmatch.BackchannelLogoutURIAcceptable:
		return nil
	case urlmatch.BackchannelLogoutURITooLong:
		// The message names the value by its beginning rather than echoing the whole body back.
		return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURITooLong, map[string]any{
			"length": len(uri), "max": urlmatch.BackchannelLogoutURIMaxBytes, "prefix": strings.ToValidUTF8(uri[:80], "")})
	case urlmatch.BackchannelLogoutURISchemeNotHTTP:
		return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURISchemeInvalid, map[string]any{"uri": uri})
	case urlmatch.BackchannelLogoutURIUserinfo:
		return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURIUserinfo, map[string]any{"uri": uri})
	case urlmatch.BackchannelLogoutURIPlainHTTP:
		return backchannelLogoutHTTPRefusal(uri, client)
	default:
		return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURIInvalid, map[string]any{"uri": uri})
	}
}

// backchannelLogoutHTTPRefusal is the refusal of an http URI on client, which may not have one: a
// self-registered client, of either type, or a public one an administrator created.
func backchannelLogoutHTTPRefusal(uri string, client *record.Client) *i18n.LocalizedError {
	if client.CreatedViaDCR {
		return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURIHTTPSelfRegistered, map[string]any{"uri": uri})
	}
	return i18n.NewLocalizedError(i18n.ErrCodeClientBackchannelLogoutURIHTTPPublicClient, map[string]any{"uri": uri})
}
