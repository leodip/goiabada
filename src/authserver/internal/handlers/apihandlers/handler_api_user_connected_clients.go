package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/api"
)

// userConnectedClientsDatabase is what the administrator's connected clients of a user need: the
// user, beside what any user's connected clients need, and what the administrative policy reads
// to judge whether the user is an administrator (#135 decision 2).
type userConnectedClientsDatabase interface {
	connectedClientsDatabase
	userTargetPolicyDatabase

	GetUserByID(ctx context.Context, tx *sql.Tx, userID int64) (*record.User, error)
}

// GET /api/v1/admin/users/{id}/connected-clients
//
// The user's connected clients (#135 decision 4), each marked isCurrent when the user is the
// caller and the client is the one the calling token was issued to (decision 5): so only on the
// caller's own user, and never for a client credentials token, which is no user's.
func HandleUserConnectedClientsGet(
	database userConnectedClientsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		userID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		user, err := database.GetUserByID(r.Context(), nil, userID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		connected, err := connectedClientsOf(r.Context(), database, user.ID, time.Now().UTC())
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The caller is the listed user only on a token issued for a user, which carries auth_time, as
		// RequireUserBoundToken judges it. A client credentials token carries none, and its sub is its
		// client identifier, which a user's subject can equal.
		callerClient := ""
		if jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context()); ok {
			_, userBound := jwtToken.Claims["auth_time"]
			if subject := callerSubject(r); userBound && subject != "" && subject == user.Subject {
				callerClient = jwtToken.StringClaim("client_id")
			}
		}
		// Never nil: the schema declares clients a required array, and a nil slice marshals to null.
		rows := make([]api.ConnectedClientResponse, 0, len(connected))
		for _, c := range connected {
			isCurrent := callerClient != "" && c.client.ClientIdentifier == callerClient
			rows = append(rows, apimapping.ToUserConnectedClientResponse(c.client, c.consent, c.grantScope, isCurrent))
		}
		writeJSON(w, r, http.StatusOK, api.GetConnectedClientsResponse{Clients: rows})
	}
}

// DELETE /api/v1/admin/users/{id}/connected-clients/{clientId}
//
// Disconnects the client from the user, as the account DELETE does for the caller (#135
// decisions 1 and 2): 404 when the user or the client does not exist or the call had nothing to
// end, writing nothing and telling nobody. Only authserver:manage disconnects an administrator
// (#402 decision 1).
func HandleUserConnectedClientDelete(
	database userConnectedClientsDatabase,
	auditLogger AuditLogger,
	logoutTokens logoutTokenSender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		userID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		user, err := database.GetUserByID(r.Context(), nil, userID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		clientIDStr := r.PathValue("clientId")
		if clientIDStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		clientID, err := strconv.ParseInt(clientIDStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, clientID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if !userTargetCeilingAllows(w, r, database, auditLogger, user.ID) {
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		result, consentID, err := disconnectClient(r.Context(), database, user.ID, client.ID, settings)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The answer comes from what this call's own transaction changed (decision 2).
		if !result.Changed() {
			writeJSONError(w, "The user holds nothing with this client", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if result.ConsentDeleted {
			auditLogger.Log(r.Context(), audit.EventDeletedUserConsent, map[string]interface{}{
				"user_id":        user.ID,
				"consent_id":     consentID,
				"logged_in_user": callerSubject(r),
			})
		}
		revocation.LogDisconnectedClient(r.Context(), auditLogger, user.ID, client.ID, callerSubject(r), result)
		logoutTokens.Send(r.Context(), settings.Issuer, result.LogoutDeliveries)

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
