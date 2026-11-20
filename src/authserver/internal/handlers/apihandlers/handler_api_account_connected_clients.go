package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/api"
)

// connectedClientsDatabase is what a user's connected clients need on either API: the user's
// consents and live grants and the clients those name, for the list; and, for the disconnect, the
// client and the consent it deletes, beside what revocation.Database revokes (#135 decisions 1, 2
// and 4).
type connectedClientsDatabase interface {
	revocation.Database

	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) (bool, error)
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	GetConsentByUserIdAndClientIdForUpdate(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error)
	GetLiveGrantsByUserId(ctx context.Context, tx *sql.Tx, userId int64, now time.Time) ([]record.LiveGrant, error)
}

// accountConnectedClientsDatabase is what the account's connected clients need: the caller, beside
// what any user's connected clients need.
type accountConnectedClientsDatabase interface {
	connectedClientsDatabase

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
}

// connectedClient is one client a user is connected to, as the list reads it: the client, its
// stored consent or nil, and the scopes its live grants record, merged.
type connectedClient struct {
	client     *record.Client
	consent    *record.UserConsent
	grantScope string
}

// connectedClientsOf reads the clients the user is connected to, in client id order: every client
// the user holds a stored consent with or a live refresh token with (#135 decision 4). A client
// that is only on one of the user's sessions is not one, since a disconnect leaves those rows. Each
// client's grant scope is the scopes its live refresh tokens record, in the order they first appear
// across the tokens taken oldest first, each once.
func connectedClientsOf(ctx context.Context, database connectedClientsDatabase, userId int64,
	now time.Time) ([]connectedClient, error) {

	consents, err := database.GetConsentsByUserId(ctx, nil, userId)
	if err != nil {
		return nil, err
	}
	grants, err := database.GetLiveGrantsByUserId(ctx, nil, userId, now)
	if err != nil {
		return nil, err
	}

	consentOf := map[int64]*record.UserConsent{}
	for i := range consents {
		if _, seen := consentOf[consents[i].ClientId]; !seen {
			consentOf[consents[i].ClientId] = &consents[i]
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].RefreshTokenId < grants[j].RefreshTokenId })
	scopesOf := map[int64][]string{}
	for _, grant := range grants {
		for _, scope := range strings.Fields(grant.Scope) {
			if !slices.Contains(scopesOf[grant.ClientId], scope) {
				scopesOf[grant.ClientId] = append(scopesOf[grant.ClientId], scope)
			}
		}
		if _, listed := scopesOf[grant.ClientId]; !listed {
			// A live grant recording no scope still connects its client.
			scopesOf[grant.ClientId] = []string{}
		}
	}

	clientIds := make([]int64, 0, len(consentOf)+len(scopesOf))
	for clientId := range consentOf {
		clientIds = append(clientIds, clientId)
	}
	for clientId := range scopesOf {
		if _, withConsent := consentOf[clientId]; !withConsent {
			clientIds = append(clientIds, clientId)
		}
	}
	sort.Slice(clientIds, func(i, j int) bool { return clientIds[i] < clientIds[j] })

	clients, err := database.GetClientsByIds(ctx, nil, clientIds)
	if err != nil {
		return nil, err
	}
	clientOf := map[int64]*record.Client{}
	for i := range clients {
		clientOf[clients[i].Id] = &clients[i]
	}

	connected := make([]connectedClient, 0, len(clientIds))
	for _, clientId := range clientIds {
		client, found := clientOf[clientId]
		if !found {
			// Deleted between the reads: its consents and tokens went with it.
			continue
		}
		connected = append(connected, connectedClient{
			client:     client,
			consent:    consentOf[clientId],
			grantScope: strings.Join(scopesOf[clientId], " "),
		})
	}
	return connected, nil
}

// disconnectClient disconnects the client from the user: revocation.DisconnectClientTx, the
// operation a consent withdrawal runs, deleting the user's consent to the client when there is one
// (#135 decisions 1 and 2). It answers what the transaction changed and the id of the consent it
// deleted, zero when it deleted none.
func disconnectClient(ctx context.Context, database connectedClientsDatabase, userId int64, clientId int64,
	settings *record.Settings) (revocation.DisconnectResult, int64, error) {

	// The consent is read inside the transaction, with a locking read, so a consent given between
	// the request's reads and its sweep is deleted with the rest: on MySQL an ordinary read would
	// answer the snapshot the transaction's earlier read of the client fixed (#135 decision 1). The
	// body can run again after a deadlock, so the id is set afresh on each attempt.
	var consentId int64
	result, err := revocation.DisconnectClientTx(ctx, database, userId, clientId,
		sessionLive(settings), func(tx *sql.Tx) (bool, error) {
			consentId = 0
			consent, getErr := database.GetConsentByUserIdAndClientIdForUpdate(ctx, tx, userId, clientId)
			if getErr != nil || consent == nil {
				return false, getErr
			}
			consentId = consent.Id
			return database.DeleteUserConsent(ctx, tx, consent.Id)
		})
	if err != nil || !result.ConsentDeleted {
		consentId = 0
	}
	return result, consentId, err
}

// GET /api/v1/account/connected-clients
//
// The caller's connected clients (#135 decision 4), each marked isCurrent when it is the client the
// calling token was issued to (decision 5): the token's client_id claim, the client identifier the
// token was issued for.
func HandleAccountConnectedClientsGet(
	database accountConnectedClientsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtToken, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		connected, err := connectedClientsOf(r.Context(), database, user.Id, time.Now().UTC())
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		callerClient := jwtToken.StringClaim("client_id")
		// Never nil: the schema declares clients a required array, and a nil slice marshals to null.
		rows := make([]api.ConnectedClientResponse, 0, len(connected))
		for _, c := range connected {
			isCurrent := callerClient != "" && c.client.ClientIdentifier == callerClient
			rows = append(rows, apimapping.ToAccountConnectedClientResponse(c.client, c.consent, c.grantScope, isCurrent))
		}
		writeJSON(w, r, http.StatusOK, api.GetConnectedClientsResponse{Clients: rows})
	}
}

// DELETE /api/v1/account/connected-clients/{clientId}
//
// Disconnects the client from the caller: revocation.DisconnectClientTx, the operation a consent
// withdrawal runs, deleting the caller's consent to it when there is one (#135 decisions 1 and 2).
// It answers 404 when the client does not exist or the call had nothing to end, writing nothing and
// telling nobody. The calling token's own client is disconnected like any other (decision 5).
func HandleAccountConnectedClientDelete(
	database accountConnectedClientsDatabase,
	auditLogger AuditLogger,
	logoutTokens logoutTokenSender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		idStr := r.PathValue("clientId")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(r.Context(), nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		result, consentId, err := disconnectClient(r.Context(), database, user.Id, client.Id, settings)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The answer comes from what this call's own transaction changed: a user who held nothing
		// with the client, or whose last grant another request ended first, gets 404 (decision 2).
		if !result.Changed() {
			writeJSONError(w, "The user holds nothing with this client", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if result.ConsentDeleted {
			auditLogger.Log(r.Context(), audit.EventDeletedOwnUserConsent, map[string]interface{}{
				"user_id":        user.Id,
				"consent_id":     consentId,
				"logged_in_user": subject,
			})
		}
		revocation.LogDisconnectedClient(r.Context(), auditLogger, user.Id, client.Id, subject, result)
		logoutTokens.Send(r.Context(), settings.Issuer, result.LogoutDeliveries)

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
