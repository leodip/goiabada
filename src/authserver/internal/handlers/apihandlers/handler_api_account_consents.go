package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/api"
)

// accountConsentsDatabase is what the account consent endpoints need: the caller's consents and
// the clients they name. It embeds revocation.Database for what a consent withdrawal
// revokes beside the row it deletes (#622).
type accountConsentsDatabase interface {
	revocation.Database

	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentID int64) (bool, error)
	GetConsentsByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.UserConsent, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserConsentByID(ctx context.Context, tx *sql.Tx, userConsentID int64) (*record.UserConsent, error)
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error
}

// GET /api/v1/account/consents
func HandleAccountConsentsGet(
	database accountConsentsDatabase,
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

		consents, err := database.GetConsentsByUserID(r.Context(), nil, user.ID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if err := database.UserConsentsLoadClients(r.Context(), nil, consents); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		resp := api.GetUserConsentsResponse{Consents: apimapping.ToAccountConsentResponses(consents)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// DELETE /api/v1/account/consents/{id}
func HandleAccountConsentDelete(
	database accountConsentsDatabase,
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

		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Consent ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		consentID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid consent ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		consent, err := database.GetUserConsentByID(r.Context(), nil, consentID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if consent == nil {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Ownership check: must belong to current user
		if consent.UserID != user.ID {
			writeJSONError(w, "Forbidden", "FORBIDDEN", http.StatusForbidden)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// Withdrawing a consent disconnects its client: the same transaction deletes the consent,
		// revokes the codes this user has not yet redeemed with that client and the refresh
		// tokens this user holds with it (#622, #135 decision 1). The refresh arm consults a
		// stored consent only when the client has Consent required on or the grant is an
		// offline one, so deleting the row alone would leave a once-consented client's grant
		// standing. It also collects the logout tokens that tell the client (#135 decision 3).
		result, err := revocation.DisconnectClientTx(r.Context(), database, consent.UserID, consent.ClientID,
			sessionLive(settings), func(tx *sql.Tx) (bool, error) {
				return database.DeleteUserConsent(r.Context(), tx, consentID)
			})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The answer comes from what this call's own transaction changed, not from the read
		// above: a consent another request deleted meanwhile, with nothing else left to end, is
		// answered as a repeated DELETE is, and that request wrote the record (#135 decision 2).
		if !result.Changed() {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if result.ConsentDeleted {
			auditLogger.Log(r.Context(), audit.EventDeletedOwnUserConsent, map[string]interface{}{
				"user_id":        user.ID,
				"consent_id":     consentID,
				"logged_in_user": subject,
			})
		}
		// What the disconnect revoked, beside the deletion event and after the commit, as
		// TerminateUserSessionTx's callers record EventTerminatedUserSession (#135 decision 6).
		revocation.LogDisconnectedClient(r.Context(), auditLogger, consent.UserID, consent.ClientID,
			subject, result)
		logoutTokens.Send(r.Context(), settings.Issuer, result.LogoutDeliveries)

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
