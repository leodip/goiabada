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

// userConsentsDatabase is what the administrator's user consent endpoints need: one user's
// consents and the clients they name.
// It embeds what the administrative policy reads to judge whether the user is an administrator,
// and revocation.Database for what a consent withdrawal revokes beside the row it deletes
// (#622).
type userConsentsDatabase interface {
	userTargetPolicyDatabase
	revocation.Database

	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentID int64) (bool, error)
	GetConsentsByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.UserConsent, error)
	GetUserByID(ctx context.Context, tx *sql.Tx, userID int64) (*record.User, error)
	GetUserConsentByID(ctx context.Context, tx *sql.Tx, userConsentID int64) (*record.UserConsent, error)
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error
}

func HandleUserConsentsGet(
	database userConsentsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user consents
		userConsents, err := database.GetConsentsByUserID(r.Context(), nil, user.ID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Load client details for consents
		err = database.UserConsentsLoadClients(r.Context(), nil, userConsents)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetUserConsentsResponse{
			Consents: apimapping.ToUserConsentResponses(userConsents),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleUserConsentDelete(
	database userConsentsDatabase,
	auditLogger AuditLogger,
	logoutTokens logoutTokenSender,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		// Get the consent to check if it exists and get user info for audit
		consent, err := database.GetUserConsentByID(r.Context(), nil, consentID)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if consent == nil {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, consent.UserID) {
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
			auditLogger.Log(r.Context(), audit.EventDeletedUserConsent, map[string]interface{}{
				"user_id":        consent.UserID,
				"consent_id":     consentID,
				"logged_in_user": callerSubject(r),
			})
		}
		// What the disconnect revoked, beside the deletion event and after the commit, as
		// TerminateUserSessionTx's callers record EventTerminatedUserSession (#135 decision 6).
		revocation.LogDisconnectedClient(r.Context(), auditLogger, consent.UserID, consent.ClientID,
			callerSubject(r), result)
		logoutTokens.Send(r.Context(), settings.Issuer, result.LogoutDeliveries)

		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
