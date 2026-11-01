package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// A user's acceptances of legal documents (#622 decision 10): every version the user accepted, the
// latest first, with the address of each version's public page, which a retired document has none
// of. The user reads their own through the account API, and an administrator reads one user's
// through the admin API, as part of the user (the users-read scopes, decision 6). Acceptances are
// never edited or removed by hand, so both routes only read.

// accountLegalDocumentAcceptancesDatabase is what the caller's acceptances need: the caller, and
// what legaldocuments.AcceptedBy reads.
type accountLegalDocumentAcceptancesDatabase interface {
	legaldocuments.AcceptedDatabase

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
}

// HandleAccountLegalDocumentAcceptancesGet - GET /api/v1/account/legal-document-acceptances
func HandleAccountLegalDocumentAcceptancesGet(database accountLegalDocumentAcceptancesDatabase,
	baseURL string) http.HandlerFunc {

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

		writeLegalDocumentAcceptances(w, r, database, user, baseURL)
	}
}

// userLegalDocumentAcceptancesDatabase is what one user's acceptances need: the user, and what
// legaldocuments.AcceptedBy reads.
type userLegalDocumentAcceptancesDatabase interface {
	legaldocuments.AcceptedDatabase

	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// HandleUserLegalDocumentAcceptancesGet - GET /api/v1/admin/users/{id}/legal-document-acceptances
func HandleUserLegalDocumentAcceptancesGet(database userLegalDocumentAcceptancesDatabase,
	baseURL string) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for legal document acceptances"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		writeLegalDocumentAcceptances(w, r, database, user, baseURL)
	}
}

// writeLegalDocumentAcceptances answers the user's acceptances, the latest first.
func writeLegalDocumentAcceptances(w http.ResponseWriter, r *http.Request, database legaldocuments.AcceptedDatabase,
	user *record.User, baseURL string) {

	accepted, err := legaldocuments.AcceptedBy(r.Context(), database, user.Id)
	if err != nil {
		writeInternalServerError(w, r, err, "user_id", user.Id)
		return
	}

	response := api.GetLegalDocumentAcceptancesResponse{
		Acceptances: make([]api.LegalDocumentAcceptanceResponse, 0, len(accepted)),
	}
	for i := range accepted {
		a := &accepted[i]
		response.Acceptances = append(response.Acceptances,
			apimapping.ToLegalDocumentAcceptanceResponse(&a.Acceptance, &a.Document, &a.Version, baseURL))
	}
	writeJSON(w, r, http.StatusOK, response)
}
