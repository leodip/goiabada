package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// A legal document's Applies to (#622): all apps, the default, or the apps an administrator
// selects. The document's apps are chosen in the settings domain, with the document (decision 6);
// a client's documents are read as part of the client, with the clients-read scopes. A document set
// to selected apps whose list is empty, its last app deleted or every app taken off, applies to
// nobody: it is never turned into all apps behind the administrator's back. Changing a document's
// apps needs no new version and leaves its acceptances as they are. The admin console's own client
// is never asked to accept a document, so it is never one of a document's apps.

// legalDocumentAppsDatabase is what choosing a document's apps needs: the document, its apps, the
// clients it names, and the transaction the list save runs in.
type legalDocumentAppsDatabase interface {
	legalDocumentsDatabase
	CreateLegalDocumentClient(ctx context.Context, tx *sql.Tx, link *record.LegalDocumentClient) error
	DeleteLegalDocumentClient(ctx context.Context, tx *sql.Tx, legalDocumentClientId int64) error
	UpdateLegalDocumentAppliesToAllApps(ctx context.Context, tx *sql.Tx, legalDocumentId int64, appliesToAllApps bool) error
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
}

// HandleLegalDocumentAppsPut - PUT /api/v1/admin/legal-documents/{id}/apps
//
// Sets the document's Applies to and replaces its whole list of apps, as a list save does (#428):
// the request's 400s and 404s first, then one transaction that takes the document's row and reads
// the document again under it, refuses a document retired meanwhile, and refuses with 409 unless the stored list is the one the caller
// loaded.
func HandleLegalDocumentAppsPut(database legalDocumentAppsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}

		var req api.UpdateLegalDocumentAppsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required as on every list save: absent or null decodes
		// to nil and is refused, [] means the caller read an empty list (#428).
		if req.ExpectedClientIds == nil {
			writeJSONError(w, "expectedClientIds is required: send the client ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if doc.IsRetired() {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentRetired, nil))
			return
		}

		var allApps bool
		switch req.AppliesTo {
		case record.LegalDocumentAppliesToAllApps:
			allApps = true
		case record.LegalDocumentAppliesToSelectedApps:
			allApps = false
		default:
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentAppliesToInvalid, nil))
			return
		}

		wanted := firstOccurrences(req.ClientIds)
		if allApps && len(wanted) > 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentAppsWithAllApps, nil))
			return
		}

		for _, clientId := range wanted {
			client, err := database.GetClientById(r.Context(), nil, clientId)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for legal document apps"),
					"client_id", clientId, "legal_document_id", doc.Id)
				return
			}
			if client == nil {
				writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			if client.IsSystemLevelClient() {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentAdminConsoleClient, nil))
				return
			}
		}

		listedKey := func(link record.LegalDocumentClient) int64 { return link.ClientId }
		listedId := func(link record.LegalDocumentClient) int64 { return link.Id }

		// One transaction, rerun whole after a deadlock (#301), with nothing written to the response
		// inside it. The list itself is not locked, as for every list save: the stored list must be
		// the one the caller loaded, and an app both add meets the unique key, answered 409 (#428).
		// The document's row is taken, for its retirement.
		added, removed := []int64{}, []int64{}
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			// The document's row, as every lifecycle write takes it, so a retirement cannot
			// commit between this check and this save's commit.
			current, getErr := lockLegalDocument(r.Context(), database, tx, doc.Id)
			if getErr != nil {
				return getErr
			}
			if current.IsRetired() {
				return errLegalDocumentRetired
			}

			stored, loadErr := database.GetLegalDocumentClientsByLegalDocumentId(r.Context(), tx, doc.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading legal document apps before update")
			}
			if !sameSet(stored, listedKey, req.ExpectedClientIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, listedKey, listedId, wanted)
			for _, rowId := range remove {
				if deleteErr := database.DeleteLegalDocumentClient(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting legal document client %d", rowId)
				}
			}
			for _, clientId := range insert {
				if createErr := database.CreateLegalDocumentClient(r.Context(), tx, &record.LegalDocumentClient{
					LegalDocumentId: doc.Id,
					ClientId:        clientId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error listing client %d on legal document", clientId)
				}
			}
			if current.AppliesToAllApps != allApps {
				if updateErr := database.UpdateLegalDocumentAppliesToAllApps(r.Context(), tx, doc.Id, allApps); updateErr != nil {
					return errs.Wrap(updateErr, "database error updating legal document applies to")
				}
			}
			// Assigned only by an attempt that reached its end. Never nil, so the record names an
			// empty list rather than null.
			added = append([]int64{}, insert...)
			removed = append([]int64{}, revokedKeys(stored, listedKey, wanted)...)
			return nil
		})
		switch {
		case errors.Is(err, errLegalDocumentNotFound):
			writeLegalDocumentNotFound(w)
			return
		case errors.Is(err, errLegalDocumentRetired):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentRetired, nil))
			return
		case err != nil:
			writeListSaveFailure(w, r, err, "legal_document_id", doc.Id)
			return
		}
		doc.AppliesToAllApps = allApps

		auditLogger.Log(r.Context(), audit.EventUpdatedLegalDocumentApps, map[string]interface{}{
			"legal_document_id":  doc.Id,
			"short_name":         doc.ShortName,
			"applies_to":         doc.AppliesTo(),
			"added_client_ids":   added,
			"removed_client_ids": removed,
			"logged_in_user":     callerSubject(r),
		})

		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}
		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

// clientLegalDocumentsDatabase is what a client's documents need: the client, every document, the
// documents that list the client, and each document's versions and apps.
type clientLegalDocumentsDatabase interface {
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error)
	GetLegalDocumentClientsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.LegalDocumentClient, error)
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
	GetLegalDocumentClientsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentClient, error)
}

// HandleClientLegalDocumentsGet - GET /api/v1/admin/clients/{id}/legal-documents
//
// The documents that apply to the client, for its page in the admin console to list read only:
// every document not retired, published or not, that applies to all apps or lists the client, in
// id order. A retired document applies to no app (decision 2).
func HandleClientLegalDocumentsGet(database clientLegalDocumentsDatabase) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for legal documents"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		docs, err := database.GetAllLegalDocuments(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting all legal documents"), "client_id", client.Id)
			return
		}
		listing, err := database.GetLegalDocumentClientsByClientId(r.Context(), nil, client.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting the client's legal documents"), "client_id", client.Id)
			return
		}
		listedOn := make(map[int64]bool, len(listing))
		for _, link := range listing {
			listedOn[link.LegalDocumentId] = true
		}

		response := api.GetClientLegalDocumentsResponse{
			Client:         *apimapping.ToClientResponse(client),
			LegalDocuments: []api.LegalDocumentResponse{},
		}
		for i := range docs {
			doc := &docs[i]
			if doc.IsRetired() || (!doc.AppliesToAllApps && !listedOn[doc.Id]) {
				continue
			}
			versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(r.Context(), nil, doc.Id)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document versions"), "legal_document_id", doc.Id)
				return
			}
			links, err := database.GetLegalDocumentClientsByLegalDocumentId(r.Context(), nil, doc.Id)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document apps"), "legal_document_id", doc.Id)
				return
			}
			var current *record.LegalDocumentVersion
			if len(versions) > 0 {
				current = &versions[len(versions)-1]
			}
			response.LegalDocuments = append(response.LegalDocuments, apimapping.ToLegalDocumentResponse(doc, current, links))
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
