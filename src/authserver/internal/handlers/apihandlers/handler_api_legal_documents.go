package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/legalmarkdown"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The admin API's legal documents (#622), in the settings domain (decision 6): privacy notices and
// terms of use. A document holds at most one draft, edited as often as the administrator likes;
// Publish freezes it as the next numbered version, which is never rewritten (decision 1). A
// never-published document can be deleted, a published one only retired and restored, and its kind
// never changes (decision 2). Its short name, its public address, is unique and fixed at the first
// publish (decision 5). A retired document is read only until it is restored.

// legalDocumentsDatabase is what the legal document endpoints need: the documents, their versions,
// and the transaction a publish and a delete run in.
type legalDocumentsDatabase interface {
	CreateLegalDocument(ctx context.Context, tx *sql.Tx, legalDocument *record.LegalDocument) error
	UpdateLegalDocument(ctx context.Context, tx *sql.Tx, legalDocument *record.LegalDocument) error
	GetLegalDocumentById(ctx context.Context, tx *sql.Tx, legalDocumentId int64) (*record.LegalDocument, error)
	GetLegalDocumentByShortName(ctx context.Context, tx *sql.Tx, shortName string) (*record.LegalDocument, error)
	GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error)
	DeleteLegalDocument(ctx context.Context, tx *sql.Tx, legalDocumentId int64) error
	CreateLegalDocumentVersion(ctx context.Context, tx *sql.Tx, version *record.LegalDocumentVersion) error
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
	GetLegalDocumentVersion(ctx context.Context, tx *sql.Tx, legalDocumentId int64, versionNumber int) (*record.LegalDocumentVersion, error)
	GetLegalDocumentClientsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentClient, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// legalDocumentShortNameRe is the short name's shape: lowercase ASCII letters, digits and hyphens,
// starting and ending with a letter or a digit, so it reads as one path segment of
// /legal/<short-name> (decision 5).
var legalDocumentShortNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// The refusals a publish decides inside its transaction, on the document as read there. Each is
// answered after the transaction has rolled back.
var (
	errLegalDocumentNotFound   = errors.New("the legal document does not exist")
	errLegalDocumentRetired    = errors.New("the legal document is retired")
	errLegalDocumentNoDraft    = errors.New("the legal document has no draft")
	errLegalDocumentDraftEmpty = errors.New("the legal document's draft has no text")
	errLegalDocumentPublished  = errors.New("the legal document has a published version")
)

// validateLegalDocumentShortName holds a short name to its shape and bound.
func validateLegalDocumentShortName(shortName string) error {
	if shortName == "" {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameRequired, nil)
	}
	if len(shortName) > record.LegalDocumentShortNameMaxLength {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameTooLong,
			map[string]any{"max": record.LegalDocumentShortNameMaxLength})
	}
	if !legalDocumentShortNameRe.MatchString(shortName) {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameInvalid, nil)
	}
	return nil
}

// validateLegalDocumentText holds a title, trimmed, and the Markdown, as written, to their bounds.
// An empty Markdown is a draft not yet written, which Publish refuses.
func validateLegalDocumentText(title, markdown string) error {
	if title == "" {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentTitleRequired, nil)
	}
	if inputvalidation.TextLength(title) > record.LegalDocumentTitleMaxLength {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentTitleTooLong,
			map[string]any{"max": record.LegalDocumentTitleMaxLength})
	}
	return validateLegalDocumentMarkdown(markdown)
}

func validateLegalDocumentMarkdown(markdown string) error {
	if inputvalidation.TextLength(markdown) > record.LegalDocumentMarkdownMaxLength {
		return i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentMarkdownTooLong,
			map[string]any{"max": record.LegalDocumentMarkdownMaxLength})
	}
	return nil
}

// legalDocumentId reads the {id} path value, answering the request when it is not an id.
func legalDocumentId(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, "Invalid legal document ID", "VALIDATION_ERROR", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// loadLegalDocument reads the document the path names, answering the request when it cannot.
func loadLegalDocument(w http.ResponseWriter, r *http.Request, database legalDocumentsDatabase) (*record.LegalDocument, bool) {
	id, ok := legalDocumentId(w, r)
	if !ok {
		return nil, false
	}
	doc, err := database.GetLegalDocumentById(r.Context(), nil, id)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document by ID"), "legal_document_id", id)
		return nil, false
	}
	if doc == nil {
		writeLegalDocumentNotFound(w)
		return nil, false
	}
	return doc, true
}

func writeLegalDocumentNotFound(w http.ResponseWriter) {
	writeJSONError(w, "Legal document not found", "NOT_FOUND", http.StatusNotFound)
}

// legalDocumentVersions reads a document's versions, the first first, answering the request when
// it cannot.
func legalDocumentVersions(w http.ResponseWriter, r *http.Request, database legalDocumentsDatabase,
	doc *record.LegalDocument) ([]record.LegalDocumentVersion, bool) {
	versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(r.Context(), nil, doc.Id)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document versions"), "legal_document_id", doc.Id)
		return nil, false
	}
	return versions, true
}

// legalDocumentApps reads the apps a document lists, answering the request when it cannot.
func legalDocumentApps(w http.ResponseWriter, r *http.Request, database legalDocumentsDatabase,
	doc *record.LegalDocument) ([]record.LegalDocumentClient, bool) {
	links, err := database.GetLegalDocumentClientsByLegalDocumentId(r.Context(), nil, doc.Id)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document apps"), "legal_document_id", doc.Id)
		return nil, false
	}
	return links, true
}

// writeLegalDocumentDetail answers the document with its draft, its versions and the apps it
// lists, which it reads first, answering the request when it cannot.
func writeLegalDocumentDetail(w http.ResponseWriter, r *http.Request, database legalDocumentsDatabase,
	doc *record.LegalDocument, versions []record.LegalDocumentVersion) {
	links, ok := legalDocumentApps(w, r, database, doc)
	if !ok {
		return
	}
	writeJSON(w, r, http.StatusOK, apimapping.ToLegalDocumentDetailResponse(doc, versions, links))
}

// shortNameIsFree reports whether no other document holds shortName, answering the request when
// one does or the read fails.
func shortNameIsFree(w http.ResponseWriter, r *http.Request, database legalDocumentsDatabase, shortName string, self int64) bool {
	holder, err := database.GetLegalDocumentByShortName(r.Context(), nil, shortName)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error checking legal document short name"), "short_name", shortName)
		return false
	}
	if holder != nil && holder.Id != self {
		writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameInUse, nil))
		return false
	}
	return true
}

// shortNameTaken answers a document write the engine refused on the short name's unique key,
// which a save committed between this request's check and its write took: the same refusal as the
// check's. It reports whether it answered.
func shortNameTaken(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, data.ErrUniqueViolation) {
		return false
	}
	writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameInUse, nil))
	return true
}

func HandleLegalDocumentsGet(database legalDocumentsDatabase) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		docs, err := database.GetAllLegalDocuments(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting all legal documents"))
			return
		}

		response := api.GetLegalDocumentsResponse{LegalDocuments: make([]api.LegalDocumentResponse, 0, len(docs))}
		for i := range docs {
			versions, ok := legalDocumentVersions(w, r, database, &docs[i])
			if !ok {
				return
			}
			links, ok := legalDocumentApps(w, r, database, &docs[i])
			if !ok {
				return
			}
			var current *record.LegalDocumentVersion
			if len(versions) > 0 {
				current = &versions[len(versions)-1]
			}
			response.LegalDocuments = append(response.LegalDocuments, apimapping.ToLegalDocumentResponse(&docs[i], current, links))
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleLegalDocumentCreatePost(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var req api.CreateLegalDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		if req.Kind != record.LegalDocumentKindMustAccept && req.Kind != record.LegalDocumentKindForInformation {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentKindInvalid, nil))
			return
		}
		shortName := strings.TrimSpace(req.ShortName)
		if err := validateLegalDocumentShortName(shortName); err != nil {
			writeValidationError(w, r, err)
			return
		}
		title := strings.TrimSpace(req.Title)
		if err := validateLegalDocumentText(title, req.Markdown); err != nil {
			writeValidationError(w, r, err)
			return
		}
		if !shortNameIsFree(w, r, database, shortName, 0) {
			return
		}

		// A new document applies to all apps, the default; the editor's app picker narrows it.
		doc := &record.LegalDocument{
			ShortName:        shortName,
			Kind:             req.Kind,
			DraftTitle:       sql.NullString{String: title, Valid: true},
			DraftMarkdown:    sql.NullString{String: req.Markdown, Valid: true},
			AppliesToAllApps: true,
		}
		if err := database.CreateLegalDocument(r.Context(), nil, doc); err != nil {
			if !shortNameTaken(w, r, err) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error creating legal document"), "short_name", shortName)
			}
			return
		}

		auditLogger.Log(r.Context(), audit.EventCreatedLegalDocument, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"kind":              doc.Kind,
			"logged_in_user":    callerSubject(r),
		})

		// A document just created lists no app, so there is nothing to read back.
		writeJSON(w, r, http.StatusCreated, apimapping.ToLegalDocumentDetailResponse(doc, nil, nil))
	}
}

func HandleLegalDocumentGet(database legalDocumentsDatabase) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}
		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}

		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

func HandleLegalDocumentDraftPut(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}

		var req api.SaveLegalDocumentDraftRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		if doc.IsRetired() {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentRetired, nil))
			return
		}
		title := strings.TrimSpace(req.Title)
		if err := validateLegalDocumentText(title, req.Markdown); err != nil {
			writeValidationError(w, r, err)
			return
		}

		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}

		// An empty short name keeps the document's. Another one is taken only until the first
		// publish: from then on links to /legal/<short-name> are out there (decision 5).
		shortName := strings.TrimSpace(req.ShortName)
		if shortName != "" && shortName != doc.ShortName {
			if len(versions) > 0 {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentShortNameFixed, nil))
				return
			}
			if err := validateLegalDocumentShortName(shortName); err != nil {
				writeValidationError(w, r, err)
				return
			}
			if !shortNameIsFree(w, r, database, shortName, doc.Id) {
				return
			}
			doc.ShortName = shortName
		}

		doc.DraftTitle = sql.NullString{String: title, Valid: true}
		doc.DraftMarkdown = sql.NullString{String: req.Markdown, Valid: true}
		if err := database.UpdateLegalDocument(r.Context(), nil, doc); err != nil {
			if !shortNameTaken(w, r, err) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error saving legal document draft"), "legal_document_id", doc.Id)
			}
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedLegalDocumentDraft, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"logged_in_user":    callerSubject(r),
		})

		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

func HandleLegalDocumentPreviewPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var req api.PreviewLegalDocumentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		if err := validateLegalDocumentMarkdown(req.Markdown); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// The renderer the published page uses, so the preview is what users will read (decision 4).
		html, err := legalmarkdown.Render(req.Markdown)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		writeJSON(w, r, http.StatusOK, api.PreviewLegalDocumentResponse{Html: string(html)})
	}
}

// HandleLegalDocumentPublishPost freezes the draft as the next version and clears it, in one
// transaction that reads the document and its versions under it. Two publishes racing for one
// number meet the versions' unique key, and the loser is answered 409 with nothing written.
func HandleLegalDocumentPublishPost(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, ok := legalDocumentId(w, r)
		if !ok {
			return
		}

		var doc *record.LegalDocument
		var versions []record.LegalDocumentVersion
		var published *record.LegalDocumentVersion
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			var err error
			doc, err = database.GetLegalDocumentById(r.Context(), tx, id)
			if err != nil {
				return errs.Wrap(err, "database error getting legal document to publish")
			}
			switch {
			case doc == nil:
				return errLegalDocumentNotFound
			case doc.IsRetired():
				return errLegalDocumentRetired
			case !doc.HasDraft():
				return errLegalDocumentNoDraft
			case strings.TrimSpace(doc.DraftMarkdown.String) == "":
				return errLegalDocumentDraftEmpty
			}

			versions, err = database.GetLegalDocumentVersionsByLegalDocumentId(r.Context(), tx, id)
			if err != nil {
				return errs.Wrap(err, "database error getting legal document versions to publish")
			}
			next := 1
			if len(versions) > 0 {
				next = versions[len(versions)-1].VersionNumber + 1
			}
			published = &record.LegalDocumentVersion{
				PublishedAt:     time.Now().UTC(),
				LegalDocumentId: doc.Id,
				VersionNumber:   next,
				Title:           doc.DraftTitle.String,
				Markdown:        doc.DraftMarkdown.String,
			}
			if err := database.CreateLegalDocumentVersion(r.Context(), tx, published); err != nil {
				return errs.Wrap(err, "database error creating legal document version")
			}
			versions = append(versions, *published)

			doc.DraftTitle = sql.NullString{}
			doc.DraftMarkdown = sql.NullString{}
			if err := database.UpdateLegalDocument(r.Context(), tx, doc); err != nil {
				return errs.Wrap(err, "database error clearing published legal document draft")
			}
			return nil
		})
		switch {
		case errors.Is(err, errLegalDocumentNotFound):
			writeLegalDocumentNotFound(w)
			return
		case errors.Is(err, errLegalDocumentRetired):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentRetired, nil))
			return
		case errors.Is(err, errLegalDocumentNoDraft):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentNoDraft, nil))
			return
		case errors.Is(err, errLegalDocumentDraftEmpty):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentDraftEmpty, nil))
			return
		case errors.Is(err, data.ErrUniqueViolation):
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentPublishedConcurrently, nil),
				"CONCURRENT_UPDATE", http.StatusConflict)
			return
		case err != nil:
			writeInternalServerError(w, r, err, "legal_document_id", id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventPublishedLegalDocument, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"version":           published.VersionNumber,
			"logged_in_user":    callerSubject(r),
		})

		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

// HandleLegalDocumentRetirePost retires a published document: it applies to no one from then on,
// and its versions stay (decision 2).
func HandleLegalDocumentRetirePost(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}
		if doc.IsRetired() {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentAlreadyRetired, nil))
			return
		}
		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}
		if len(versions) == 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentNotPublished, nil))
			return
		}

		doc.RetiredAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		if err := database.UpdateLegalDocument(r.Context(), nil, doc); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error retiring legal document"), "legal_document_id", doc.Id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventRetiredLegalDocument, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"logged_in_user":    callerSubject(r),
		})

		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

// HandleLegalDocumentRestorePost restores a retired document as it was, its current version
// included, so earlier acceptances of that version still count (decision 2).
func HandleLegalDocumentRestorePost(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}
		if !doc.IsRetired() {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentNotRetired, nil))
			return
		}
		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}

		doc.RetiredAt = sql.NullTime{}
		if err := database.UpdateLegalDocument(r.Context(), nil, doc); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error restoring legal document"), "legal_document_id", doc.Id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventRestoredLegalDocument, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"logged_in_user":    callerSubject(r),
		})

		writeLegalDocumentDetail(w, r, database, doc, versions)
	}
}

// HandleLegalDocumentDelete deletes a document that was never published. The versions are read
// again in the transaction that deletes it; a publish committed between that read and the delete
// is refused by the engine, whose foreign key from a version has no cascade.
func HandleLegalDocumentDelete(database legalDocumentsDatabase, auditLogger AuditLogger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}

		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(r.Context(), tx, doc.Id)
			if err != nil {
				return errs.Wrap(err, "database error getting legal document versions to delete")
			}
			if len(versions) > 0 {
				return errLegalDocumentPublished
			}
			if err := database.DeleteLegalDocument(r.Context(), tx, doc.Id); err != nil {
				return errs.Wrap(err, "database error deleting legal document")
			}
			return nil
		})
		if errors.Is(err, errLegalDocumentPublished) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeLegalDocumentPublishedNotDeleted, nil))
			return
		}
		if err != nil {
			writeInternalServerError(w, r, err, "legal_document_id", doc.Id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventDeletedLegalDocument, map[string]interface{}{
			"legal_document_id": doc.Id,
			"short_name":        doc.ShortName,
			"logged_in_user":    callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}

// HandleLegalDocumentVersionGet answers one published version with its text, a retired document's
// included: the admin console shows what users accepted whatever became of the document.
func HandleLegalDocumentVersionGet(database legalDocumentsDatabase) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		number, err := strconv.Atoi(r.PathValue("version"))
		if err != nil || number <= 0 {
			writeJSONError(w, "Invalid version number", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		doc, ok := loadLegalDocument(w, r, database)
		if !ok {
			return
		}

		version, err := database.GetLegalDocumentVersion(r.Context(), nil, doc.Id, number)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting legal document version"),
				"legal_document_id", doc.Id, "version", number)
			return
		}
		if version == nil {
			writeJSONError(w, "Legal document version not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		versions, ok := legalDocumentVersions(w, r, database, doc)
		if !ok {
			return
		}
		links, ok := legalDocumentApps(w, r, database, doc)
		if !ok {
			return
		}
		var current *record.LegalDocumentVersion
		if len(versions) > 0 {
			current = &versions[len(versions)-1]
		}

		writeJSON(w, r, http.StatusOK, api.GetLegalDocumentVersionResponse{
			LegalDocument: apimapping.ToLegalDocumentResponse(doc, current, links),
			Version:       apimapping.ToLegalDocumentVersionResponse(version),
		})
	}
}
