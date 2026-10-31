package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// legalDocumentColumns is the legal_documents table as scanLegalDocument reads it.
var legalDocumentColumns = columnList{
	sqlite:   "id, created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps",
	mysql:    "id, created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps",
	postgres: "id, created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps",
	mssql:    "id, created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps",
}

// scanLegalDocument reads one row selected with legalDocumentColumns.
func scanLegalDocument(row rowScanner, doc *record.LegalDocument) error {
	return row.Scan(
		&doc.Id,
		&doc.CreatedAt,
		&doc.UpdatedAt,
		&doc.ShortName,
		&doc.Kind,
		&doc.DraftTitle,
		&doc.DraftMarkdown,
		&doc.RetiredAt,
		&doc.AppliesToAllApps,
	)
}

var insertLegalDocument = statement{
	sqlite: "INSERT INTO legal_documents (created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO legal_documents (created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO legal_documents (created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
	mssql: "INSERT INTO legal_documents (created_at, updated_at, short_name, kind, draft_title, draft_markdown, retired_at, applies_to_all_apps) " +
		"OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8)",
}

// updateLegalDocument writes the whole row but created_at, kind and applies_to_all_apps, which are
// dont-update: a document's kind is fixed when it is created (#622 decision 2), and its Applies to
// is written by updateLegalDocumentAppliesToAllApps alone, so a draft saved from an older read
// cannot put back an Applies to changed since.
var updateLegalDocument = statement{
	sqlite: "UPDATE legal_documents SET updated_at = ?, short_name = ?, draft_title = ?, draft_markdown = ?, retired_at = ? " +
		"WHERE id = ?",
	mysql: "UPDATE legal_documents SET updated_at = ?, short_name = ?, draft_title = ?, draft_markdown = ?, retired_at = ? " +
		"WHERE id = ?",
	postgres: "UPDATE legal_documents SET updated_at = $1, short_name = $2, draft_title = $3, draft_markdown = $4, retired_at = $5 " +
		"WHERE id = $6",
	mssql: "UPDATE legal_documents SET updated_at = @p1, short_name = @p2, draft_title = @p3, draft_markdown = @p4, retired_at = @p5 " +
		"WHERE id = @p6",
}

// updateLegalDocumentAppliesToAllApps writes a document's Applies to, and nothing else of its row.
var updateLegalDocumentAppliesToAllApps = statement{
	sqlite:   "UPDATE legal_documents SET updated_at = ?, applies_to_all_apps = ? WHERE id = ?",
	mysql:    "UPDATE legal_documents SET updated_at = ?, applies_to_all_apps = ? WHERE id = ?",
	postgres: "UPDATE legal_documents SET updated_at = $1, applies_to_all_apps = $2 WHERE id = $3",
	mssql:    "UPDATE legal_documents SET updated_at = @p1, applies_to_all_apps = @p2 WHERE id = @p3",
}

var selectLegalDocumentById = statement{
	sqlite:   "SELECT " + legalDocumentColumns.sqlite + " FROM legal_documents WHERE id = ?",
	mysql:    "SELECT " + legalDocumentColumns.mysql + " FROM legal_documents WHERE id = ?",
	postgres: "SELECT " + legalDocumentColumns.postgres + " FROM legal_documents WHERE id = $1",
	mssql:    "SELECT " + legalDocumentColumns.mssql + " FROM legal_documents WHERE id = @p1",
}

var selectLegalDocumentByShortName = statement{
	sqlite:   "SELECT " + legalDocumentColumns.sqlite + " FROM legal_documents WHERE short_name = ?",
	mysql:    "SELECT " + legalDocumentColumns.mysql + " FROM legal_documents WHERE short_name = ?",
	postgres: "SELECT " + legalDocumentColumns.postgres + " FROM legal_documents WHERE short_name = $1",
	mssql:    "SELECT " + legalDocumentColumns.mssql + " FROM legal_documents WHERE short_name = @p1",
}

var selectAllLegalDocuments = statement{
	sqlite:   "SELECT " + legalDocumentColumns.sqlite + " FROM legal_documents ORDER BY id",
	mysql:    "SELECT " + legalDocumentColumns.mysql + " FROM legal_documents ORDER BY id",
	postgres: "SELECT " + legalDocumentColumns.postgres + " FROM legal_documents ORDER BY id",
	mssql:    "SELECT " + legalDocumentColumns.mssql + " FROM legal_documents ORDER BY id",
}

var deleteLegalDocument = statement{
	sqlite:   "DELETE FROM legal_documents WHERE id = ?",
	mysql:    "DELETE FROM legal_documents WHERE id = ?",
	postgres: "DELETE FROM legal_documents WHERE id = $1",
	mssql:    "DELETE FROM legal_documents WHERE id = @p1",
}

// legalDocumentVersionColumns is the legal_document_versions table as scanLegalDocumentVersion
// reads it.
var legalDocumentVersionColumns = columnList{
	sqlite:   "id, published_at, legal_document_id, version_number, title, markdown",
	mysql:    "id, published_at, legal_document_id, version_number, title, markdown",
	postgres: "id, published_at, legal_document_id, version_number, title, markdown",
	mssql:    "id, published_at, legal_document_id, version_number, title, markdown",
}

// scanLegalDocumentVersion reads one row selected with legalDocumentVersionColumns.
func scanLegalDocumentVersion(row rowScanner, version *record.LegalDocumentVersion) error {
	return row.Scan(
		&version.Id,
		&version.PublishedAt,
		&version.LegalDocumentId,
		&version.VersionNumber,
		&version.Title,
		&version.Markdown,
	)
}

// insertLegalDocumentVersion is the one write a version ever gets: there is no update statement,
// so a published version is never rewritten (#622 decision 1).
var insertLegalDocumentVersion = statement{
	sqlite: "INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) " +
		"VALUES (?, ?, ?, ?, ?)",
	mysql: "INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) " +
		"VALUES (?, ?, ?, ?, ?)",
	postgres: "INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) " +
		"VALUES ($1, $2, $3, $4, $5) RETURNING id",
	mssql: "INSERT INTO legal_document_versions (published_at, legal_document_id, version_number, title, markdown) " +
		"OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5)",
}

var selectLegalDocumentVersionsByLegalDocumentId = statement{
	sqlite: "SELECT " + legalDocumentVersionColumns.sqlite + " FROM legal_document_versions " +
		"WHERE legal_document_id = ? ORDER BY version_number",
	mysql: "SELECT " + legalDocumentVersionColumns.mysql + " FROM legal_document_versions " +
		"WHERE legal_document_id = ? ORDER BY version_number",
	postgres: "SELECT " + legalDocumentVersionColumns.postgres + " FROM legal_document_versions " +
		"WHERE legal_document_id = $1 ORDER BY version_number",
	mssql: "SELECT " + legalDocumentVersionColumns.mssql + " FROM legal_document_versions " +
		"WHERE legal_document_id = @p1 ORDER BY version_number",
}

var selectLegalDocumentVersion = statement{
	sqlite: "SELECT " + legalDocumentVersionColumns.sqlite + " FROM legal_document_versions " +
		"WHERE legal_document_id = ? AND version_number = ?",
	mysql: "SELECT " + legalDocumentVersionColumns.mysql + " FROM legal_document_versions " +
		"WHERE legal_document_id = ? AND version_number = ?",
	postgres: "SELECT " + legalDocumentVersionColumns.postgres + " FROM legal_document_versions " +
		"WHERE legal_document_id = $1 AND version_number = $2",
	mssql: "SELECT " + legalDocumentVersionColumns.mssql + " FROM legal_document_versions " +
		"WHERE legal_document_id = @p1 AND version_number = @p2",
}

func (d *Database) CreateLegalDocument(ctx context.Context, tx *sql.Tx, legalDocument *record.LegalDocument) error {

	now := time.Now().UTC()

	originalCreatedAt := legalDocument.CreatedAt
	originalUpdatedAt := legalDocument.UpdatedAt
	legalDocument.CreatedAt = sql.NullTime{Time: now, Valid: true}
	legalDocument.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertLegalDocument, "legal document",
		legalDocument.CreatedAt, legalDocument.UpdatedAt, legalDocument.ShortName, legalDocument.Kind,
		legalDocument.DraftTitle, legalDocument.DraftMarkdown, legalDocument.RetiredAt, legalDocument.AppliesToAllApps)
	if err != nil {
		legalDocument.CreatedAt = originalCreatedAt
		legalDocument.UpdatedAt = originalUpdatedAt
		return err
	}

	legalDocument.Id = id
	return nil
}

func (d *Database) UpdateLegalDocument(ctx context.Context, tx *sql.Tx, legalDocument *record.LegalDocument) error {

	if legalDocument.Id == 0 {
		return errs.New("can't update legal document with id 0")
	}

	originalUpdatedAt := legalDocument.UpdatedAt
	legalDocument.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateLegalDocument.text(d.Dialect),
		legalDocument.UpdatedAt, legalDocument.ShortName, legalDocument.DraftTitle, legalDocument.DraftMarkdown,
		legalDocument.RetiredAt, legalDocument.Id)
	if err != nil {
		legalDocument.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update legal document")
	}

	return nil
}

func (d *Database) UpdateLegalDocumentAppliesToAllApps(ctx context.Context, tx *sql.Tx, legalDocumentId int64,
	appliesToAllApps bool) error {

	if legalDocumentId == 0 {
		return errs.New("can't update the applies to of legal document with id 0")
	}

	_, err := d.ExecSQL(ctx, tx, updateLegalDocumentAppliesToAllApps.text(d.Dialect),
		sql.NullTime{Time: time.Now().UTC(), Valid: true}, appliesToAllApps, legalDocumentId)
	if err != nil {
		return errs.Wrap(err, "unable to update legal document applies to")
	}

	return nil
}

func (d *Database) GetLegalDocumentById(ctx context.Context, tx *sql.Tx, legalDocumentId int64) (*record.LegalDocument, error) {
	return queryOne(ctx, d, tx, selectLegalDocumentById.text(d.Dialect), []any{legalDocumentId},
		scanLegalDocument, "legal document")
}

func (d *Database) GetLegalDocumentByShortName(ctx context.Context, tx *sql.Tx, shortName string) (*record.LegalDocument, error) {

	doc, err := queryOne(ctx, d, tx, selectLegalDocumentByShortName.text(d.Dialect), []any{shortName},
		scanLegalDocument, "legal document")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for, as SQL Server pads a
	// trailing space for =; see engineFoldedTheMatch. A short name is the document's address, so
	// it is matched exactly.
	if doc != nil && engineFoldedTheMatch(doc.ShortName, shortName) {
		return nil, nil
	}

	return doc, nil
}

func (d *Database) GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error) {
	return queryAll(ctx, d, tx, nil, selectAllLegalDocuments.text(d.Dialect), nil, scanLegalDocument, "legal document")
}

func (d *Database) DeleteLegalDocument(ctx context.Context, tx *sql.Tx, legalDocumentId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteLegalDocument.text(d.Dialect), legalDocumentId)
	if err != nil {
		return errs.Wrap(err, "unable to delete legal document")
	}

	return nil
}

func (d *Database) CreateLegalDocumentVersion(ctx context.Context, tx *sql.Tx, version *record.LegalDocumentVersion) error {

	id, err := d.insert(ctx, tx, insertLegalDocumentVersion, "legal document version",
		version.PublishedAt, version.LegalDocumentId, version.VersionNumber, version.Title, version.Markdown)
	if err != nil {
		return err
	}

	version.Id = id
	return nil
}

func (d *Database) GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx,
	legalDocumentId int64) ([]record.LegalDocumentVersion, error) {
	return queryAll(ctx, d, tx, nil, selectLegalDocumentVersionsByLegalDocumentId.text(d.Dialect),
		[]any{legalDocumentId}, scanLegalDocumentVersion, "legal document version")
}

func (d *Database) GetLegalDocumentVersion(ctx context.Context, tx *sql.Tx, legalDocumentId int64,
	versionNumber int) (*record.LegalDocumentVersion, error) {
	return queryOne(ctx, d, tx, selectLegalDocumentVersion.text(d.Dialect), []any{legalDocumentId, versionNumber},
		scanLegalDocumentVersion, "legal document version")
}
