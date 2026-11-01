package commondb

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// A user's acceptances of legal document versions (#622). A row is written once and never
// rewritten, so there is no whole-row UPDATE, and none is deleted by hand: deleting the user
// removes it.

// legalDocumentAcceptanceColumns is the legal_document_acceptances table as
// scanLegalDocumentAcceptance reads it.
var legalDocumentAcceptanceColumns = columnList{
	sqlite:   "id, accepted_at, user_id, legal_document_version_id",
	mysql:    "id, accepted_at, user_id, legal_document_version_id",
	postgres: "id, accepted_at, user_id, legal_document_version_id",
	mssql:    "id, accepted_at, user_id, legal_document_version_id",
}

// scanLegalDocumentAcceptance reads one row selected with legalDocumentAcceptanceColumns.
func scanLegalDocumentAcceptance(row rowScanner, acceptance *record.LegalDocumentAcceptance) error {
	return row.Scan(
		&acceptance.Id,
		&acceptance.AcceptedAt,
		&acceptance.UserId,
		&acceptance.LegalDocumentVersionId,
	)
}

var insertLegalDocumentAcceptance = statement{
	sqlite:   "INSERT INTO legal_document_acceptances (accepted_at, user_id, legal_document_version_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO legal_document_acceptances (accepted_at, user_id, legal_document_version_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO legal_document_acceptances (accepted_at, user_id, legal_document_version_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO legal_document_acceptances (accepted_at, user_id, legal_document_version_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectLegalDocumentAcceptancesByUserId = statement{
	sqlite:   "SELECT " + legalDocumentAcceptanceColumns.sqlite + " FROM legal_document_acceptances WHERE user_id = ? ORDER BY id",
	mysql:    "SELECT " + legalDocumentAcceptanceColumns.mysql + " FROM legal_document_acceptances WHERE user_id = ? ORDER BY id",
	postgres: "SELECT " + legalDocumentAcceptanceColumns.postgres + " FROM legal_document_acceptances WHERE user_id = $1 ORDER BY id",
	mssql:    "SELECT " + legalDocumentAcceptanceColumns.mssql + " FROM legal_document_acceptances WHERE user_id = @p1 ORDER BY id",
}

func (d *Database) CreateLegalDocumentAcceptance(ctx context.Context, tx *sql.Tx,
	acceptance *record.LegalDocumentAcceptance) error {

	if acceptance.UserId == 0 {
		return errs.New("can't create legal document acceptance with user_id 0")
	}

	if acceptance.LegalDocumentVersionId == 0 {
		return errs.New("can't create legal document acceptance with legal_document_version_id 0")
	}

	if acceptance.AcceptedAt.IsZero() {
		return errs.New("can't create legal document acceptance with no accepted_at")
	}

	id, err := d.insert(ctx, tx, insertLegalDocumentAcceptance, "legal document acceptance",
		acceptance.AcceptedAt, acceptance.UserId, acceptance.LegalDocumentVersionId)
	if err != nil {
		return err
	}

	acceptance.Id = id
	return nil
}

func (d *Database) GetLegalDocumentAcceptancesByUserId(ctx context.Context, tx *sql.Tx,
	userId int64) ([]record.LegalDocumentAcceptance, error) {
	return queryAll(ctx, d, tx, nil, selectLegalDocumentAcceptancesByUserId.text(d.Dialect),
		[]any{userId}, scanLegalDocumentAcceptance, "legal document acceptance")
}
