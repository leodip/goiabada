package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// The apps a legal document set to selected apps applies to (#622). A row is created and deleted,
// never rewritten, so there is no whole-row UPDATE.

// legalDocumentClientColumns is the legal_documents_clients table as scanLegalDocumentClient reads
// it.
var legalDocumentClientColumns = columnList{
	sqlite:   "id, created_at, legal_document_id, client_id",
	mysql:    "id, created_at, legal_document_id, client_id",
	postgres: "id, created_at, legal_document_id, client_id",
	mssql:    "id, created_at, legal_document_id, client_id",
}

// scanLegalDocumentClient reads one row selected with legalDocumentClientColumns.
func scanLegalDocumentClient(row rowScanner, link *record.LegalDocumentClient) error {
	return row.Scan(
		&link.Id,
		&link.CreatedAt,
		&link.LegalDocumentId,
		&link.ClientId,
	)
}

var insertLegalDocumentClient = statement{
	sqlite:   "INSERT INTO legal_documents_clients (created_at, legal_document_id, client_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO legal_documents_clients (created_at, legal_document_id, client_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO legal_documents_clients (created_at, legal_document_id, client_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO legal_documents_clients (created_at, legal_document_id, client_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectLegalDocumentClientsByLegalDocumentId = statement{
	sqlite:   "SELECT " + legalDocumentClientColumns.sqlite + " FROM legal_documents_clients WHERE legal_document_id = ? ORDER BY id",
	mysql:    "SELECT " + legalDocumentClientColumns.mysql + " FROM legal_documents_clients WHERE legal_document_id = ? ORDER BY id",
	postgres: "SELECT " + legalDocumentClientColumns.postgres + " FROM legal_documents_clients WHERE legal_document_id = $1 ORDER BY id",
	mssql:    "SELECT " + legalDocumentClientColumns.mssql + " FROM legal_documents_clients WHERE legal_document_id = @p1 ORDER BY id",
}

var selectLegalDocumentClientsByClientId = statement{
	sqlite:   "SELECT " + legalDocumentClientColumns.sqlite + " FROM legal_documents_clients WHERE client_id = ? ORDER BY id",
	mysql:    "SELECT " + legalDocumentClientColumns.mysql + " FROM legal_documents_clients WHERE client_id = ? ORDER BY id",
	postgres: "SELECT " + legalDocumentClientColumns.postgres + " FROM legal_documents_clients WHERE client_id = $1 ORDER BY id",
	mssql:    "SELECT " + legalDocumentClientColumns.mssql + " FROM legal_documents_clients WHERE client_id = @p1 ORDER BY id",
}

var deleteLegalDocumentClient = statement{
	sqlite:   "DELETE FROM legal_documents_clients WHERE id = ?",
	mysql:    "DELETE FROM legal_documents_clients WHERE id = ?",
	postgres: "DELETE FROM legal_documents_clients WHERE id = $1",
	mssql:    "DELETE FROM legal_documents_clients WHERE id = @p1",
}

func (d *Database) CreateLegalDocumentClient(ctx context.Context, tx *sql.Tx, link *record.LegalDocumentClient) error {

	if link.LegalDocumentId == 0 {
		return errs.New("can't create legal document client with legal_document_id 0")
	}

	if link.ClientId == 0 {
		return errs.New("can't create legal document client with client_id 0")
	}

	originalCreatedAt := link.CreatedAt
	link.CreatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	id, err := d.insert(ctx, tx, insertLegalDocumentClient, "legal document client",
		link.CreatedAt, link.LegalDocumentId, link.ClientId)
	if err != nil {
		link.CreatedAt = originalCreatedAt
		return err
	}

	link.Id = id
	return nil
}

func (d *Database) GetLegalDocumentClientsByLegalDocumentId(ctx context.Context, tx *sql.Tx,
	legalDocumentId int64) ([]record.LegalDocumentClient, error) {
	return queryAll(ctx, d, tx, nil, selectLegalDocumentClientsByLegalDocumentId.text(d.Dialect),
		[]any{legalDocumentId}, scanLegalDocumentClient, "legal document client")
}

func (d *Database) GetLegalDocumentClientsByClientId(ctx context.Context, tx *sql.Tx,
	clientId int64) ([]record.LegalDocumentClient, error) {
	return queryAll(ctx, d, tx, nil, selectLegalDocumentClientsByClientId.text(d.Dialect),
		[]any{clientId}, scanLegalDocumentClient, "legal document client")
}

func (d *Database) DeleteLegalDocumentClient(ctx context.Context, tx *sql.Tx, legalDocumentClientId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteLegalDocumentClient.text(d.Dialect), legalDocumentClientId)
	if err != nil {
		return errs.Wrap(err, "unable to delete legal document client")
	}

	return nil
}
