package legaldocuments

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// Accepted is one version a user accepted: the acceptance, the version, and its document as it is
// now, retired or not.
type Accepted struct {
	Acceptance record.LegalDocumentAcceptance
	Document   record.LegalDocument
	Version    record.LegalDocumentVersion
}

// AcceptedDatabase is what reading a user's acceptances needs: the acceptances, every document, and
// each one's versions. data.Database satisfies it.
type AcceptedDatabase interface {
	GetLegalDocumentAcceptancesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.LegalDocumentAcceptance, error)
	GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error)
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
}

// AcceptedBy answers every version the user accepted, the latest acceptance first, retired
// documents included (#622 decision 10). An acceptance is written once, at the moment the user
// accepts, so the latest is the one stored last. Only the documents the user accepted a version of
// have their versions read.
func AcceptedBy(ctx context.Context, db AcceptedDatabase, userId int64) ([]Accepted, error) {
	acceptances, err := db.GetLegalDocumentAcceptancesByUserId(ctx, nil, userId)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the user's legal document acceptances")
	}
	if len(acceptances) == 0 {
		return []Accepted{}, nil
	}
	wanted := make(map[int64]bool, len(acceptances))
	for _, acceptance := range acceptances {
		wanted[acceptance.LegalDocumentVersionId] = true
	}

	docs, err := db.GetAllLegalDocuments(ctx, nil)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the legal documents")
	}
	type found struct {
		document record.LegalDocument
		version  record.LegalDocumentVersion
	}
	byVersionId := make(map[int64]found, len(wanted))
	for _, doc := range docs {
		if len(byVersionId) == len(wanted) {
			break
		}
		versions, err := db.GetLegalDocumentVersionsByLegalDocumentId(ctx, nil, doc.Id)
		if err != nil {
			return nil, errs.Wrap(err, "unable to read the legal document's versions")
		}
		for _, version := range versions {
			if wanted[version.Id] {
				byVersionId[version.Id] = found{document: doc, version: version}
			}
		}
	}

	accepted := make([]Accepted, 0, len(acceptances))
	for i := len(acceptances) - 1; i >= 0; i-- {
		acceptance := acceptances[i]
		f, ok := byVersionId[acceptance.LegalDocumentVersionId]
		if !ok {
			// The version's foreign key has no cascade, so a version a user accepted is never
			// deleted, and neither is its document.
			return nil, errs.New("a legal document version the user accepted was not found")
		}
		accepted = append(accepted, Accepted{Acceptance: acceptance, Document: f.document, Version: f.version})
	}
	return accepted, nil
}
