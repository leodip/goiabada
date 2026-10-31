// Package legaldocuments answers which legal documents are in effect where (#622): a document is in
// effect once it has a published version and while it is not retired, and its current version is
// its latest. It applies to all apps, or to the clients it lists. The sign-in pages' footer, the
// registration form and the public settings read the documents in effect through it.
package legaldocuments

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// InEffect is a document in effect and its current version.
type InEffect struct {
	Document record.LegalDocument
	Current  record.LegalDocumentVersion
}

// readerDatabase is what the reader needs: every document, each one's versions, the client a
// sign-in names and the documents that list it.
type readerDatabase interface {
	GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error)
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetLegalDocumentClientsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.LegalDocumentClient, error)
}

// Reader reads the documents in effect.
type Reader struct {
	database readerDatabase
}

// NewReader returns a Reader over database.
func NewReader(database readerDatabase) *Reader {
	return &Reader{database: database}
}

// ForAllApps answers the documents in effect that apply to all apps, in id order.
func (r *Reader) ForAllApps(ctx context.Context) ([]InEffect, error) {
	return r.inEffect(ctx, nil)
}

// ForClient answers the documents in effect that apply to all apps or list the client
// clientIdentifier names, in id order. An empty identifier, or one no client has, is a page no app
// is behind, which the all-apps documents alone apply to.
func (r *Reader) ForClient(ctx context.Context, clientIdentifier string) ([]InEffect, error) {
	if clientIdentifier == "" {
		return r.ForAllApps(ctx)
	}
	client, err := r.database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the client the legal documents apply to")
	}
	if client == nil {
		return r.ForAllApps(ctx)
	}
	links, err := r.database.GetLegalDocumentClientsByClientId(ctx, nil, client.Id)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the legal documents that list the client")
	}
	listed := make(map[int64]bool, len(links))
	for _, link := range links {
		listed[link.LegalDocumentId] = true
	}
	return r.inEffect(ctx, listed)
}

// inEffect answers the documents in effect that apply to all apps or are in listed.
func (r *Reader) inEffect(ctx context.Context, listed map[int64]bool) ([]InEffect, error) {
	docs, err := r.database.GetAllLegalDocuments(ctx, nil)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the legal documents")
	}
	inEffect := []InEffect{}
	for _, doc := range docs {
		// A retired document applies to no app (decision 2), and one set to selected apps applies to
		// the apps it lists alone, never to all apps, even when it lists none.
		if doc.IsRetired() || (!doc.AppliesToAllApps && !listed[doc.Id]) {
			continue
		}
		versions, err := r.database.GetLegalDocumentVersionsByLegalDocumentId(ctx, nil, doc.Id)
		if err != nil {
			return nil, errs.Wrap(err, "unable to read the legal document's versions")
		}
		// A document never published is shown nowhere (decision 1).
		if len(versions) == 0 {
			continue
		}
		inEffect = append(inEffect, InEffect{Document: doc, Current: versions[len(versions)-1]})
	}
	return inEffect, nil
}
