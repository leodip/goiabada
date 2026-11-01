// Package legaldocuments answers which legal documents are in effect where (#622): a document is in
// effect once it has a published version and while it is not retired, and its current version is
// its latest. It applies to all apps, or to the clients it lists. The registration form reads the
// documents in effect through it. The acceptance step, the silent sign-in and the password grant ask it what a user owes (Owed), the step
// records what the user accepted through it (RecordAcceptances), and the account and admin APIs read
// back what a user accepted (AcceptedBy).
package legaldocuments

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// InEffect is a document in effect and its current version.
type InEffect struct {
	Document record.LegalDocument
	Current  record.LegalDocumentVersion
}

// Database is what the reader needs: every document, each one's versions, the client a sign-in
// names, the documents that list it, and a user's acceptances. data.Database satisfies it.
type Database interface {
	GetAllLegalDocuments(ctx context.Context, tx *sql.Tx) ([]record.LegalDocument, error)
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetLegalDocumentClientsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.LegalDocumentClient, error)
	GetLegalDocumentAcceptancesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.LegalDocumentAcceptance, error)
}

// Reader reads the documents in effect.
type Reader struct {
	database Database
}

// NewReader returns a Reader over database.
func NewReader(database Database) *Reader {
	return &Reader{database: database}
}

// ForClient answers the documents in effect that apply to all apps or list the client
// clientIdentifier names, in id order. An empty identifier, or one no client has, is a page no app
// is behind, which the all-apps documents alone apply to.
func (r *Reader) ForClient(ctx context.Context, clientIdentifier string) ([]InEffect, error) {
	if clientIdentifier == "" {
		return r.inEffect(ctx, nil)
	}
	client, err := r.database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the client the legal documents apply to")
	}
	if client == nil {
		return r.inEffect(ctx, nil)
	}
	return r.forClientRecord(ctx, client)
}

// forClientRecord answers the documents in effect that apply to all apps or list client.
func (r *Reader) forClientRecord(ctx context.Context, client *record.Client) ([]InEffect, error) {
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

// Owed answers the documents a user owes the acceptance step on a sign-in to client, in id order:
// each must-accept document in effect for it, applying to all apps or listing it, whose current
// version the user has not accepted. A document accepted once counts for every app it covers, and
// a new version is owed again. The admin console's own client owes nothing and reads nothing: it
// also serves My Account, which a user reaches without accepting anything (#622).
func (r *Reader) Owed(ctx context.Context, client *record.Client, userId int64) ([]InEffect, error) {
	if client.ClientIdentifier == builtin.AdminConsoleClientIdentifier {
		return nil, nil
	}
	inEffect, err := r.forClientRecord(ctx, client)
	if err != nil {
		return nil, err
	}
	mustAccept := []InEffect{}
	for _, doc := range inEffect {
		if doc.Document.Kind == record.LegalDocumentKindMustAccept {
			mustAccept = append(mustAccept, doc)
		}
	}
	if len(mustAccept) == 0 {
		return nil, nil
	}

	acceptances, err := r.database.GetLegalDocumentAcceptancesByUserId(ctx, nil, userId)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the user's legal document acceptances")
	}
	accepted := make(map[int64]bool, len(acceptances))
	for _, acceptance := range acceptances {
		accepted[acceptance.LegalDocumentVersionId] = true
	}
	owed := []InEffect{}
	for _, doc := range mustAccept {
		if !accepted[doc.Current.Id] {
			owed = append(owed, doc)
		}
	}
	return owed, nil
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
