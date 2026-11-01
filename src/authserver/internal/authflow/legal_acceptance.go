package authflow

import (
	"context"
	"database/sql"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// legalAcceptanceDeclinedDescription is the error_description of the access_denied an app is
// answered with when the user declines the acceptance step (#622 decision 8).
const legalAcceptanceDeclinedDescription = "The user declined a required legal document"

// legalAcceptanceDatabase is what the acceptance step reads and writes: the client and the user,
// the user's stored consent to the client, which decides where the ceremony goes once nothing is
// owed, and the acceptances it records. data.Database satisfies it.
type legalAcceptanceDatabase interface {
	legaldocuments.AcceptanceDatabase
	consentReader

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// LegalAcceptanceDocument is one document the acceptance step lists.
type LegalAcceptanceDocument struct {
	Title     string
	ShortName string
	// VersionId is the id of the version shown, which the checkbox and the hidden field carry.
	VersionId     int64
	VersionNumber int
	// Ticked is whether the box was ticked when the step is shown again after a submission.
	Ticked bool
}

// LegalAcceptanceScreen is what the acceptance step shows, for the handler to render.
type LegalAcceptanceScreen struct {
	// ClientName is record.Client's NameForUsers, as the consent screen names the app.
	ClientName string
	Documents  []LegalAcceptanceDocument
	// Unticked says the step is shown again because Accept came with a box left unticked.
	Unticked bool
	// Changed says the step is shown again because what is owed changed since it was shown.
	Changed bool
}

// LegalAcceptanceResult is what the acceptance step did. Exactly one of Screen, NextStep and
// ClientError is set.
type LegalAcceptanceResult struct {
	// Screen is the step the user is owed. Nothing was saved or recorded.
	Screen *LegalAcceptanceScreen

	// NextStep is /auth/consent or /auth/issue, set when nothing is owed and the ceremony was saved
	// in requires_consent or ready_to_issue_code.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error

	// ClientError is the access_denied the client is owed: for a decline, or for a user who holds
	// none of the requested scopes any more. The ceremony ends with it: it was cleared.
	ClientError *ClientError
	// ClearErr is the clear's failure: ceremony.ErrCeremonyReplaced, which answers the "no longer
	// active" page and nothing to the client, or any other, which answers the client server_error in
	// place of ClientError (#141).
	ClearErr error
}

// LegalAcceptance is the acceptance step (#622 decisions 7 and 8), reached in
// requires_legal_acceptance once the ceremony is bound to a session and before consent: GET
// /auth/legal-acceptance lists the must-accept documents the user owes for the app (Prompt), and
// POST records them or ends the sign-in (Submit). The route table builds one.
type LegalAcceptance struct {
	database       legalAcceptanceDatabase
	scopes         scopeFilter
	auditLogger    auditLogger
	legalDocuments legalDocumentsOwed
}

// NewLegalAcceptance builds the operation over the database, the scope filter, the audit log and
// the legal documents it uses.
func NewLegalAcceptance(database legalAcceptanceDatabase, scopes scopeFilter, auditLogger auditLogger,
	legalDocuments legalDocumentsOwed) *LegalAcceptance {

	return &LegalAcceptance{database: database, scopes: scopes, auditLogger: auditLogger,
		legalDocuments: legalDocuments}
}

// Prompt is GET /auth/legal-acceptance. In order:
//
//  1. Loads the client and the user; a failed read, or one not found, is an error, and nothing is
//     saved.
//  2. Reads the documents the user owes for the client.
//  3. Something owed: returns the screen, every box unticked. Nothing owed any more, accepted in
//     another tab or retired meanwhile: decides where the ceremony goes as Completion would
//     (routeBoundCeremony) and moves it on.
func (o *LegalAcceptance) Prompt(ctx context.Context, browser legalAcceptanceBrowser,
	authContext *ceremony.AuthContext) (LegalAcceptanceResult, error) {

	client, user, err := o.load(ctx, authContext)
	if err != nil {
		return LegalAcceptanceResult{}, err
	}
	owed, err := o.legalDocuments.Owed(ctx, client, user.Id)
	if err != nil {
		return LegalAcceptanceResult{}, err
	}
	if len(owed) > 0 {
		return LegalAcceptanceResult{Screen: legalAcceptanceScreen(client, owed, nil)}, nil
	}
	return o.moveOn(ctx, browser, authContext, client, user)
}

// Submit is POST /auth/legal-acceptance, the user's answer to the step. In order:
//
//  1. Reads the answer from body, the submitted form body alone (legalAcceptanceAccepted).
//  2. Decline: reads the client's provenance, records declined_legal_documents, clears the
//     ceremony and returns access_denied. Nothing is stored, so the next sign-in asks again, and
//     the user's session stays (decision 8).
//  3. Accept: loads the client and the user and reads what is owed now, then decides
//     (decideLegalAcceptance). A change since the step was shown, or a box left unticked, returns
//     the screen again and records nothing. Nothing owed any more moves the ceremony on. Otherwise
//     records an acceptance of each version shown (legaldocuments.RecordAcceptances), records
//     accepted_legal_document for each after the commit, and moves the ceremony on as Completion
//     would (routeBoundCeremony).
func (o *LegalAcceptance) Submit(ctx context.Context, browser legalAcceptanceBrowser,
	authContext *ceremony.AuthContext, body url.Values) (LegalAcceptanceResult, error) {

	if !legalAcceptanceAccepted(body) {
		client := clientProvenance(ctx, o.database, authContext.ClientId)
		details := map[string]interface{}{"user_id": authContext.UserId}
		if client != nil {
			details["client_id"] = client.Id
		}
		o.auditLogger.Log(ctx, audit.EventDeclinedLegalDocuments, details)
		return LegalAcceptanceResult{
			ClientError: &ClientError{Client: client, Code: "access_denied",
				Description: legalAcceptanceDeclinedDescription},
			ClearErr: browser.ClearAuthContext(authContext.CeremonyId),
		}, nil
	}

	client, user, err := o.load(ctx, authContext)
	if err != nil {
		return LegalAcceptanceResult{}, err
	}
	owed, err := o.legalDocuments.Owed(ctx, client, user.Id)
	if err != nil {
		return LegalAcceptanceResult{}, err
	}
	owedVersions := make([]int64, 0, len(owed))
	for _, doc := range owed {
		owedVersions = append(owedVersions, doc.Current.Id)
	}

	ticked := submittedVersions(body, legalAcceptanceTickedField)
	switch decideLegalAcceptance(submittedVersions(body, legalAcceptanceShownField), ticked, owedVersions) {
	case legalAcceptanceChanged:
		screen := legalAcceptanceScreen(client, owed, ticked)
		screen.Changed = true
		return LegalAcceptanceResult{Screen: screen}, nil
	case legalAcceptanceUnticked:
		screen := legalAcceptanceScreen(client, owed, ticked)
		screen.Unticked = true
		return LegalAcceptanceResult{Screen: screen}, nil
	case legalAcceptanceRecorded:
		written, recordErr := legaldocuments.RecordAcceptances(ctx, o.database, user.Id, owedVersions)
		if recordErr != nil {
			return LegalAcceptanceResult{}, recordErr
		}
		byVersion := make(map[int64]legaldocuments.InEffect, len(owed))
		for _, doc := range owed {
			byVersion[doc.Current.Id] = doc
		}
		for _, acceptance := range written {
			doc := byVersion[acceptance.LegalDocumentVersionId]
			o.auditLogger.Log(ctx, audit.EventAcceptedLegalDocument, map[string]interface{}{
				"user_id":           user.Id,
				"client_id":         client.Id,
				"legal_document_id": doc.Document.Id,
				"short_name":        doc.Document.ShortName,
				"version":           doc.Current.VersionNumber,
			})
		}
	}
	return o.moveOn(ctx, browser, authContext, client, user)
}

// load reads the ceremony's client and user, each of which must exist.
func (o *LegalAcceptance) load(ctx context.Context,
	authContext *ceremony.AuthContext) (*record.Client, *record.User, error) {

	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, errs.New("client not found")
	}
	user, err := o.database.GetUserById(ctx, nil, authContext.UserId)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, errs.New("user not found")
	}
	return client, user, nil
}

// moveOn sends a ceremony that owes nothing on, as Completion would have sent it with nothing owed.
func (o *LegalAcceptance) moveOn(ctx context.Context, browser legalAcceptanceBrowser,
	authContext *ceremony.AuthContext, client *record.Client, user *record.User) (LegalAcceptanceResult, error) {

	answer, err := routeBoundCeremony(ctx, o.database, o.scopes, authContext, client, user)
	if err != nil {
		return LegalAcceptanceResult{}, err
	}
	nextStep, clientError, writeErr := moveBoundCeremonyOn(answer, browser, authContext, client)
	if clientError != nil {
		return LegalAcceptanceResult{ClientError: clientError, ClearErr: writeErr}, nil
	}
	return LegalAcceptanceResult{NextStep: nextStep, SaveErr: writeErr}, nil
}

// legalAcceptanceScreen builds the step's screen for the documents owed, each box ticked as ticked
// says, nil for none.
func legalAcceptanceScreen(client *record.Client, owed []legaldocuments.InEffect,
	ticked map[int64]bool) *LegalAcceptanceScreen {

	clientName, _ := client.NameForUsers()
	screen := &LegalAcceptanceScreen{ClientName: clientName}
	for _, doc := range owed {
		screen.Documents = append(screen.Documents, LegalAcceptanceDocument{
			Title:         doc.Current.Title,
			ShortName:     doc.Document.ShortName,
			VersionId:     doc.Current.Id,
			VersionNumber: doc.Current.VersionNumber,
			Ticked:        ticked[doc.Current.Id],
		})
	}
	return screen
}
