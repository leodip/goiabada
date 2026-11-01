package authflow

import (
	"context"
	"database/sql"
	"log/slog"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
	"github.com/leodip/goiabada/core/errs"
)

// consentPromptDatabase is what ConsentPrompt reads: the user, the client, the user's stored
// consent to it, and whether the client has a logo for the screen. data.Database satisfies it.
type consentPromptDatabase interface {
	clientDisplayDatabase

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// ConsentPrompt is GET /auth/consent, reached in requires_consent: it shows the consent screen, or
// moves a ceremony whose scope is already consented on to issuance. The route table builds one.
type ConsentPrompt struct {
	database consentPromptDatabase
}

// NewConsentPrompt builds the operation over the database it reads.
func NewConsentPrompt(database consentPromptDatabase) *ConsentPrompt {
	return &ConsentPrompt{database: database}
}

// ConsentScreen is what the consent screen shows, for the handler to render.
type ConsentScreen struct {
	// ClientName is record.Client's NameForUsers, not ClientDisplayInfo.ClientName, which falls
	// back to the raw identifier and would show a self-registered client as dcr_<uuid>. A prompt
	// nobody can evaluate defeats the point of prompting (#108).
	ClientName string
	// ClientNameUnverified is whether ClientName is the client's own claim about itself; the screen
	// then shows the unverified notice under it.
	ClientNameUnverified bool
	// ClientDescription is empty when ClientNameUnverified: the name is then the client's
	// self-asserted description, which would otherwise be shown twice (#108).
	ClientDescription string
	ShowClientSection bool
	HasLogo           bool
	LogoURL           string
	WebsiteURL        string
	// PrivacyPolicyURL and TermsOfServiceURL are the client's own documents, empty when it has
	// none. The screen links them whenever set, whatever the client's display switches: RFC 7591
	// section 2 says the server SHOULD display them (#622 decision 12).
	PrivacyPolicyURL  string
	TermsOfServiceURL string
	// Scopes is the screen's rows, whose order names its checkboxes.
	Scopes []ScopeInfo
}

// ConsentPromptResult is what ConsentPrompt.Run did. Exactly one of Screen and NextStep is set.
type ConsentPromptResult struct {
	// Screen is the consent screen the user is owed. Nothing was saved.
	Screen *ConsentScreen

	// NextStep is /auth/issue, set when no screen is owed and the ceremony was saved in
	// ready_to_issue_code.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// Run, in order:
//
//  1. Loads the user, the client and the user's stored consent to the client; a failed read, or a
//     user or client not found, is returned as an error, and nothing is saved.
//  2. Builds the screen's rows from the ceremony's scope and the stored consent, and decides whether
//     the screen is owed (consentScreenOwed).
//  3. Owed: reads the client block (getClientDisplayInfo) and returns the screen. Not owed: saves
//     the ceremony in ready_to_issue_code and returns /auth/issue.
func (o *ConsentPrompt) Run(ctx context.Context, browser stepSaver,
	authContext *ceremony.AuthContext) (ConsentPromptResult, error) {

	user, err := o.database.GetUserById(ctx, nil, authContext.UserId)
	if err != nil {
		return ConsentPromptResult{}, err
	}
	if user == nil {
		return ConsentPromptResult{}, errs.New("user not found")
	}

	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return ConsentPromptResult{}, err
	}
	if client == nil {
		return ConsentPromptResult{}, errs.New("client not found")
	}

	consent, err := o.database.GetConsentByUserIdAndClientId(ctx, nil, user.Id, client.Id)
	if err != nil {
		return ConsentPromptResult{}, err
	}

	scopes := buildScopeInfoArray(ctx, authContext.Scope, consent)

	if consentScreenOwed(scopes, authContext.Scope, authContext.HasPromptValue("consent")) {
		displayInfo := getClientDisplayInfo(ctx, o.database, client)
		clientName, clientNameUnverified := client.NameForUsers()

		return ConsentPromptResult{Screen: &ConsentScreen{
			ClientName:           clientName,
			ClientNameUnverified: clientNameUnverified,
			ClientDescription:    client.DescriptionForUsers(),
			ShowClientSection:    displayInfo.ShowSection,
			HasLogo:              displayInfo.HasLogo,
			LogoURL:              displayInfo.LogoURL,
			WebsiteURL:           displayInfo.WebsiteURL,
			PrivacyPolicyURL:     client.PrivacyPolicyURL,
			TermsOfServiceURL:    client.TermsOfServiceURL,
			Scopes:               scopes,
		}}, nil
	}

	authContext.AuthState = ceremony.AuthStateReadyToIssueCode
	return ConsentPromptResult{
		NextStep: "/auth/issue",
		SaveErr:  browser.SaveAuthContext(authContext),
	}, nil
}

// consentSubmissionDatabase is what ConsentSubmission reads and writes: the client and the user the
// selection is weighed for, and the consent row userconsent.Record writes. data.Database satisfies
// it.
type consentSubmissionDatabase interface {
	userconsent.Database

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// consentSubmissionBrowser is the two browser-session writes ConsentSubmission makes: the save that
// moves a granted ceremony on, and the clear that ends a refused one.
type consentSubmissionBrowser interface {
	stepSaver
	ceremonyClearer
}

// ConsentSubmission is POST /auth/consent, the user's answer to the consent screen, reached in
// requires_consent. The route table builds one.
type ConsentSubmission struct {
	database    consentSubmissionDatabase
	scopes      scopeFilter
	auditLogger auditLogger
}

// NewConsentSubmission builds the operation over the database, the scope filter and the audit log
// it uses.
func NewConsentSubmission(database consentSubmissionDatabase, scopes scopeFilter,
	auditLogger auditLogger) *ConsentSubmission {

	return &ConsentSubmission{database: database, scopes: scopes, auditLogger: auditLogger}
}

// ConsentSubmissionResult is what ConsentSubmission.Run did. Exactly one of ClientError and
// NextStep is set.
type ConsentSubmissionResult struct {
	// ClientError is the access_denied the client is owed for a refused submission. The ceremony
	// ends with it: it was cleared, and nothing was recorded.
	ClientError *ClientError
	// ClearErr is the clear's failure: ceremony.ErrCeremonyReplaced, which answers the "no longer
	// active" page and nothing to the client, or any other, which answers the client server_error
	// in place of ClientError (#141).
	ClearErr error

	// NextStep is /auth/issue, set when the consent was recorded and the ceremony saved in
	// ready_to_issue_code.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// Run, in order:
//
//  1. Reads the submission from body, the submitted form body alone (consentApproved,
//     tickedScopes), and decides it (decideConsentSubmission).
//  2. Only when that asks for the held scope: loads the client and the user, and narrows the ticked
//     selection to the permissions the user holds now; a failed read, or a client or user not found,
//     is returned as an error, and nothing is written.
//  3. A refusal: the cancel and the empty selection read the client's provenance (clientProvenance),
//     since nothing loaded it; the selection holding nothing is logged at warn. Each clears the
//     ceremony and returns ClientError.
//  4. A grant: records the consent (userconsent.Record), sets the consented scope, audits
//     EventSavedConsent after the commit, and saves the ceremony in ready_to_issue_code.
//
// The selection is weighed against the permissions the user holds now, which need not be the ones
// they held when the screen was rendered. A consent row grants nothing on its own, since every
// reader pairs it with a live permission check, but it suppresses the consent screen on later
// ceremonies, so a row recording a permission the user did not hold would cover it if it were
// granted back later, and the user's own consents page would list a scope the application cannot
// use (#241). It is narrowed before the consent row is read, so a selection it empties refuses
// without reading or writing a consent.
func (o *ConsentSubmission) Run(ctx context.Context, browser consentSubmissionBrowser,
	authContext *ceremony.AuthContext, body url.Values) (ConsentSubmissionResult, error) {

	facts := consentSubmissionFacts{approved: consentApproved(body)}
	if facts.approved {
		facts.ticked = tickedScopes(body, buildScopeInfoArray(ctx, authContext.Scope, nil))
	}

	var client *record.Client
	var user *record.User

	answer, need := decideConsentSubmission(facts)
	for need != consentSubmissionFactNone {
		if need == consentSubmissionFactHeldScope {
			var err error
			client, err = o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
			if err != nil {
				return ConsentSubmissionResult{}, err
			}
			if client == nil {
				return ConsentSubmissionResult{}, errs.New("client not found")
			}

			user, err = o.database.GetUserById(ctx, nil, authContext.UserId)
			if err != nil {
				return ConsentSubmissionResult{}, err
			}
			if user == nil {
				return ConsentSubmissionResult{}, errs.New("user not found")
			}

			heldScope, err := o.scopes.FilterOutScopesWhereUserIsNotAuthorized(ctx, strings.Join(facts.ticked, " "), user)
			if err != nil {
				return ConsentSubmissionResult{}, err
			}
			facts.heldScope = &heldScope
		}
		answer, need = decideConsentSubmission(facts)
	}

	switch answer {
	case consentSubmissionDeclined, consentSubmissionNothingTicked:
		// No request reaches both this read and the load above (#108).
		refusedClient := clientProvenance(ctx, o.database, authContext.ClientId)
		return ConsentSubmissionResult{
			ClientError: &ClientError{Client: refusedClient, Code: "access_denied",
				Description: "The user did not provide consent"},
			ClearErr: browser.ClearAuthContext(authContext.CeremonyId),
		}, nil
	case consentSubmissionNothingHeld:
		slog.WarnContext(ctx, "the consented selection holds no permission the user still has, so no consent is recorded",
			"user_id", user.Id,
			"client_identifier", authContext.ClientId)

		// Worded apart from the refusal above, which answers the user's own choice: an administrator
		// emptied this selection. The wording and the error code are /auth/completed's for the same
		// condition arriving later, so the same removal gets one answer wherever it lands (#241
		// decision 3).
		return ConsentSubmissionResult{
			ClientError: &ClientError{Client: client, Code: "access_denied",
				Description: "The user is not authorized to access any of the requested scopes"},
			ClearErr: browser.ClearAuthContext(authContext.CeremonyId),
		}, nil
	}

	consent, err := userconsent.Record(ctx, o.database, user.Id, client.Id, *facts.heldScope)
	if err != nil {
		return ConsentSubmissionResult{}, err
	}
	authContext.ConsentedScope = consent.Scope

	o.auditLogger.Log(ctx, audit.EventSavedConsent, map[string]interface{}{
		"user_id":    consent.UserId,
		"client_id":  consent.ClientId,
		"consent_id": consent.Id,
	})

	authContext.AuthState = ceremony.AuthStateReadyToIssueCode
	return ConsentSubmissionResult{
		NextStep: "/auth/issue",
		SaveErr:  browser.SaveAuthContext(authContext),
	}, nil
}
