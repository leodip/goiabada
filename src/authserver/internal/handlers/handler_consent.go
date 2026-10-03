package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

type ScopeInfo struct {
	Scope            string
	Description      string
	AlreadyConsented bool
}

func buildScopeInfoArray(ctx context.Context, scope string, consent *models.UserConsent) []ScopeInfo {
	scopeInfoArr := []ScopeInfo{}

	if len(scope) == 0 {
		return scopeInfoArr
	}

	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if oidc.IsClaimScope(scope) || oidc.IsOfflineAccessScope(scope) {
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      i18n.T(ctx, oidc.ScopeDescriptionKey(scope)),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		} else {
			// resource-permission
			parts := strings.Split(scope, ":")
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope: scope,
				Description: i18n.T(ctx, "consent.scope.permission_template",
					map[string]any{"permission": parts[1], "resource": parts[0]}),
				AlreadyConsented: consent != nil && consent.HasScope(scope),
			})
		}
	}
	return scopeInfoArr
}

// consentDatabase is what the consent screen needs: the client, the consent it reads and records,
// and the user granting it.
//
// It embeds the authorize port because a refusal is answered through redirToClientWithError, the
// client display port because the screen renders through getClientDisplayInfo, and the consent
// writer's port because a grant is recorded through userconsent.Record.
type consentDatabase interface {
	authorizeDatabase
	clientDisplayDatabase
	userconsent.Database

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
}

func HandleConsentGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database consentDatabase,
	auditLogger AuditLogger,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateRequiresConsent) {
			return
		}

		user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.New("user not found"))
			return
		}

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found"))
			return
		}

		consent, err := database.GetConsentByUserIdAndClientId(r.Context(), nil, user.Id, client.Id)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		scopeInfoArr := buildScopeInfoArray(r.Context(), authContext.Scope, consent)

		if consentScreenOwed(scopeInfoArr, authContext.Scope, authContext.HasPromptValue("consent")) {
			displayInfo := getClientDisplayInfo(r.Context(), database, client)

			// The consent screen names the client through its own rule rather than through
			// displayInfo.ClientName, which falls back to the raw identifier and would show a
			// self-registered client as dcr_<uuid>. A prompt nobody can evaluate defeats the point
			// of prompting (#108).
			clientName, clientNameUnverified := consentClientName(client)

			clientDescription := displayInfo.Description
			if clientNameUnverified {
				// The name and the description are both the client's self-asserted client_name in
				// this case, so an administrator who ticked "show description" on a self-registered
				// client would otherwise read the same string twice (#108).
				clientDescription = ""
			}

			bind := map[string]interface{}{
				"showClientSection": displayInfo.ShowSection,
				"clientName":        clientName,
				// Whether the name above is the client's own claim about itself. The template
				// renders the unverified notice under the name when this is set.
				"clientNameUnverified": clientNameUnverified,
				"clientDescription":    clientDescription,
				"clientLogoUrl":        displayInfo.LogoURL,
				"clientWebsiteUrl":     displayInfo.WebsiteURL,
				"hasLogo":              displayInfo.HasLogo,
				"scopes":               scopeInfoArr,
				// The rendered form says which ceremony rendered it, and HandleConsentPost
				// refuses a submission naming any other one. The checkbox indices are only
				// meaningful against this ceremony's scope list (#79).
				"ceremonyId": authContext.CeremonyId,
			}

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		// consent is done, ready to issue code
		authContext.AuthState = ceremony.AuthStateReadyToIssueCode
		err = ceremonyStore.SaveAuthContext(w, r, authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/issue", authContext), http.StatusFound)
	}
}

// consentScreenOwed answers whether GET /auth/consent renders the screen rather than going
// straight on to issuance. It is shown when:
//   - not every requested scope is already consented, OR
//   - offline_access is requested (a refresh token grant is always re-confirmed), OR
//   - prompt=consent was explicitly requested (force consent UI).
func consentScreenOwed(scopes []ScopeInfo, scope string, promptConsent bool) bool {
	fullyConsented := true
	for _, scopeInfo := range scopes {
		fullyConsented = fullyConsented && scopeInfo.AlreadyConsented
	}
	return !fullyConsented || oidc.HasOfflineAccessScope(scope) || promptConsent
}

func HandleConsentPost(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database consentDatabase,
	templateFS fs.FS,
	auditLogger AuditLogger,
	permissionChecker PermissionChecker,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// loadAuthContext refuses a submission naming another ceremony before the AuthState check, so
		// a form left open in another tab gets the 400 mismatch page rather than the 500 that a
		// replaced context's state would produce, and before the btnSubmit/btnCancel dispatch, so a
		// stale cancel cannot clear the auth context of the ceremony that is actually current (#79).
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateRequiresConsent) {
			return
		}

		facts := consentSubmissionFacts{approved: consentApproved(r.PostForm)}
		if facts.approved {
			facts.ticked = tickedScopes(r.PostForm, buildScopeInfoArray(r.Context(), authContext.Scope, nil))
		}

		// client and user are loaded only on the path that weighs the selection against the
		// permissions the user holds; a refusal before it resolves provenance instead.
		var client *models.Client
		var user *models.User

		answer, need := decideConsentSubmission(facts)
		for need != consentSubmissionFactNone {
			switch need {
			case consentSubmissionFactHeldScope:
				var err error
				client, err = database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				if client == nil {
					pageRenderer.InternalServerError(w, r, errs.New("client not found"))
					return
				}

				user, err = database.GetUserById(r.Context(), nil, authContext.UserId)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				if user == nil {
					pageRenderer.InternalServerError(w, r, errs.New("user not found"))
					return
				}

				// The ticked selection is weighed against the permissions the user holds NOW,
				// which need not be the ones they held when the screen was rendered. The row a
				// grant writes grants nothing on its own, since every reader pairs it with a live
				// permission check, but it suppresses the consent screen on later ceremonies: an
				// unfiltered row means a permission granted back months later is covered by a
				// tick the user made at a moment when they did not hold it, and the user's own
				// consents page lists a scope the application can never use (#241).
				//
				// Before the consent row is read rather than beside the write, so a selection
				// the filter empties refuses without reading or writing anything.
				heldScope, err := permissionChecker.FilterOutScopesWhereUserIsNotAuthorized(r.Context(),
					strings.Join(facts.ticked, " "), user)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
				facts.heldScope = &heldScope
			}
			answer, need = decideConsentSubmission(facts)
		}

		switch answer {
		case consentSubmissionDeclined, consentSubmissionNothingTicked:
			// A refusal answers the client with an error redirect, and an error redirect carries
			// the client it is answering, so provenance is resolved here, where no client has
			// been loaded; no request reaches both this and the load above (#108).
			refusedClient := clientProvenance(r.Context(), database, authContext.ClientId)

			// The clear goes FIRST, inside answerClientWithError: a Set-Cookie written after the
			// error redirect has committed never reaches the wire, so the browser would keep an
			// auth context in requires_consent, which GET /auth/consent accepts, and replaying it
			// could turn access_denied into a code for the same authorization request (#141).
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, refusedClient,
					"access_denied", "The user did not provide consent"))
		case consentSubmissionNothingHeld:
			slog.WarnContext(r.Context(), "the consented selection holds no permission the user still has, so no consent is recorded",
				"user_id", user.Id,
				"client_identifier", authContext.ClientId)

			// A DIFFERENT refusal from the one above, deliberately. That one answers a user who
			// declined or ticked nothing, which is a choice they made; this one answers a
			// selection an administrator emptied, which is not. The wording and the error code
			// are /auth/completed's for the same condition arriving later, so the same removal
			// gets one answer wherever it lands (#241 decision 3).
			answerClientWithError(w, r, database, pageRenderer, ceremonyStore, templateFS,
				redirectErrorFromAuthContext(authContext, client,
					"access_denied", "The user is not authorized to access any of the requested scopes"))
		default:
			consent, err := userconsent.Record(r.Context(), database, user.Id, client.Id, *facts.heldScope)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			authContext.ConsentedScope = consent.Scope

			auditLogger.Log(r.Context(), audit.EventSavedConsent, map[string]interface{}{
				"userId":    consent.UserId,
				"clientId":  consent.ClientId,
				"consentId": consent.Id,
			})

			// consent is done, ready to issue code
			authContext.AuthState = ceremony.AuthStateReadyToIssueCode
			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/issue", authContext), http.StatusFound)
		}
	}
}

// consentApproved reads the submission's action from the submitted body.
//
// Both action controls are read from the body rather than from r.Form: this form posts to
// action="", so r.Form would merge the URL query in, and a button that was not clicked sends no key
// at all. A consent screen reached at /auth/consent?btnSubmit=submit would therefore turn the
// user's click on Cancel into a grant of every box the form still had checked, since r.FormValue
// found the query's btnSubmit where the body had only btnCancel (#79).
//
// Approval needs the submit control alone. A body carrying both, which no browser sends, is
// refused rather than resolved in favour of granting.
func consentApproved(postForm url.Values) bool {
	return postForm.Get("btnSubmit") == "submit" && !postForm.Has("btnCancel")
}

// tickedScopes is the scopes whose checkbox the submitted body carries, in the ceremony's order.
//
// The checkbox names are positional, consent0 .. consentN, so the key is matched exactly.
// strings.Contains found "consent1" inside "consent10" and granted a scope the user had unchecked,
// from 11 scopes upwards (#79).
//
// It takes the body alone: r.Form merges the URL query, and this form posts to action="", so a
// crafted /auth/consent?consent5=on would otherwise count as a tick.
func tickedScopes(postForm url.Values, scopes []ScopeInfo) []string {
	ticked := make([]string, 0, len(scopes))
	for idx, scopeInfo := range scopes {
		if postForm.Has(fmt.Sprintf("consent%d", idx)) {
			ticked = append(ticked, scopeInfo.Scope)
		}
	}
	return ticked
}

// consentSubmissionFact is a fact decideConsentSubmission needs and has not been given.
// HandleConsentPost loads it and asks again.
type consentSubmissionFact int

const (
	// consentSubmissionFactNone means the answer is decided.
	consentSubmissionFactNone consentSubmissionFact = iota
	// consentSubmissionFactHeldScope is the ticked selection narrowed to the permissions the user
	// holds now.
	consentSubmissionFactHeldScope
)

// consentSubmissionAnswer is how a consent submission is answered.
type consentSubmissionAnswer int

const (
	// consentSubmissionUndecided is returned beside a fact still to load.
	consentSubmissionUndecided consentSubmissionAnswer = iota
	// consentSubmissionDeclined answers access_denied for a cancel.
	consentSubmissionDeclined
	// consentSubmissionNothingTicked answers access_denied, as a cancel does, for an approval
	// ticking no scope.
	consentSubmissionNothingTicked
	// consentSubmissionNothingHeld answers access_denied for a selection holding no scope the user
	// still has.
	consentSubmissionNothingHeld
	// consentSubmissionGranted records the consent and goes on to issuance.
	consentSubmissionGranted
)

// consentSubmissionFacts is what decideConsentSubmission decides from. The held scope is nil
// until HandleConsentPost has loaded it.
type consentSubmissionFacts struct {
	approved bool
	// ticked is the scopes the user ticked, read only for an approval.
	ticked    []string
	heldScope *string
}

// decideConsentSubmission decides how a consent submission is answered, or names the next fact it
// needs to decide that.
//
// Refusal is decided by what was consented to, not by whether a key named consent... arrived. A
// submission matching no scope used to reach the issuers with an empty consented scope, which they
// read as "no consent screen was shown" and answer with the full requested scope (#79). The held
// scope is asked for only once something was ticked, so a refusal the user chose reads no
// permission.
func decideConsentSubmission(f consentSubmissionFacts) (consentSubmissionAnswer, consentSubmissionFact) {
	if !f.approved {
		return consentSubmissionDeclined, consentSubmissionFactNone
	}
	if len(f.ticked) == 0 {
		return consentSubmissionNothingTicked, consentSubmissionFactNone
	}
	if f.heldScope == nil {
		return consentSubmissionUndecided, consentSubmissionFactHeldScope
	}
	if *f.heldScope == "" {
		return consentSubmissionNothingHeld, consentSubmissionFactNone
	}
	return consentSubmissionGranted, consentSubmissionFactNone
}
