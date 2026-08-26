package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
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
		if oidc.IsIdTokenScope(scope) || oidc.IsOfflineAccessScope(scope) {
			scopeInfoArr = append(scopeInfoArr, ScopeInfo{
				Scope:            scope,
				Description:      i18n.T(ctx, oidc.GetIdTokenScopeDescriptionKey(scope)),
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

func HandleConsentGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateRequiresConsent
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		scopeInfoArr := buildScopeInfoArray(r.Context(), authContext.Scope, consent)

		scopesFullyConsented := true
		for _, scopeInfo := range scopeInfoArr {
			scopesFullyConsented = scopesFullyConsented && scopeInfo.AlreadyConsented
		}

		// Show consent screen if:
		// - Not all scopes are fully consented, OR
		// - offline_access is requested (always re-confirm refresh token grant), OR
		// - prompt=consent was explicitly requested (force consent UI)
		if !scopesFullyConsented || authContext.HasScope(oidc.OfflineAccessScope) || authContext.HasPromptValue("consent") {
			displayInfo := getClientDisplayInfo(database, client)

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

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/consent.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		} else {
			// consent is done, ready to issue code
			authContext.AuthState = oauth.AuthStateReadyToIssueCode
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
		}
	}
}

func HandleConsentPost(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
	templateFS fs.FS,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Before the AuthState check, so a form left open in another tab gets the 400 mismatch
		// page rather than the 500 that a replaced context's state would produce. Before the
		// btnSubmit/btnCancel dispatch too, so a stale cancel cannot clear the auth context of
		// the ceremony that is actually current (#79).
		//
		// r.PostFormValue rather than r.FormValue: this form posts to action="", so r.Form
		// would let /auth/consent?ceremonyId=... supply the id, and only the submitted body is
		// a submission. Same reasoning as the checkbox selection below.
		if !ceremonyMatches(authContext.CeremonyId, r.PostFormValue(ceremonyIdField)) {
			rejectCeremonyMismatch(httpHelper, auditLogger, w, r, authContext)
			return
		}

		requiredState := oauth.AuthStateRequiresConsent
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// Both action controls are read from the submitted body, for the same reason as the
		// checkbox selection below: this form posts to action="", so r.Form would merge the URL
		// query in, and a button that was not clicked sends no key at all. A consent screen
		// reached at /auth/consent?btnSubmit=submit would therefore turn the user's click on
		// Cancel into a grant of every box the form still had checked, since r.FormValue found
		// the query's btnSubmit where the body had only btnCancel (#79).
		//
		// Approval needs the submit control alone. A body carrying both, which no browser sends,
		// is refused rather than resolved in favour of granting.
		approved := r.PostForm.Get("btnSubmit") == "submit" && !r.PostForm.Has("btnCancel")

		if approved {

			// The checkbox names are positional, consent0 .. consentN, so the key is matched
			// exactly. strings.Contains found "consent1" inside "consent10" and granted a scope
			// the user had unchecked, from 11 scopes upwards (#79).
			//
			// r.PostForm rather than r.Form: r.Form merges the URL query, and this form posts to
			// action="", so a crafted /auth/consent?consent5=on would otherwise count as a tick.
			scopeInfoArr := buildScopeInfoArray(r.Context(), authContext.Scope, nil)
			grantedScopes := make([]string, 0, len(scopeInfoArr))
			for idx, scopeInfo := range scopeInfoArr {
				if r.PostForm.Has(fmt.Sprintf("consent%d", idx)) {
					grantedScopes = append(grantedScopes, scopeInfo.Scope)
				}
			}

			// Refusal is decided by what was consented to, not by whether a key named consent...
			// arrived. A submission matching no scope used to reach the issuers with an empty
			// consented scope, which they read as "no consent screen was shown" and answer with
			// the full requested scope (#79).
			if len(grantedScopes) == 0 {
				// A refusal answers the client with an error redirect, and an error redirect now
				// carries the client it is answering, so provenance is resolved here rather than
				// in the approval branch below where the load used to be the only one. The two
				// branches are mutually exclusive, so no request loads the client twice (#108).
				refusedClient := clientProvenance(database, authContext.ClientId)

				// The clear goes FIRST. ClearAuthContext persists the deletion through a
				// Set-Cookie on w, and redirToClientWithError commits the response in every
				// response mode, so clearing afterwards leaves the header on a response already
				// written. The browser then keeps an auth context in requires_consent, which
				// GET /auth/consent accepts: replaying it renders the consent screen again and
				// the user may approve, so the client would receive access_denied and then a
				// code for the same authorization request (#141).
				err = authHelper.ClearAuthContext(w, r)
				if err != nil {
					// The clear failed, so Save wrote no cookie and the browser still holds the
					// auth context. The client is owed an error response regardless: its redirect
					// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
					// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
					slog.Error("failed to clear the auth context, answering the client with server_error",
						"error", err)
					err = redirToClientWithError(w, r, database, httpHelper, templateFS,
						redirectErrorFromAuthContext(authContext, refusedClient, "server_error", "Internal server error"))
					if err != nil {
						// Nowhere left to send the client, so the 500 is the last resort here.
						httpHelper.InternalServerError(w, r, err)
					}
					return
				}

				err = redirToClientWithError(w, r, database, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, refusedClient,
						"access_denied", "The user did not provide consent"))
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			} else {

				client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if client == nil {
					httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
					return
				}

				user, err := database.GetUserById(nil, authContext.UserId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				if user == nil {
					httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
					return
				}

				consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				if consent == nil {
					consent = &models.UserConsent{
						UserId:    user.Id,
						ClientId:  client.Id,
						GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
					}
				}

				// The join assigns the whole selection, so an existing consent is replaced rather
				// than appended to.
				consent.Scope = strings.Join(grantedScopes, " ")

				if consent.Id > 0 {
					err = database.UpdateUserConsent(nil, consent)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}
				} else {
					err = database.CreateUserConsent(nil, consent)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}
				}
				authContext.ConsentedScope = consent.Scope

				auditLogger.Log(constants.AuditSavedConsent, map[string]interface{}{
					"userId":    consent.UserId,
					"clientId":  consent.ClientId,
					"consentId": consent.Id,
				})

				// consent is done, ready to issue code
				authContext.AuthState = oauth.AuthStateReadyToIssueCode
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/issue", http.StatusFound)
			}
		} else {

			// Provenance is resolved here for the same reason as in the no-scopes-consented
			// refusal above: this branch answers the client with an error redirect, and the
			// redirect now carries the client it is answering (#108).
			refusedClient := clientProvenance(database, authContext.ClientId)

			// The clear goes FIRST, for the same reason as the no-scopes-consented refusal
			// above: a Set-Cookie written after redirToClientWithError has committed never
			// reaches the wire, so the browser keeps an auth context in requires_consent that
			// a replay of GET /auth/consent can still turn into a code (#141).
			err = authHelper.ClearAuthContext(w, r)
			if err != nil {
				// The clear failed, so Save wrote no cookie and the browser still holds the
				// auth context. The client is owed an error response regardless: its redirect
				// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
				// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
				slog.Error("failed to clear the auth context, answering the client with server_error",
					"error", err)
				err = redirToClientWithError(w, r, database, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, refusedClient, "server_error", "Internal server error"))
				if err != nil {
					// Nowhere left to send the client, so the 500 is the last resort here.
					httpHelper.InternalServerError(w, r, err)
				}
				return
			}

			err = redirToClientWithError(w, r, database, httpHelper, templateFS,
				redirectErrorFromAuthContext(authContext, refusedClient,
					"access_denied", "The user did not provide consent"))
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			return
		}
	}
}
