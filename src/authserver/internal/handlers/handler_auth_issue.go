package handlers

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleIssueGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	tokenIssuer TokenIssuer,
	database data.Database,
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

		requiredState := oauth.AuthStateReadyToIssueCode
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// Check if this is an implicit flow request
		if oauth.ParseResponseType(authContext.ResponseType).IsImplicitFlow() {
			err = handleImplicitFlow(w, r, authContext, sessionIdentifier, authHelper, tokenIssuer, database, auditLogger)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Authorization Code Flow
		createCodeInput := &oauth.CreateCodeInput{
			AuthContext:       *authContext,
			SessionIdentifier: sessionIdentifier,
		}
		code, err := codeIssuer.CreateAuthCode(createCodeInput)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditCreatedAuthCode, map[string]interface{}{
			"userId":   createCodeInput.UserId,
			"clientId": code.ClientId,
			"codeId":   code.Id,
		})

		err = authHelper.ClearAuthContext(w, r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// handleImplicitFlow handles the implicit grant flow token issuance.
// Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5, tokens are returned in fragment.
func handleImplicitFlow(
	w http.ResponseWriter,
	r *http.Request,
	authContext *oauth.AuthContext,
	sessionIdentifier string,
	authHelper AuthHelper,
	tokenIssuer TokenIssuer,
	database data.Database,
	auditLogger AuditLogger,
) error {
	// Load client
	client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId)))
	}

	// Load user
	user, err := database.GetUserById(nil, authContext.UserId)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.WithStack(errors.New(fmt.Sprintf("user %v not found", authContext.UserId)))
	}

	// Determine what tokens to issue based on response_type
	rtInfo := oauth.ParseResponseType(authContext.ResponseType)
	issueAccessToken := rtInfo.HasToken
	issueIdToken := rtInfo.HasIdToken

	// auth_time should reflect when authentication completed in the current flow,
	// not when the session originally started. This is consistent with the auth code
	// flow (which sets AuthenticatedAt to time.Now() in code_issuer.go) and ensures
	// correct auth_time after step-up authentication.
	authenticatedAt := time.Now().UTC()

	// Determine the scope to use (consented scope if available, otherwise requested scope)
	scope := authContext.Scope
	if authContext.ConsentedScope != "" {
		scope = authContext.ConsentedScope
	}

	// Generate tokens
	implicitInput := &oauth.ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             scope,
		AcrLevel:          authContext.AcrLevel,
		AuthMethods:       authContext.AuthMethods,
		SessionIdentifier: sessionIdentifier,
		Nonce:             authContext.Nonce,
		AuthenticatedAt:   authenticatedAt,
	}

	tokenResponse, err := tokenIssuer.GenerateTokenResponseForImplicit(r.Context(), implicitInput, issueAccessToken, issueIdToken)
	if err != nil {
		return err
	}

	// Audit log
	auditLogger.Log(constants.AuditTokenIssuedImplicitResponse, map[string]interface{}{
		"userId":            user.Id,
		"clientId":          client.Id,
		"scope":             scope,
		"responseType":      authContext.ResponseType,
		"issueAccessToken":  issueAccessToken,
		"issueIdToken":      issueIdToken,
	})

	// Clear auth context
	err = authHelper.ClearAuthContext(w, r)
	if err != nil {
		return err
	}

	// Issue tokens via fragment (implicit flow always uses fragment response mode)
	return issueImplicitTokens(w, r, authContext.RedirectURI, authContext.State, tokenResponse)
}

// issueImplicitTokens redirects to the client with tokens in the fragment.
// Per RFC 6749 4.2.2, implicit grant tokens MUST be delivered via fragment.
func issueImplicitTokens(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	state string,
	tokenResponse *oauth.ImplicitGrantResponse,
) error {
	values := url.Values{}

	if tokenResponse.AccessToken != "" {
		values.Add("access_token", tokenResponse.AccessToken)
		values.Add("token_type", tokenResponse.TokenType)
		values.Add("expires_in", fmt.Sprintf("%d", tokenResponse.ExpiresIn))
	}

	if tokenResponse.IdToken != "" {
		values.Add("id_token", tokenResponse.IdToken)
	}

	if tokenResponse.Scope != "" {
		values.Add("scope", tokenResponse.Scope)
	}

	if strings.TrimSpace(state) != "" {
		values.Add("state", state)
	}

	http.Redirect(w, r, redirectURI+"#"+values.Encode(), http.StatusFound)
	return nil
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code *models.Code, responseMode string) error {

	if responseMode == "" {
		responseMode = "query"
	}

	if responseMode == "fragment" {
		values := url.Values{}
		values.Add("code", code.Code)
		values.Add("state", code.State)
		http.Redirect(w, r, code.RedirectURI+"#"+values.Encode(), http.StatusFound)
		return nil
	}
	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = code.RedirectURI
		m["code"] = code.Code
		if len(strings.TrimSpace(code.State)) > 0 {
			m["state"] = code.State
		}

		t, err := template.ParseFS(templateFS, "form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}
		err = t.Execute(w, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		return nil
	}

	// default to query
	redirUrl, _ := url.ParseRequestURI(code.RedirectURI)
	values := redirUrl.Query()
	values.Add("code", code.Code)
	values.Add("state", code.State)
	redirUrl.RawQuery = values.Encode()
	http.Redirect(w, r, redirUrl.String(), http.StatusFound)
	return nil
}
