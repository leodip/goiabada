package handlers

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleIssueGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
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
