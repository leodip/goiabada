package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAdminClientNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientNewPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":            message,
				"clientIdentifier": r.FormValue("clientIdentifier"),
				"description":      r.FormValue("description"),
				"csrfField":        csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		description := r.FormValue("description")

		if strings.TrimSpace(clientIdentifier) == "" {
			renderError("Client identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		authorizationCodeEnabled := r.FormValue("authorizationCodeEnabled") == "on"
		clientCredentialsEnabled := r.FormValue("clientCredentialsEnabled") == "on"

		// Call AuthServer API to create client
		_, err := apiClient.CreateClient(jwtInfo.TokenResponse.AccessToken, &api.CreateClientRequest{
			ClientIdentifier:         strings.TrimSpace(clientIdentifier),
			Description:              strings.TrimSpace(description),
			AuthorizationCodeEnabled: authorizationCodeEnabled,
			ClientCredentialsEnabled: clientCredentialsEnabled,
		})
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
