package adminclienthandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminClientOAuth2Get(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		adminClientOAuth2Flows := struct {
			ClientId                 int64
			ClientIdentifier         string
			IsPublic                 bool
			AuthorizationCodeEnabled bool
			ClientCredentialsEnabled bool
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			IsPublic:                 client.IsPublic,
			AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientOAuth2Flows,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_oauth2_flows.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientOAuth2Post(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		isSystemLevelClient := client.IsSystemLevelClient()
		if isSystemLevelClient {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
			return
		}

		authCodeEnabled := false
		if r.FormValue("authCodeEnabled") == "on" {
			authCodeEnabled = true
		}
		clientCredentialsEnabled := false
		if r.FormValue("clientCredentialsEnabled") == "on" {
			clientCredentialsEnabled = true
		}

		client.AuthorizationCodeEnabled = authCodeEnabled
		client.ClientCredentialsEnabled = clientCredentialsEnabled
		if client.IsPublic {
			client.ClientCredentialsEnabled = false
		}

		err = database.UpdateClient(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedClientOAuth2Flows, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/oauth2-flows", config.Get().BaseURL, client.Id), http.StatusFound)
	}
}
