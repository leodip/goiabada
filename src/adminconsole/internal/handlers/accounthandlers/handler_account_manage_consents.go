package accounthandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func HandleAccountManageConsentsGet(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	type consentInfo struct {
		ConsentId         int64
		Client            string
		ClientDescription string
		GrantedAt         string
		Scope             string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		userConsents, err := database.GetConsentsByUserId(nil, user.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserConsentsLoadClients(nil, userConsents)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		consentInfoArr := []consentInfo{}
		for _, c := range userConsents {
			ci := consentInfo{
				ConsentId:         c.Id,
				Client:            c.Client.ClientIdentifier,
				ClientDescription: c.Client.Description,
				GrantedAt:         c.GrantedAt.Time.Format(time.RFC1123),
				Scope:             c.Scope,
			}
			consentInfoArr = append(consentInfoArr, ci)
		}

		bind := map[string]interface{}{
			"consents":  consentInfoArr,
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_manage_consents.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountManageConsentsRevokePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("could not find consent id to revoke")))
			return
		}

		userConsents, err := database.GetConsentsByUserId(nil, user.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		found := false
		for _, c := range userConsents {
			if c.Id == int64(consentId) {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("unable to revoke consent with id %v because it doesn't belong to user id %v", consentId, user.Id)))
			return
		} else {

			err := database.DeleteUserConsent(nil, int64(consentId))
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditDeletedUserConsent, map[string]interface{}{
				"userId":       user.Id,
				"consentId":    int64(consentId),
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})

			result := struct {
				Success bool
			}{
				Success: true,
			}
			httpHelper.EncodeJson(w, r, result)
		}
	}
}
