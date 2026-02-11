package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/unknwon/paginater"
)

func HandleAdminSettingsAuditLogsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Fetch settings
		settingsResp, err := apiClient.GetSettingsAuditLogs(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsAuditLogsGet{
			AuditLogsInConsoleEnabled:  settingsResp.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settingsResp.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      settingsResp.AuditLogRetentionDays,
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_audit_logs.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsAuditLogsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		settingsInfo := SettingsAuditLogsPost{
			AuditLogsInConsoleEnabled:  r.FormValue("auditLogsInConsoleEnabled") == "on",
			AuditLogsInDatabaseEnabled: r.FormValue("auditLogsInDatabaseEnabled") == "on",
			AuditLogRetentionDays:      r.FormValue("auditLogRetentionDays"),
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_audit_logs.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Parse retention days with validation
		retentionInt := 0
		if v := settingsInfo.AuditLogRetentionDays; len(v) > 0 {
			p, err := strconv.Atoi(v)
			if err != nil {
				renderError("Audit log retention days must be a valid number.")
				return
			}
			retentionInt = p
		}

		updateReq := &api.UpdateSettingsAuditLogsRequest{
			AuditLogsInConsoleEnabled:  settingsInfo.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settingsInfo.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      retentionInt,
		}

		_, err := apiClient.UpdateSettingsAuditLogs(jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/audit-logs", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}

func HandleAdminSettingsAuditLogViewerGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Parse pagination parameters
		pageStr := r.URL.Query().Get("page")
		auditEvent := r.URL.Query().Get("auditEvent")

		pageInt, err := strconv.Atoi(pageStr)
		if err != nil || pageInt < 1 {
			pageInt = 1
		}

		const pageSize = 20

		// Fetch audit logs
		auditLogsResp, err := apiClient.GetAuditLogsPaginated(jwtInfo.TokenResponse.AccessToken, pageInt, pageSize, auditEvent)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		pageResult := AuditLogsPageResult{
			AuditLogs:  auditLogsResp.AuditLogs,
			Total:      auditLogsResp.Total,
			Page:       pageInt,
			PageSize:   pageSize,
			AuditEvent: auditEvent,
		}

		p := paginater.New(auditLogsResp.Total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"pageResult":      pageResult,
			"paginator":       p,
			"selectedEvent":   auditEvent,
			"auditEventTypes": constants.AuditEventTypes,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_audit_log_viewer.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
