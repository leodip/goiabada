package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleAdminSettingsAuditLogsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
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

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": savedSuccessfully,
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
	httpSession sessionstore.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		settingsInfo := SettingsAuditLogsPost{
			AuditLogsInConsoleEnabled:  r.FormValue("auditLogsInConsoleEnabled") == "on",
			AuditLogsInDatabaseEnabled: r.FormValue("auditLogsInDatabaseEnabled") == "on",
			AuditLogRetentionDays:      r.FormValue("auditLogRetentionDays"),
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"settings": settingsInfo,
				"error":    message,
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

		sess.SetFlash("savedSuccessfully", "true")
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
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Parse pagination parameters
		pageStr := r.URL.Query().Get("page")
		auditEvent := r.URL.Query().Get("auditEvent")
		requestId := r.URL.Query().Get("requestId")

		pageInt := pagination.ParsePage(pageStr)

		const pageSize = 20

		// Fetch audit logs
		auditLogsResp, err := apiClient.GetAuditLogsPaginated(jwtInfo.TokenResponse.AccessToken, pageInt, pageSize, auditEvent, requestId)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// A page past the last one is only visible once the total has come back.
		// Ask again at the last page rather than render an empty list under a bar
		// that highlights a full one (#305).
		if clamped := pagination.ClampPage(auditLogsResp.Total, pageSize, pageInt); clamped != pageInt {
			pageInt = clamped
			auditLogsResp, err = apiClient.GetAuditLogsPaginated(jwtInfo.TokenResponse.AccessToken, pageInt, pageSize, auditEvent, requestId)
			if err != nil {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		pageResult := AuditLogsPageResult{
			AuditLogs:  auditLogsResp.AuditLogs,
			Total:      auditLogsResp.Total,
			Page:       pageInt,
			PageSize:   pageSize,
			AuditEvent: auditEvent,
			RequestId:  requestId,
		}

		p := pagination.New(auditLogsResp.Total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"pageResult":        pageResult,
			"paginator":         p,
			"selectedEvent":     auditEvent,
			"selectedRequestId": requestId,
			"paginatorLink":     auditLogViewerLink(auditEvent, requestId),
			"auditEventTypes":   constants.AuditEventTypes,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_audit_log_viewer.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// auditLogViewerLink is the base URL the paginator appends "page" to, carrying whichever filters
// are set. It is built here rather than with printf in the template because a request id is
// client-chosen: one holding an "&" pasted into a URL string splits into a second parameter when
// addUrlParam parses it, so "?requestId=x&page=9" would put page=9 in front of every page link and
// the handler would read that one. url.Values escapes it once (#328).
func auditLogViewerLink(auditEvent string, requestId string) string {
	const path = "/admin/settings/audit-log-viewer"

	query := url.Values{}
	if auditEvent != "" {
		query.Set("auditEvent", auditEvent)
	}
	if requestId != "" {
		query.Set("requestId", requestId)
	}
	if len(query) == 0 {
		return path
	}
	return path + "?" + query.Encode()
}
