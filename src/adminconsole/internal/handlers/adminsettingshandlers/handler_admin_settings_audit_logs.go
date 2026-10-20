package adminsettingshandlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// settingsAuditLogsAPI is what the audit logs page needs: the retention settings, the event types
// it filters by, and the page of records.
type settingsAuditLogsAPI interface {
	GetAuditEventTypes(ctx context.Context, accessToken string) (*api.GetAuditEventTypesResponse, error)
	GetAuditLogsPaginated(ctx context.Context, accessToken string, page, pageSize int, auditEvent string, requestId string) (*api.GetAuditLogsResponse, error)
	GetSettingsAuditLogs(ctx context.Context, accessToken string) (*api.SettingsAuditLogsResponse, error)
	UpdateSettingsAuditLogs(ctx context.Context, accessToken string, request *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error)
}

func HandleAuditLogsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsAuditLogsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Fetch settings
		settingsResp, err := apiClient.GetSettingsAuditLogs(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsAuditLogsGet{
			AuditLogsInConsoleEnabled:  settingsResp.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settingsResp.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      settingsResp.AuditLogRetentionDays,
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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

func HandleAuditLogsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsAuditLogsAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		settingsInfo := SettingsAuditLogsPost{
			AuditLogsInConsoleEnabled:  r.FormValue("auditLogsInConsoleEnabled") == "on",
			AuditLogsInDatabaseEnabled: r.FormValue("auditLogsInDatabaseEnabled") == "on",
			AuditLogRetentionDays:      r.FormValue("auditLogRetentionDays"),
		}

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"settings":   settingsInfo,
				"error":      message,
				"errorField": errorField,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_audit_logs.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		retentionInt, err := strconv.Atoi(strings.TrimSpace(settingsInfo.AuditLogRetentionDays))
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.settings_audit_logs.retention_days_invalid"), "auditLogRetentionDays")
			return
		}

		updateReq := &api.UpdateSettingsAuditLogsRequest{
			AuditLogsInConsoleEnabled:  settingsInfo.AuditLogsInConsoleEnabled,
			AuditLogsInDatabaseEnabled: settingsInfo.AuditLogsInDatabaseEnabled,
			AuditLogRetentionDays:      retentionInt,
		}

		_, err = apiClient.UpdateSettingsAuditLogs(r.Context(), jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, auditLogsErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/audit-logs", baseURL), http.StatusFound)
	}
}

func HandleAuditLogViewerGet(
	httpHelper HttpHelper,
	apiClient settingsAuditLogsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Parse pagination parameters
		pageStr := r.URL.Query().Get("page")
		auditEvent := r.URL.Query().Get("auditEvent")
		requestId := strings.TrimSpace(r.URL.Query().Get("requestId"))

		pageInt := pagination.ParsePage(pageStr)

		const pageSize = 20

		// Fetch audit logs
		auditLogsResp, err := apiClient.GetAuditLogsPaginated(r.Context(), jwtInfo.TokenResponse.AccessToken, pageInt, pageSize, auditEvent, requestId)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// A page past the last one is only visible once the total has come back.
		// Ask again at the last page rather than render an empty list under a bar
		// that highlights a full one (#305).
		if clamped := pagination.ClampPage(auditLogsResp.Total, pageSize, pageInt); clamped != pageInt {
			pageInt = clamped
			auditLogsResp, err = apiClient.GetAuditLogsPaginated(r.Context(), jwtInfo.TokenResponse.AccessToken, pageInt, pageSize, auditEvent, requestId)
			if err != nil {
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}
		}

		// The filter dropdown's options come from the auth server, which owns the event names
		// and is the only process that writes them. Compiling the list in here would let the
		// two binaries disagree after a partial upgrade, offering a filter value the server
		// never writes or omitting one it does (#351).
		eventTypesResp, err := apiClient.GetAuditEventTypes(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Whether the auth server stores events at all, which the page says when it does not, since
		// the list then gains nothing new however long it is watched.
		settingsResp, err := apiClient.GetSettingsAuditLogs(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		rows := make([]AuditLogRow, 0, len(auditLogsResp.AuditLogs))
		for _, entry := range auditLogsResp.AuditLogs {
			details, ok := auditLogDetails(entry.Details)
			rows = append(rows, AuditLogRow{AuditLogResponse: entry, DetailPairs: details, DetailsParsed: ok})
		}

		pageResult := AuditLogsPageResult{
			AuditLogs:  auditLogsResp.AuditLogs,
			Rows:       rows,
			Total:      auditLogsResp.Total,
			Page:       pageInt,
			PageSize:   pageSize,
			AuditEvent: auditEvent,
			RequestId:  requestId,
		}

		p := pagination.New(auditLogsResp.Total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"pageResult":          pageResult,
			"paginator":           p,
			"selectedEvent":       auditEvent,
			"selectedRequestId":   requestId,
			"paginatorLink":       auditLogViewerLink(auditEvent, requestId),
			"auditEventTypes":     eventTypesResp.AuditEventTypes,
			"auditLogsInDatabase": settingsResp.AuditLogsInDatabaseEnabled,
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

// auditLogDetails reads an entry's details, a JSON object, as its keys and values in the order they
// were written: a string as it is, any other value as its JSON. Details that are no JSON object
// answer ok false, and the page shows them as they were written. They are read here rather than in
// the browser, which parsed them in a script and showed a nested value as "[object Object]".
func auditLogDetails(details string) ([]AuditLogDetail, bool) {
	decoder := json.NewDecoder(strings.NewReader(details))
	decoder.UseNumber()
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return nil, false
	}
	var pairs []AuditLogDetail
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false
		}
		// Only a JSON string is read as text: Unmarshal takes null into a string too, as "".
		text := string(raw)
		if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &text) != nil {
			return nil, false
		}
		pairs = append(pairs, AuditLogDetail{Key: key, Value: text})
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return pairs, true
}
