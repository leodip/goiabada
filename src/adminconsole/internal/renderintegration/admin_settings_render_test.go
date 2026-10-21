package renderintegration

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// TestRender_AdminSettingsAuditLogViewer is seam 8's rendering half (#328). The page test
// above the handler drives a mocked HttpHelper and therefore renders nothing, so the things that
// can only go wrong in HTML are proved here: each event names its request id and links to that
// request's events, an entry written off a request names none, the details are drawn as keys and
// values with their markup escaped, and an id is escaped wherever it is echoed, in a row's link
// and in the filter input. The id is whatever a client put in X-Request-Id, so the escaping is the
// one thing on this page standing between a stored id and script in an administrator's browser.
func TestRender_AdminSettingsAuditLogViewer(t *testing.T) {
	auditWritten := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	logs := []api.AuditLogResponse{
		{Id: 1, CreatedAt: auditWritten, AuditEvent: "user_login",
			Details: `{"email":"alice@example.com","name":"<b>x</b>"}`, RequestId: "host/Ppg6bHPK5f-000012"},
		{Id: 2, CreatedAt: auditWritten.Add(time.Second), AuditEvent: "revoked_user_auth_state",
			Details: `{}`, RequestId: ""},
		{Id: 3, CreatedAt: auditWritten.Add(2 * time.Second), AuditEvent: "user_login",
			Details: `{}`, RequestId: `x"><b>y</b>&page=9`},
	}
	rows := []adminsettingshandlers.AuditLogRow{
		{AuditLogResponse: logs[0], DetailsParsed: true, DetailPairs: []adminsettingshandlers.AuditLogDetail{
			{Key: "email", Value: "alice@example.com"}, {Key: "name", Value: "<b>x</b>"}}},
		{AuditLogResponse: logs[1], DetailsParsed: true},
		{AuditLogResponse: logs[2], DetailsParsed: true},
	}

	out := renderMenuPage(t, "/admin_settings_audit_log_viewer.html", map[string]interface{}{
		"pageResult": adminsettingshandlers.AuditLogsPageResult{
			AuditLogs:  logs,
			Rows:       rows,
			Total:      73,
			Page:       4,
			PageSize:   20,
			AuditEvent: "user_login",
			RequestId:  `"><script>alert(1)</script>`,
		},
		"paginator":         pagination.New(73, 20, 4, 5),
		"selectedEvent":     "user_login",
		"selectedRequestId": `"><script>alert(1)</script>`,
		"paginatorLink": "/admin/settings/audit-log-viewer?auditEvent=user_login&requestId=" +
			url.QueryEscape(`"><script>alert(1)</script>`),
		"auditEventTypes":     []string{"user_login", "revoked_user_auth_state"},
		"auditLogsInDatabase": true,
	})

	// Each event names its request id, localized: pt-BR, like every other page in this package.
	// The id links to that request's events, as one query parameter whatever it holds, and an entry
	// written off a request names none.
	assert.Contains(t, out, `Id da requisição: <a class="text-link inline-block max-w-full font-mono wrap-anywhere" `+
		`href="/admin/settings/audit-log-viewer?requestId=host%2fPpg6bHPK5f-000012">host/Ppg6bHPK5f-000012`+
		`<span class="sr-only"> – mostrar todos os eventos desta requisição</span></a>`)
	assert.Contains(t, out, `href="/admin/settings/audit-log-viewer?requestId=x%22%3e%3cb%3ey%3c%2fb%3e%26page%3d9">`+
		`x&#34;&gt;&lt;b&gt;y&lt;/b&gt;&amp;page=9<span`)
	assert.Equal(t, 2, strings.Count(out, "Id da requisição: <a"), "the entry written off a request names no id")

	// An event's name may break after each underscore, and nowhere else.
	assert.Contains(t, out, ">revoked_<wbr>user_<wbr>auth_<wbr>state</span>")

	// The details as keys and values, a value's markup escaped; an empty object says so.
	assert.Contains(t, out, `<dt class="shrink-0 font-semibold">email</dt><dd class="min-w-0 wrap-anywhere">alice@example.com</dd>`)
	assert.Contains(t, out, `<dd class="min-w-0 wrap-anywhere">&lt;b&gt;x&lt;/b&gt;</dd>`)
	assert.NotContains(t, out, "<b>x</b>")
	assert.Equal(t, 2, strings.Count(out, `<span class="text-ink-muted">Nenhum</span>`))

	// The id typed into the filter comes back into the input escaped. The raw sequence
	// would close the value attribute and open a script element; the escaped one cannot.
	assert.NotContains(t, out, `<script>alert(1)</script>`)
	assert.Contains(t, out, "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;")

	// The paginator's links carry both filters, escaped, and the page number is the only
	// "page" in them: an id holding "&page=" would otherwise win over the real one.
	assert.Contains(t, out, "requestId=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
	assert.Contains(t, out, "auditEvent=user_login")
	assert.NotContains(t, out, "page=-1")

	// The timestamp column, which is two values in one cell and only one of them is prose.
	// The text a reader sees is localized, in pt-BR's layout; the <time> element's datetime
	// attribute is the machine value the HTML element defines and stays RFC3339 under every
	// locale, which is what a later localization sweep must not "finish" (#373, decision 11).
	assert.Contains(t, out, `<time datetime="2026-09-12T10:00:00Z">12/09/2026 10:00</time>`)
	assert.NotContains(t, out, ">2026-09-12T10:00:00Z<",
		"the ISO string is the attribute, never the text the page shows")

	// The event filter is a GET form the browser escapes, and the event list filters as typed.
	assert.Contains(t, out, `<form class="mb-5 flex flex-wrap items-end gap-3" method="get" action="/admin/settings/audit-log-viewer" role="search">`)
	assert.Contains(t, out, `<select class="control" id="auditEventFilter" name="auditEvent" data-searchable>`)
	assert.Contains(t, out, `<option value="user_login" selected>user_login</option>`)
	assert.NotContains(t, out, "não está guardando eventos", "events are stored, so the page says nothing of it")
}

// While the auth server stores no events, the page says so, beside the list it still has.
func TestRender_AdminSettingsAuditLogViewerSaysWhenNothingIsStored(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_audit_log_viewer.html", map[string]interface{}{
		"pageResult":          adminsettingshandlers.AuditLogsPageResult{Page: 1, PageSize: 20},
		"paginator":           pagination.New(0, 20, 1, 5),
		"selectedEvent":       "",
		"selectedRequestId":   "",
		"paginatorLink":       "/admin/settings/audit-log-viewer",
		"auditEventTypes":     []string{"user_login"},
		"auditLogsInDatabase": false,
	})

	assert.Contains(t, out, "não está guardando eventos de auditoria no banco de dados")
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/audit-logs">Registro de auditoria</a>`)
	assert.Contains(t, out, `<p class="empty-state">Nenhum evento de auditoria ainda.</p>`)
}

// The signing keys page, the third of the three dates its handler used to format. Its layout was
// "02 Jan 2006 15:04:05 MST", so it is the one site that showed a zone; the catalog layout carries
// none, which decision 8 recorded as the wrinkle it answers. The values are UTC, as every date in
// this console has always been (#373).
func TestRender_AdminSettingsKeysLocalizesTheCreatedAtCell(t *testing.T) {
	created := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	out := renderMenuPage(t, "/admin_settings_keys.html", map[string]interface{}{
		"keys": []adminsettingshandlers.SettingsKey{{
			Id: 1, CreatedAt: &created, State: "current", KeyIdentifier: "key-1",
			Type: "RSA", Algorithm: "RS256",
		}},
	})

	assert.Contains(t, out, `<td data-label="Criada">16/09/2026 12:00</td>`, "the created-at cell is not localized")
	assert.NotContains(t, out, "16 Sep 2026", "an English month name is what the old layout produced")
}
