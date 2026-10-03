package renderintegration

import (
	"net/url"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/pagination"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// TestRender_AdminSettingsAuditLogViewer is seam 8's rendering half (#328). The page test
// above the handler drives a mocked HttpHelper and therefore renders nothing, so the three
// things that can only go wrong in HTML are proved here: the fourth column carries each
// row's request id, an entry written off a request shows a dash rather than an empty cell,
// and an id echoed back into the filter input is escaped. The id is whatever a client put
// in X-Request-Id, so the escaping is the one thing on this page standing between a stored
// id and script in an administrator's browser.
func TestRender_AdminSettingsAuditLogViewer(t *testing.T) {
	auditWritten := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

	out := renderMenuPage(t, "/admin_settings_audit_log_viewer.html", map[string]interface{}{
		"pageResult": adminsettingshandlers.AuditLogsPageResult{
			AuditLogs: []api.AuditLogResponse{
				{Id: 1, CreatedAt: auditWritten, AuditEvent: "user_login",
					Details: `{"email":"alice@example.com"}`, RequestId: "host/Ppg6bHPK5f-000012"},
				{Id: 2, CreatedAt: auditWritten.Add(time.Second), AuditEvent: "revoked_user_auth_state",
					Details: `{}`, RequestId: ""},
			},
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
		"auditEventTypes": []string{"user_login", "revoked_user_auth_state"},
	})

	// The column exists and is localized: pt-BR, like every other page in this package.
	assert.Contains(t, out, "Id da requisição")

	// Each row's id, and the dash standing for "not written on a request".
	assert.Contains(t, out, "host/Ppg6bHPK5f-000012")
	assert.Contains(t, out, ">-</td>")

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

	assert.Contains(t, out, "<td>16/09/2026 12:00</td>", "the created-at cell is not localized")
	assert.NotContains(t, out, "16 Sep 2026", "an English month name is what the old layout produced")
}
