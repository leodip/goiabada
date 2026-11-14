package integration

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/hashutil"
)

// The admin API's preview and test send of an email template over HTTP (#818 decisions 11, 12 and
// 13): the preview answers the email with the sample values in the chosen brand and stores
// nothing; the test send reaches the mailbox as a recipient would get it, takes authserver:manage,
// and is audited as sent_test_email with the email template and the language, as the SMTP test now
// is too.

// The sample values the server draws a preview and a test send with.
const (
	previewSampleName = "Jane Doe"
	previewSampleLink = "https://example.invalid/sample-link"
)

func TestAPIEmailTemplatePreview_AnswersTheEmailAndStoresNothing(t *testing.T) {
	readToken, client := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	appName := appNameOfSettings(t)
	dark := record.NewBrand(brandName("Preview"), record.BrandAppearanceDark, "plum")
	require.NoError(t, database.CreateBrand(context.Background(), nil, &dark))
	t.Cleanup(func() {
		_ = database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
			_, err := database.DeleteBrand(context.Background(), tx, dark.Id)
			return err
		})
	})

	status, body, _ := emailTemplateCall(t, readToken, http.MethodPost, emailTemplatesPath+"/password_reset_link/fr/preview", map[string]any{
		"subject":     "Nouveau mot de passe pour {{app_name}}",
		"buttonLabel": "Changer",
		"body":        "Bonjour {{name}}, le lien vaut {{expiry}} : {{link}}\n\n{{button}}",
		"brandId":     dark.Id,
	})

	require.Equal(t, http.StatusOK, status, "preview: %v", body)
	assert.Equal(t, "Nouveau mot de passe pour "+appName, body["subject"])
	assert.Equal(t, "Bonjour "+previewSampleName+", le lien vaut 5 minutes : "+previewSampleLink, strings.TrimSpace(strings.SplitN(body["text"].(string), "\n", 2)[0]))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body["html"].(string)))
	require.NoError(t, err)
	assert.Equal(t, "fr", doc.Find("html").AttrOr("lang", ""))
	assert.Equal(t, "dark", doc.Find(`meta[name="color-scheme"]`).AttrOr("content", ""), "drawn in the chosen brand")
	assert.Equal(t, "Changer", strings.TrimSpace(doc.Find("[data-email-button] a").Text()))

	edit, err := database.GetEmailTemplate(context.Background(), nil, "password_reset_link", "fr")
	require.NoError(t, err)
	assert.Nil(t, edit, "a preview stores nothing")

	t.Run("a text a save would refuse is refused with the same answer", func(t *testing.T) {
		status, body, _ := emailTemplateCall(t, readToken, http.MethodPost, emailTemplatesPath+"/password_reset_link/fr/preview", map[string]any{
			"subject": "Lien", "buttonLabel": "Changer", "body": "Bonjour {{name}}.",
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "handler.email_template.required_placeholder_missing", body["error_code"])
		assert.Equal(t, "/body", body["error_field"])
	})
}

func TestAPIEmailTemplateSendTest_ReachesTheMailboxAndIsAudited(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	manageToken, caller := createAdminClientWithToken(t)
	appName := appNameOfSettings(t)
	to := plusAddress()

	status, body, requestId := emailTemplateCall(t, manageToken, http.MethodPost, emailTemplatesPath+"/verification_code/es/send-test", map[string]any{
		"to":      to,
		"subject": "Tu código de {{app_name}}: {{code}}",
		"body":    "Hola {{name}}:\n\n{{code}}\n\nCaduca en {{expiry}}.",
	})

	require.Equal(t, http.StatusOK, status, "send-test: %v", body)
	assert.Equal(t, map[string]any{"success": true, "encrypted": false}, body)
	message := onlyMailTo(t, to)
	title, lang, text := readEmail(t, message)
	assert.Equal(t, "Tu código de "+appName+": ABCD1234", message.Subject, "nothing in the subject marks a test")
	assert.Equal(t, message.Subject, title)
	assert.Equal(t, "es", lang)
	assert.True(t, strings.HasPrefix(text, "Hola "+previewSampleName+":\n\nABCD1234\n\nCaduca en 5 minutos.\n"), text)

	assert.Equal(t, []map[string]any{{
		"logged_in_user": caller.ClientIdentifier,
		"email_digest":   hashutil.HashString(strings.ToLower(to)),
		"email_template": "verification_code",
		"language":       "es",
	}}, auditRows(t, manageToken, "sent_test_email", requestId))
}

// authserver:manage-settings reads and previews templates but is refused a test send, which is
// audited under the settings ceiling and sends nothing (#818 decisions 9 and 12).
func TestAPIEmailTemplateSendTest_TakesManage(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	token, client := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	to := plusAddress()
	text := map[string]any{"to": to, "subject": "Bienvenido", "buttonLabel": "Activar", "body": "Hola.\n\n{{button}}"}

	status, _, _ := emailTemplateCall(t, token, http.MethodPost, emailTemplatesPath+"/welcome/es/preview", text)
	assert.Equal(t, http.StatusOK, status, "manage-settings previews")

	status, body, requestId := emailTemplateCall(t, token, http.MethodPost, emailTemplatesPath+"/welcome/es/send-test", text)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", body["error_code"])
	rows := refusalRows(t, manageToken, requestId)
	require.Len(t, rows, 1)
	assert.Equal(t, "settings", rows[0]["ceiling"])
	assert.Equal(t, "/api/v1/admin/email-templates/{email}/{language}/send-test", rows[0]["route"])
	assert.Empty(t, sentTo(t, to), "nothing is sent")
}

// With SMTP off a test send is refused as the SMTP test is.
func TestAPIEmailTemplateSendTest_SMTPOffIsRefused(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.SMTPEnabled = false })
	manageToken, _ := createAdminClientWithToken(t)

	status, body, _ := emailTemplateCall(t, manageToken, http.MethodPost, emailTemplatesPath+"/otp_enabled/en/send-test", map[string]any{
		"to": plusAddress(), "subject": "Two-factor on", "body": "Hello {{name}}.",
	})

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "SMTP_NOT_ENABLED", body["error_code"])
}

// The SMTP test sends the test email template, and its entry names it and the language it was
// sent in (#818 decision 13).
func TestAPISettingsEmailSendTest_IsAuditedWithTheTestTemplate(t *testing.T) {
	useMailpitSMTP(t)
	requireDatabaseAuditLogs(t)
	manageToken, caller := createAdminClientWithToken(t)
	to := plusAddress()

	resp, requestId := sendAdmin(t, manageToken, http.MethodPost, "/api/v1/admin/settings/email/send-test", api.SendTestEmailRequest{To: to})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, []map[string]any{{
		"logged_in_user": caller.ClientIdentifier,
		"email_digest":   hashutil.HashString(strings.ToLower(to)),
		"email_template": "test",
		"language":       "en",
	}}, auditRows(t, manageToken, "sent_test_email", requestId))
}
