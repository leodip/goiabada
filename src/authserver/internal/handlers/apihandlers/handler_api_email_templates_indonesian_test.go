package apihandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The admin API takes id wherever it takes a built-in language tag (#668 decision 1): an email
// template is read with its Indonesian text, and that text is saved, read back, previewed and reset
// by requests naming id in their path.

// The read answers an Indonesian language, its built-in text, and an Indonesian edit laid over it.
func TestEmailTemplateGet_AnswersTheIndonesianTextAndItsEdit(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return([]record.EmailTemplate{
		{EmailTemplate: "password_reset_link", Language: "id", Subject: nullString("Kata sandi baru untuk Anda")},
	}, nil)

	rr, body := serveEmailTemplate(HandleEmailTemplateGet(database),
		emailTemplateRequest(http.MethodGet, "authserver:admin-read", "password_reset_link", "", ""))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	id := languageOf(t, body["emailTemplate"].(map[string]any), "id")
	assert.Equal(t, "edited", id["status"])
	assert.Equal(t, []any{"subject"}, id["editedFields"])
	builtIn := id["builtInText"].(map[string]any)
	assert.Equal(t, "Atur ulang kata sandi", builtIn["subject"])
	assert.Equal(t, "Atur ulang kata sandi", builtIn["buttonLabel"])
	assert.True(t, strings.HasPrefix(builtIn["body"].(string),
		"Halo {{name}},\n\nAnda dapat mengatur ulang kata sandi Anda melalui tautan di bawah ini:\n\n{{button}}\n\n{{link}}\n\n"), builtIn["body"])
	editor := id["editorText"].(map[string]any)
	assert.Equal(t, "Kata sandi baru untuk Anda", editor["subject"])
	assert.Equal(t, builtIn["body"], editor["body"])
}

// A save naming id stores the Indonesian edit under id, answers it and audits it with language id.
func TestEmailTemplatePut_StoresAnIndonesianEdit(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	var saved *record.EmailTemplate
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("SaveEmailTemplate", mock.Anything, emailTemplateTx, mock.AnythingOfType("*record.EmailTemplate")).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.EmailTemplate) }).Return(nil).Once()

	rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
		emailTemplateRequest(http.MethodPut, "authserver:manage", "password_changed", "id",
			saveBody(t, "Kata sandi {{app_name}} Anda diubah", "", "Halo {{name}}, kata sandi Anda telah diubah.")))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotNil(t, saved)
	assert.Equal(t, "password_changed", saved.EmailTemplate)
	assert.Equal(t, "id", saved.Language)
	assert.Equal(t, nullString("Kata sandi {{app_name}} Anda diubah"), saved.Subject)
	assert.Equal(t, nullString("Halo {{name}}, kata sandi Anda telah diubah."), saved.Body)

	assert.Equal(t, "id", body["language"])
	assert.Equal(t, "edited", body["status"])
	assert.Equal(t, []any{"subject", "body"}, body["editedFields"])
	assert.Equal(t, "Kata sandi Anda telah diubah", body["builtInText"].(map[string]any)["subject"])
	require.Len(t, *records, 1)
	assert.Equal(t, "updated_email_template", (*records)[0].event)
	assert.Equal(t, "id", (*records)[0].details["language"])
}

// A reset naming id removes the Indonesian edit and audits it with language id.
func TestEmailTemplateDelete_ResetsTheIndonesianText(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("DeleteEmailTemplate", mock.Anything, emailTemplateTx, "verification_code", "id").Return(true, nil).Once()

	rr, _ := serveEmailTemplate(HandleEmailTemplateDelete(database, auditLogger),
		emailTemplateRequest(http.MethodDelete, "authserver:manage", "verification_code", "id", ""))

	assert.Equal(t, http.StatusNoContent, rr.Code)
	require.Len(t, *records, 1)
	assert.Equal(t, map[string]interface{}{
		"email_template": "verification_code", "language": "id", "logged_in_user": grantCaller,
	}, (*records)[0].details)
}

// A preview naming id draws the Indonesian built-in text marked lang="id", the lifetime in menit,
// for a caller reading the console in English.
func TestEmailTemplatePreview_DrawsTheIndonesianText(t *testing.T) {
	r := sampleRequest(t, "authserver:admin-read", "activation_link", "id", "en", acmeSettings(),
		readBuiltInText(t, "activation_link", "id"))

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "Aktifkan akun Anda", body["subject"])
	doc := htmlDoc(t, body["html"].(string))
	assert.Equal(t, "id", doc.Find("html").AttrOr("lang", ""))
	assert.Equal(t, "Aktifkan akun", strings.TrimSpace(doc.Find("[data-email-button] a").Text()))
	assert.Contains(t, body["text"], "Tautan ini kedaluwarsa dalam 5 menit.")
}
