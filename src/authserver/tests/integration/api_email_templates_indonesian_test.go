package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin API takes id wherever it takes a built-in language tag (#668 decision 1): the password
// reset link's Indonesian text is listed and read, an Indonesian edit is saved, read back, previewed
// and sent to a recipient reading id-ID, and a reset gives the built-in Indonesian text back.
func TestAPIEmailTemplates_AnIndonesianEditIsSavedReadPreviewedAndReset(t *testing.T) {
	useMailpitSMTP(t)
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "password_reset_link", "id")
	appName := appNameOfSettings(t)

	assert.Equal(t, "default", listedStatus(t, manageToken, "password_reset_link", "id"))
	id := emailTemplateLanguage(t, manageToken, "password_reset_link", "id")
	assert.Equal(t, "Atur ulang kata sandi", id["builtInText"].(map[string]any)["subject"])
	assert.Equal(t, "Atur ulang kata sandi", id["builtInText"].(map[string]any)["buttonLabel"])

	status, body, _ := emailTemplateCall(t, manageToken, http.MethodPut, emailTemplatesPath+"/password_reset_link/id", map[string]any{
		"subject":     "Pilih kata sandi baru untuk {{app_name}}",
		"buttonLabel": "Atur ulang kata sandi",
		"body":        "Hai {{name}}, buka {{link}} dalam {{expiry}}.\n\n{{button}}",
	})
	require.Equal(t, http.StatusOK, status, "save: %v", body)
	assert.Equal(t, "id", body["language"])
	assert.Equal(t, []any{"subject", "body"}, body["editedFields"])

	id = emailTemplateLanguage(t, manageToken, "password_reset_link", "id")
	assert.Equal(t, "edited", id["status"])
	assert.Equal(t, "Pilih kata sandi baru untuk {{app_name}}", id["editorText"].(map[string]any)["subject"])
	assert.Equal(t, "edited", listedStatus(t, manageToken, "password_reset_link", "id"))
	assert.Equal(t, "default", listedStatus(t, manageToken, "password_reset_link", "en"))

	status, body, _ = emailTemplateCall(t, manageToken, http.MethodPost, emailTemplatesPath+"/password_reset_link/id/preview",
		id["editorText"])
	require.Equal(t, http.StatusOK, status, "preview: %v", body)
	assert.Equal(t, "Pilih kata sandi baru untuk "+appName, body["subject"])
	assert.Equal(t, "Hai "+previewSampleName+", buka "+previewSampleLink+" dalam 5 menit.",
		strings.TrimSpace(strings.SplitN(body["text"].(string), "\n", 2)[0]))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body["html"].(string)))
	require.NoError(t, err)
	assert.Equal(t, "id", doc.Find("html").AttrOr("lang", ""))

	subject, button, text := resetLinkEmailSent(t, resetLinkUser(t, "Budi", "id-ID"))
	assert.Equal(t, "Pilih kata sandi baru untuk "+appName, subject)
	assert.Equal(t, "Atur ulang kata sandi", button)
	assert.True(t, strings.HasPrefix(text, "Hai Budi, buka <link> dalam 5 menit.\n"), text)

	resp, _ := sendAdmin(t, manageToken, http.MethodDelete, emailTemplatesPath+"/password_reset_link/id", nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	edit, err := database.GetEmailTemplate(context.Background(), nil, "password_reset_link", "id")
	require.NoError(t, err)
	assert.Nil(t, edit, "the reset removes the Indonesian edit")

	assert.Equal(t, "default", emailTemplateLanguage(t, manageToken, "password_reset_link", "id")["status"])
	subject, button, text = resetLinkEmailSent(t, resetLinkUser(t, "Budi", "id-ID"))
	assert.Equal(t, "Atur ulang kata sandi", subject)
	assert.Equal(t, "Atur ulang kata sandi", button)
	assert.True(t, strings.HasPrefix(text, "Halo Budi,\n\nAnda dapat mengatur ulang kata sandi Anda melalui tautan di bawah ini:\n"), text)
}
