package renderintegration

import (
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordInputRe matches the password box, whatever order its attributes come in.
var passwordInputRe = regexp.MustCompile(`<input id="password"[^>]*>`)

// clearCheckboxRe matches the removal checkbox.
var clearCheckboxRe = regexp.MustCompile(`<input id="clearSmtpPassword"[^>]*>`)

// The email settings page says what will happen to the password before a save: a badge saying
// whether one is saved, the placeholder saying an empty box keeps it, and the removal checkbox,
// offered only when there is something to remove. The saved host goes into the page for the
// host-change warning to compare against (#410 decision 3). Rendered in pt-BR, like every page in
// this package, so a string missing from that catalog shows as a raw key.
func TestRender_AdminSettingsEmailWithASavedPassword(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailGet{
			SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPEncryption: "starttls",
			HasSMTPPassword: true, SavedSMTPHost: "smtp.example.com",
		},
	})

	assert.Contains(t, out, ">Salva</span>", "the Saved badge")
	assert.NotContains(t, out, ">Não definida</span>")
	assert.Contains(t, out, "A senha salva nunca é exibida.", "the tooltip")

	box := passwordInputRe.FindString(out)
	require.NotEmpty(t, box, "the password box is rendered")
	assert.Contains(t, box, `placeholder="Deixe vazio para manter a senha salva"`)
	assert.Contains(t, box, `value=""`, "the box is empty on load")

	checkbox := clearCheckboxRe.FindString(out)
	require.NotEmpty(t, checkbox, "the removal is offered")
	assert.Contains(t, checkbox, `name="clearSmtpPassword"`)
	assert.NotContains(t, checkbox, "checked")
	assert.Contains(t, out, "Remover senha salva")

	assert.Contains(t, out, `name="hasSmtpPassword" value="true"`)
	assert.Contains(t, out, `name="savedHostOrIP" value="smtp.example.com"`)
	assert.Contains(t, out, "O host SMTP foi alterado", "the host-change warning is rendered, hidden until the host changes")
}

func TestRender_AdminSettingsEmailWithNoSavedPassword(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailGet{
			SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPEncryption: "starttls",
			SavedSMTPHost: "smtp.example.com",
		},
	})

	assert.Contains(t, out, ">Não definida</span>", "the Not set badge")
	assert.NotContains(t, out, ">Salva</span>")

	box := passwordInputRe.FindString(out)
	require.NotEmpty(t, box, "the password box is rendered")
	assert.NotContains(t, box, "placeholder=", "there is no saved password to keep")
	assert.Empty(t, clearCheckboxRe.FindString(out), "there is nothing to remove")
	assert.Contains(t, out, `name="hasSmtpPassword" value=""`)
}

// After a refused save the page comes back as it was submitted: the typed password in its box, the
// removal ticked if it was, the badge and the saved host as they were (#410 decision 3).
func TestRender_AdminSettingsEmailRedrawnAfterARefusedSave(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailPost{
			SMTPEnabled: true, SMTPHost: "smtp.other.example", SMTPPort: "587", SMTPEncryption: "starttls",
			SMTPPassword: "typed-secret", HasSMTPPassword: true, SavedSMTPHost: "smtp.example.com",
			ClearSMTPPassword: true,
		},
		"error": "Enter the SMTP password again.",
	})

	assert.Contains(t, out, "Enter the SMTP password again.")
	assert.Contains(t, out, ">Salva</span>")
	assert.Contains(t, passwordInputRe.FindString(out), `value="typed-secret"`)
	assert.Contains(t, clearCheckboxRe.FindString(out), "checked")
	assert.Contains(t, out, `name="hostOrIP" value="smtp.other.example"`)
	assert.Contains(t, out, `name="savedHostOrIP" value="smtp.example.com"`)
}

// The page's script shows and hides markup the template rendered, and never writes markup itself
// (#105, #120).
func TestRender_AdminSettingsEmailScriptWritesNoMarkup(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailGet{HasSMTPPassword: true, SavedSMTPHost: "smtp.example.com"},
	})

	assert.NotContains(t, out, "innerHTML")
	assert.NotContains(t, out, "insertAdjacentHTML")
}
