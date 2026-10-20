package renderintegration

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordInputRe matches the password box, whatever order its attributes come in.
var passwordInputRe = regexp.MustCompile(`<input[^>]* id="password"[^>]*>`)

// clearCheckboxRe matches the removal checkbox.
var clearCheckboxRe = regexp.MustCompile(`<input[^>]* id="clearSmtpPassword"[^>]*>`)

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

	assert.Contains(t, out, `<span class="tag tag-positive -my-0.5">Salva</span>`, "the Saved tag")
	assert.NotContains(t, out, ">Não definida</span>")
	assert.Contains(t, out, "A senha salva nunca é exibida.", "the hint")

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
	assert.Contains(t, out, "Você alterou o host", "the host-change caution is rendered, hidden until the host changes")
	assert.Regexp(t, `<div class="notice notice-caution" id="hostChangeWarning" hidden>`, out)
}

func TestRender_AdminSettingsEmailWithNoSavedPassword(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailGet{
			SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPPort: 587, SMTPEncryption: "starttls",
			SavedSMTPHost: "smtp.example.com",
		},
	})

	assert.Contains(t, out, `<span class="tag -my-0.5">Não definida</span>`, "the Not set tag")
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
	assert.Contains(t, out, `src="/static/pages/admin-settings-email.js`)

	b, err := fs.ReadFile(web.StaticFS(), "pages/admin-settings-email.js")
	require.NoError(t, err)
	assert.NotContains(t, string(b), "innerHTML")
	assert.NotContains(t, string(b), "insertAdjacentHTML")
	assert.NotContains(t, string(b), "outerHTML")
}

// With email off, the server's three sections start hidden, and turning email off asks first
// against email as stored, which the saved host says: on here, so unticking asks.
func TestRender_AdminSettingsEmailHidesTheServerWhileOffAndAsksBeforeTurningItOff(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
			"settings": adminsettingshandlers.SettingsEmailGet{SMTPEnabled: enabled, SMTPHost: "smtp.example.com",
				SavedSMTPHost: "smtp.example.com", SMTPEncryption: "starttls"},
		})

		sections := regexp.MustCompile(`<div class="panel-body stacked" data-smtp-section( hidden)?>`).FindAllStringSubmatch(out, -1)
		require.Len(t, sections, 3, "enabled: %v", enabled)
		for _, section := range sections {
			assert.Equal(t, !enabled, section[1] != "", "enabled: %v", enabled)
		}
		box := regexp.MustCompile(`<input type="checkbox" id="smtpEnabled"[^>]*>`).FindString(out)
		require.NotEmpty(t, box)
		assert.Contains(t, box, `data-confirm-when="unchecked" data-stored-checked="true"`)
	}
	assert.Contains(t, renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailGet{SMTPEncryption: "none"},
	}), `data-stored-checked="false"`, "with nothing saved, unticking has nothing to clear")
}

// A refusal marks the field its code names, names the notice in the field's description and gives
// it the focus.
func TestRender_AdminSettingsEmailMarksTheRefusedField(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsEmailPost{SMTPEnabled: true, SMTPHost: "smtp.example.com", SMTPPort: "99999",
			SMTPEncryption: "starttls", SavedSMTPHost: "smtp.example.com"},
		"error":      "SMTP port must be between 1 and 65535.",
		"errorField": "port",
	})

	port := regexp.MustCompile(`<input[^>]* id="port"[^>]*>`).FindString(out)
	require.NotEmpty(t, port)
	assert.Contains(t, port, `aria-describedby="email-error" aria-invalid="true" autofocus`)
	assert.Equal(t, 1, strings.Count(out, `aria-invalid="true"`), "one field is marked")
}

// A sent test email is said with the address it went to, which came from the form, so it is
// escaped like any other value.
func TestRender_AdminSettingsEmailSendTestNamesTheAddress(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_email_sendtest.html", map[string]interface{}{
		"smtpEnabled": true,
		"sentTo":      `ana+"><b>x</b>@example.com`,
	})

	assert.Contains(t, out, `E-mail de teste enviado para ana&#43;&#34;&gt;&lt;b&gt;x&lt;/b&gt;@example.com.`)
	assert.NotContains(t, out, "<b>x</b>")
}
