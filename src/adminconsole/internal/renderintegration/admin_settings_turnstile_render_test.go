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

// The Turnstile page's controls, whatever order their attributes come in.
var (
	turnstileSwitchRe   = regexp.MustCompile(`<input[^>]* id="turnstileEnabled"[^>]*>`)
	turnstileSiteKeyRe  = regexp.MustCompile(`<input[^>]* id="turnstileSiteKey"[^>]*>`)
	turnstileSecretRe   = regexp.MustCompile(`<input[^>]* id="turnstileSecretKey"[^>]*>`)
	turnstileClearBoxRe = regexp.MustCompile(`<input[^>]* id="clearTurnstileSecretKey"[^>]*>`)
)

// checkedRe matches a checkbox's checked attribute, and not data-confirm-when="checked".
var checkedRe = regexp.MustCompile(`\schecked[\s>]`)

// The Turnstile page says what a save will do to the secret key, as the email page does for the
// SMTP password: a badge saying whether one is saved, the placeholder saying an empty box keeps it,
// and the removal checkbox, offered only when there is something to remove (#642 decision 11).
// Rendered in pt-BR, like every page in this package, so a string missing from that catalog shows as
// a raw key.
func TestRender_AdminSettingsTurnstileWithASavedSecretKey(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsTurnstile{
			TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
			HasTurnstileSecretKey: true, SavedTurnstileEnabled: true,
		},
	})

	assert.Contains(t, out, "<title>Configurações do Turnstile – Test</title>")
	assert.Contains(t, out, `<span class="tag tag-positive -my-0.5">Salva</span>`, "the Saved tag")
	assert.NotContains(t, out, ">Não definida</span>")
	assert.Contains(t, out, "A chave secreta salva nunca é exibida.", "the hint")

	assert.Regexp(t, checkedRe, turnstileSwitchRe.FindString(out))
	assert.Contains(t, turnstileSiteKeyRe.FindString(out), `value="1x00000000000000000000AA"`)

	box := turnstileSecretRe.FindString(out)
	require.NotEmpty(t, box, "the secret key box is rendered")
	assert.Contains(t, box, `type="password"`)
	assert.Contains(t, box, `name="turnstileSecretKey"`)
	assert.Contains(t, box, `placeholder="Deixe vazio para manter a chave secreta salva"`)
	assert.Contains(t, box, `value=""`, "the box is empty on load")

	checkbox := turnstileClearBoxRe.FindString(out)
	require.NotEmpty(t, checkbox, "the removal is offered")
	assert.Contains(t, checkbox, `name="clearTurnstileSecretKey"`)
	assert.NotRegexp(t, checkedRe, checkbox)
	assert.Contains(t, out, "Remover chave secreta salva")
	assert.Regexp(t, `<div class="notice notice-caution" id="clearTurnstileSecretKeyNotice" hidden>`, out)

	assert.Contains(t, out, `name="hasTurnstileSecretKey" value="true"`)
	assert.Contains(t, out, `name="savedTurnstileEnabled" value="true"`)
	assert.NotRegexp(t, rawKeyRe, out)
}

func TestRender_AdminSettingsTurnstileWithNoSavedSecretKey(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsTurnstile{},
	})

	assert.Contains(t, out, `<span class="tag -my-0.5">Não definida</span>`, "the Not set tag")
	assert.NotContains(t, out, ">Salva</span>")
	assert.NotRegexp(t, checkedRe, turnstileSwitchRe.FindString(out))

	box := turnstileSecretRe.FindString(out)
	require.NotEmpty(t, box, "the secret key box is rendered")
	assert.NotContains(t, box, "placeholder=", "there is no saved secret key to keep")
	assert.NotContains(t, out, "A chave secreta salva nunca é exibida.")
	assert.Empty(t, turnstileClearBoxRe.FindString(out), "there is nothing to remove")
	assert.Contains(t, out, `name="hasTurnstileSecretKey" value=""`)
	assert.NotRegexp(t, rawKeyRe, out)
}

// Turning the challenge on asks first, naming the way back from a challenge nobody can pass, since a
// wrong site key cannot be checked on save. It asks only when the challenge was off as stored, so a
// save that keeps it on is not asked about, and a refused turn-on, redrawn with the switch ticked
// while the challenge is still off, asks again.
func TestRender_AdminSettingsTurnstileAsksBeforeTurningTheChallengeOn(t *testing.T) {
	testCases := []struct {
		name       string
		settings   adminsettingshandlers.SettingsTurnstile
		wantStored string
	}{
		{"off as stored", adminsettingshandlers.SettingsTurnstile{}, "false"},
		{"on as stored", adminsettingshandlers.SettingsTurnstile{TurnstileEnabled: true, SavedTurnstileEnabled: true}, "true"},
		{"a refused turn-on redrawn", adminsettingshandlers.SettingsTurnstile{TurnstileEnabled: true}, "false"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{"settings": tc.settings})

			box := turnstileSwitchRe.FindString(out)
			require.NotEmpty(t, box)
			assert.Contains(t, box, `data-confirm-when="checked"`)
			assert.Contains(t, box, `data-stored-checked="`+tc.wantStored+`"`)
			assert.Contains(t, box, "goiabada-authserver recover --disable-turnstile")
			assert.Contains(t, out, `data-confirm-dialog="confirmSave"`)
			assert.Contains(t, out, `name="savedTurnstileEnabled" value="`+map[string]string{"true": "true", "false": ""}[tc.wantStored]+`"`)
		})
	}
}

// After a refused save the page comes back as it was submitted: the typed secret key in its box, the
// removal ticked if it was, the badge and the stored switch as they were, and the field the refusal
// is about marked, described by the notice and focused (#642 decision 11).
func TestRender_AdminSettingsTurnstileRedrawnAfterARefusedSave(t *testing.T) {
	testCases := []struct {
		name     string
		settings adminsettingshandlers.SettingsTurnstile
		field    string
		marked   *regexp.Regexp
	}{
		{
			name: "the secret key's refusal",
			settings: adminsettingshandlers.SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "2x00000000000000000000AB",
				TurnstileSecretKey: "typed-secret", HasTurnstileSecretKey: true, SavedTurnstileEnabled: true},
			field:  "turnstileSecretKey",
			marked: turnstileSecretRe,
		},
		{
			name:     "the site key's refusal",
			settings: adminsettingshandlers.SettingsTurnstile{TurnstileEnabled: true, TurnstileSecretKey: "typed-secret"},
			field:    "turnstileSiteKey",
			marked:   turnstileSiteKeyRe,
		},
		{
			name: "the removal's refusal",
			settings: adminsettingshandlers.SettingsTurnstile{TurnstileEnabled: true, TurnstileSiteKey: "1x00000000000000000000AA",
				HasTurnstileSecretKey: true, ClearTurnstileSecretKey: true, SavedTurnstileEnabled: true},
			field:  "clearTurnstileSecretKey",
			marked: turnstileClearBoxRe,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{
				"settings":   tc.settings,
				"error":      "The refusal & its <reason>.",
				"errorField": tc.field,
			})

			assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="turnstile-error">`)
			assert.Contains(t, out, "The refusal &amp; its &lt;reason&gt;.", "the API's sentence, escaped")
			assert.Contains(t, turnstileSecretRe.FindString(out), `value="`+tc.settings.TurnstileSecretKey+`"`)
			marked := tc.marked.FindString(out)
			require.NotEmpty(t, marked)
			assert.Contains(t, marked, `aria-invalid="true"`)
			assert.Contains(t, marked, "turnstile-error")
			assert.Contains(t, marked, "autofocus")
			assert.Equal(t, 1, strings.Count(out, `aria-invalid="true"`), "one field is marked")
			if tc.settings.ClearTurnstileSecretKey {
				assert.Regexp(t, checkedRe, turnstileClearBoxRe.FindString(out))
				assert.Regexp(t, `<div class="notice notice-caution" id="clearTurnstileSecretKeyNotice">`, out)
			}
		})
	}
}

// A save is said on the page it saved.
func TestRender_AdminSettingsTurnstileSaysASave(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{
		"settings":          adminsettingshandlers.SettingsTurnstile{},
		"savedSuccessfully": true,
	})
	assert.Contains(t, out, `<div class="notice notice-positive" role="status">`)
}

// The page's script shows and hides markup the template rendered, and never writes markup itself
// (#105, #120).
func TestRender_AdminSettingsTurnstileScriptWritesNoMarkup(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_turnstile.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsTurnstile{HasTurnstileSecretKey: true},
	})
	assert.Contains(t, out, `src="/static/pages/admin-settings-turnstile.js`)

	b, err := fs.ReadFile(web.StaticFS(), "pages/admin-settings-turnstile.js")
	require.NoError(t, err)
	assert.NotContains(t, string(b), "innerHTML")
	assert.NotContains(t, string(b), "insertAdjacentHTML")
	assert.NotContains(t, string(b), "outerHTML")
}

// The settings menu lists the Turnstile page beside Email, marked as the page the user is on there.
func TestRender_AdminMenuListsTurnstileBesideEmail(t *testing.T) {
	out := renderMenuPageAt(t, "/admin/settings/turnstile", "/admin_settings_turnstile.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsTurnstile{},
	})

	email := strings.Index(out, `href="/admin/settings/email"`)
	turnstile := strings.Index(out, `href="/admin/settings/turnstile" aria-current="page"`)
	auditLogs := strings.Index(out, `href="/admin/settings/audit-logs"`)
	require.NotEqual(t, -1, turnstile, "the Turnstile link is marked current")
	assert.Less(t, email, turnstile, "after Email")
	assert.Less(t, turnstile, auditLogs, "before Audit logging")
	assert.Equal(t, 1, strings.Count(out, `aria-current="page"`), "only the Turnstile link is current")
}
