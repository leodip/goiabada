package renderintegration

import (
	"html"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keepSignedInRadioRe matches the opening tag of each Keep users signed in radio button, whatever
// order its attributes come in.
var keepSignedInRadioRe = regexp.MustCompile(`<input[^>]* name="keepSignedIn"[^>]*>`)

// keepSignedInValueRe reads a radio button's value.
var keepSignedInValueRe = regexp.MustCompile(` value="([^"]*)"`)

// The Sessions page offers "Keep users signed in after the browser closes" as three radio buttons,
// Always, Let each user choose and Never, each with a hint saying what it does, and the stored mode
// is the one chosen (#743 decision 4).
func TestRender_AdminSettingsSessionsOffersTheThreeKeepSignedInModes(t *testing.T) {
	for _, stored := range []string{"always", "ask", "never"} {
		t.Run(stored, func(t *testing.T) {
			out := renderMenuPageIn(t, "/admin_settings_sessions.html", map[string]interface{}{
				"settings": adminsettingshandlers.SettingsSessionGet{
					UserSessionIdleTimeoutInSeconds: 7200, UserSessionMaxLifetimeInSeconds: 86400,
					MaxUserSessionsPerUser: 20, KeepSignedIn: stored,
				},
			}, "en", true)
			text := html.UnescapeString(out)

			radios := keepSignedInRadioRe.FindAllString(out, -1)
			require.Len(t, radios, 3, "three radio buttons")
			var values, checked []string
			for _, radio := range radios {
				assert.Contains(t, radio, `type="radio"`)
				value := keepSignedInValueRe.FindStringSubmatch(radio)
				require.NotNil(t, value, "each radio button has a value: %s", radio)
				values = append(values, value[1])
				if regexp.MustCompile(` checked[ >]`).MatchString(radio) {
					checked = append(checked, value[1])
				}
				assert.NotContains(t, radio, "aria-invalid", "nothing was refused")
			}
			assert.Equal(t, []string{"always", "ask", "never"}, values)
			assert.Equal(t, []string{stored}, checked, "the stored mode, and only it, is chosen")

			assert.Contains(t, text, "Keep users signed in after the browser closes")
			for _, label := range []string{
				"Always",
				"Every user stays signed in after closing the browser, until the session ends.",
				"Let each user choose",
				"The password page asks each user, with an unticked box, whether to stay signed in after closing the browser.",
				"Never",
				"Every user signs in again after closing the browser.",
			} {
				assert.Contains(t, text, label)
			}
		})
	}
}

// A refusal about the mode marks the radio buttons invalid, describes their group by the notice and
// focuses the first, and keeps the other fields as they were entered.
func TestRender_AdminSettingsSessionsMarksARefusedKeepSignedIn(t *testing.T) {
	out := renderMenuPage(t, "/admin_settings_sessions.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsSessionPost{
			UserSessionIdleTimeoutInSeconds: "3600", UserSessionMaxLifetimeInSeconds: "43200",
			MaxUserSessionsPerUser: "20", KeepSignedIn: "",
		},
		"error":      "Escolha se os usuários continuam conectados depois de fechar o navegador.",
		"errorField": "keepSignedIn",
	})

	radios := keepSignedInRadioRe.FindAllString(out, -1)
	require.Len(t, radios, 3)
	for i, radio := range radios {
		assert.Contains(t, radio, `aria-invalid="true"`)
		assert.NotRegexp(t, ` checked[ >]`, radio, "no mode was chosen")
		if i == 0 {
			assert.Contains(t, radio, "autofocus")
		} else {
			assert.NotContains(t, radio, "autofocus")
		}
	}
	assert.Regexp(t, `<fieldset[^>]* aria-describedby="sessions-error keepSignedInHint"`, out)
	assert.Contains(t, out, `name="maxUserSessionsPerUser" value="20"`)
	assert.Contains(t, html.UnescapeString(out), "Deixar cada usuário escolher", "the radio buttons are in the page's language")
}
