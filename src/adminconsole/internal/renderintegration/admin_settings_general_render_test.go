package renderintegration

import (
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registrationEmailWarningRe matches the opening tag of the warning under the verification switch.
var registrationEmailWarningRe = regexp.MustCompile(`<div id="selfRegistrationEmailWarning"[^>]*>`)

// hiddenClassRe matches a class attribute naming hidden as one of its classes.
var hiddenClassRe = regexp.MustCompile(`class="(?:[^"]*\s)?hidden(?:\s[^"]*)?"`)

const registrationEmailWarningEn = "Email isn't set up, so registration is unavailable. " +
	"Set it up under Email - SMTP, or turn off email verification."

// The General page warns, under the verification switch, that registration is unavailable while both
// registration switches are on and email is off, which is when the auth server refuses it (#526
// decision 4). The page script toggles it as the switches change; what the HTML decides is that it is
// there and whether it starts shown, for each pair of switches and email state.
func TestRender_AdminSettingsGeneralWarnsWhenRegistrationNeedsEmail(t *testing.T) {
	cases := []struct {
		name                 string
		selfRegistration     bool
		requiresVerification bool
		smtpEnabled          bool
		shown                bool
	}{
		{"both switches on, email off", true, true, false, true},
		{"both switches on, email on", true, true, true, false},
		{"verification off, email off", true, false, false, false},
		{"self-registration off, email off", false, true, false, false},
		{"both switches off, email off", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
				"settings": adminsettingshandlers.SettingsGeneral{
					AppName: "Goiabada", PasswordPolicy: "low",
					SelfRegistrationEnabled:                   tc.selfRegistration,
					SelfRegistrationRequiresEmailVerification: tc.requiresVerification,
					PKCERequired:                              true,
				},
			}, "en", tc.smtpEnabled)

			warning := registrationEmailWarningRe.FindString(out)
			require.NotEmpty(t, warning, "the warning is rendered whatever the switches, for the script to toggle")
			assert.Contains(t, html.UnescapeString(out), registrationEmailWarningEn)
			if tc.shown {
				assert.NotRegexp(t, hiddenClassRe, warning, "the warning starts shown")
			} else {
				assert.Regexp(t, hiddenClassRe, warning, "the warning starts hidden")
			}

			// The script reads email's state from the same value the template did, and follows both
			// switches.
			if tc.smtpEnabled {
				assert.Regexp(t, `const smtpEnabled =\s*true\s*;`, out)
			} else {
				assert.Regexp(t, `const smtpEnabled =\s*false\s*;`, out)
			}
			assert.Contains(t, out, "selfRegistrationRequiresEmailVerification.addEventListener('change'")
		})
	}
}

// The warning comes after the verification switch and before the next one, so it reads as that
// switch's.
func TestRender_AdminSettingsGeneralPutsTheWarningUnderTheVerificationSwitch(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true, PasswordPolicy: "low"},
	}, "en", false)

	verification := strings.Index(out, `<input id="selfRegistrationRequiresEmailVerification"`)
	warning := strings.Index(out, `<div id="selfRegistrationEmailWarning"`)
	next := strings.Index(out, `<input id="dynamicClientRegistrationEnabled"`)
	require.NotEqual(t, -1, verification)
	require.NotEqual(t, -1, warning)
	require.NotEqual(t, -1, next)
	assert.Less(t, verification, warning)
	assert.Less(t, warning, next)
}

// The verification switch's tooltip no longer promises a confirmation link either way: it says the
// switch needs email set up and that registration is unavailable without it (#526 decision 4).
func TestRender_AdminSettingsGeneralVerificationTooltipSaysItNeedsEmail(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{PasswordPolicy: "low"},
	}, "en", true)

	assert.Contains(t, html.UnescapeString(out), "This needs email set up under Email - SMTP: while it isn't, registration is unavailable.")
	assert.NotContains(t, html.UnescapeString(out), "If enabled, self-registered users will need to activate their accounts via a confirmation link sent to their email.")
}

// The same page in Brazilian Portuguese, the locale every other page in this package renders in: the
// warning and the tooltip come from that catalog, and no raw key leaks.
func TestRender_AdminSettingsGeneralRegistrationEmailStringsInPtBR(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true, PasswordPolicy: "low"},
	}, "pt-BR", false)

	assert.Contains(t, html.UnescapeString(out), "O e-mail não está configurado, então o cadastro está indisponível.")
	assert.Contains(t, html.UnescapeString(out), "Isso exige o e-mail configurado em E-mail - SMTP")
}
