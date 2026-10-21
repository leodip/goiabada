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

// registrationEmailWarningRe matches the opening tag of the caution under the registration choices.
var registrationEmailWarningRe = regexp.MustCompile(`<div class="notice notice-caution" id="selfRegistrationEmailWarning"[^>]*>`)

// emailVerificationRowRe matches the opening tag of the email verification row.
var emailVerificationRowRe = regexp.MustCompile(`<label class="check-row" for="selfRegistrationRequiresEmailVerification" id="emailVerificationRow"[^>]*>`)

const registrationEmailWarningEn = "Email isn't set up, so nobody can register: set it up, or stop requiring email verification."

// The General page warns, under the registration choices, that nobody can register while both
// registration switches are on and email is off, which is when the auth server refuses it (#526
// decision 4). The page script shows it again as the switches change; what the HTML decides is that
// it is there and whether it starts shown, for each pair of switches and email state, and that the
// script reads email's state from the same value the template did.
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
			require.NotEmpty(t, warning, "the caution is rendered whatever the switches, for the script to show")
			assert.Contains(t, html.UnescapeString(out), registrationEmailWarningEn)
			if tc.shown {
				assert.NotContains(t, warning, " hidden", "the caution starts shown")
			} else {
				assert.Contains(t, warning, " hidden", "the caution starts hidden")
			}

			if tc.smtpEnabled {
				assert.Contains(t, out, `data-smtp-enabled="true"`)
			} else {
				assert.Contains(t, out, `data-smtp-enabled="false"`)
			}
			assert.Contains(t, out, `src="/static/pages/admin-settings-general.js`)
		})
	}
}

// The caution is about email verification: it closes the list of the user registration choices,
// before Dynamic client registration's own list and the OAuth flows, and links to the email settings
// it asks for.
func TestRender_AdminSettingsGeneralPutsTheWarningUnderEmailVerification(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true, PasswordPolicy: "low"},
	}, "en", false)

	verification := strings.Index(out, `<input type="checkbox" id="selfRegistrationRequiresEmailVerification"`)
	registration := strings.Index(out, `<input type="checkbox" id="dynamicClientRegistrationEnabled"`)
	warning := strings.Index(out, `id="selfRegistrationEmailWarning"`)
	flows := strings.Index(out, `<input type="checkbox" id="pkceRequired"`)
	require.NotEqual(t, -1, verification)
	require.NotEqual(t, -1, registration)
	require.NotEqual(t, -1, warning)
	require.NotEqual(t, -1, flows)
	assert.Less(t, verification, warning)
	assert.Less(t, warning, registration)
	assert.Less(t, registration, flows)
	assert.Contains(t, out[verification:warning], `</div>`, "the warning follows the registration choices' list")
	assert.Contains(t, out[warning:registration], `<div class="check-list">`, "Dynamic client registration is a list of its own")
	assert.Contains(t, out[warning:registration], `<a class="text-link" href="/admin/settings/email">Email settings</a>`)
}

// Email verification governs nothing while registration is off, so its row starts hidden then, and
// is hidden rather than disabled, so the choice made before is still sent and kept.
func TestRender_AdminSettingsGeneralShowsVerificationOnlyWithRegistration(t *testing.T) {
	for _, registration := range []bool{true, false} {
		out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
			"settings": adminsettingshandlers.SettingsGeneral{SelfRegistrationEnabled: registration,
				SelfRegistrationRequiresEmailVerification: true, PasswordPolicy: "low"},
		}, "en", true)

		row := emailVerificationRowRe.FindString(out)
		require.NotEmpty(t, row)
		assert.Equal(t, !registration, strings.Contains(row, " hidden"), "registration on: %v", registration)
		box := regexp.MustCompile(`<input type="checkbox" id="selfRegistrationRequiresEmailVerification"[^>]*>`).FindString(out)
		require.NotEmpty(t, box)
		assert.NotContains(t, box, "disabled")
		assert.Contains(t, box, " checked")
	}
}

// The verification hint says the choice needs email set up (#526 decision 4).
func TestRender_AdminSettingsGeneralVerificationHintSaysItNeedsEmail(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{PasswordPolicy: "low"},
	}, "en", true)

	assert.Contains(t, html.UnescapeString(out), "A new account is activated through a link sent to its email address. This needs email set up.")
}

// The password policy is four option cards, each saying what its policy asks, the stored one chosen.
func TestRender_AdminSettingsGeneralOffersEachPasswordPolicy(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{PasswordPolicy: "medium"},
	}, "en", true)

	checked := regexp.MustCompile(`<input type="radio" name="passwordPolicy" value="([a-z]+)" checked`).FindAllStringSubmatch(out, -1)
	require.Len(t, checked, 1, "one policy is chosen")
	assert.Equal(t, "medium", checked[0][1])
	for _, policy := range []string{"none", "low", "medium", "high"} {
		assert.Contains(t, out, `<input type="radio" name="passwordPolicy" value="`+policy+`"`)
	}
	assert.Contains(t, out, "At least 10 characters, with a lowercase letter, an uppercase letter, a number and a symbol.")
}

// A change of issuer asks first, against the issuer the auth server holds: after a refused save the
// field shows what was sent and the comparison is still with the stored one, so saving the same
// issuer again asks again (#562 decision 6).
func TestRender_AdminSettingsGeneralAsksBeforeChangingTheIssuer(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings":       adminsettingshandlers.SettingsGeneral{Issuer: "https://new.example", PasswordPolicy: "low"},
		"storedSettings": adminsettingshandlers.SettingsGeneral{Issuer: "https://auth.example", PasswordPolicy: "low"},
		"error":          "App name is too long.",
		"errorField":     "appName",
	}, "en", true)

	issuer := regexp.MustCompile(`<input class="control" id="issuer"[^>]*>`).FindString(out)
	require.NotEmpty(t, issuer)
	assert.Contains(t, issuer, `value="https://new.example"`)
	assert.Contains(t, issuer, `data-stored-value="https://auth.example"`)
	assert.Contains(t, html.UnescapeString(issuer), `data-confirm="You're changing the issuer.`)
	assert.Contains(t, out, `data-confirm-dialog="confirmSave"`)
	assert.Contains(t, out, `id="confirmSave_modalDialog"`)
}

// A refusal marks the field it is about, names the notice in the field's description and gives it
// the focus; the other field is left alone.
func TestRender_AdminSettingsGeneralMarksTheRefusedField(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings":       adminsettingshandlers.SettingsGeneral{Issuer: "goiabada", PasswordPolicy: "low"},
		"storedSettings": adminsettingshandlers.SettingsGeneral{Issuer: "https://auth.example", PasswordPolicy: "low"},
		"error":          "Invalid issuer.",
		"errorField":     "issuer",
	}, "en", true)

	issuer := regexp.MustCompile(`<input class="control" id="issuer"[^>]*>`).FindString(out)
	appName := regexp.MustCompile(`<input class="control" id="appName"[^>]*>`).FindString(out)
	require.NotEmpty(t, issuer)
	require.NotEmpty(t, appName)
	assert.Contains(t, issuer, `aria-describedby="general-error issuerHint"`)
	assert.Contains(t, issuer, ` aria-invalid="true" autofocus`)
	assert.NotContains(t, appName, "aria-invalid")
	assert.NotContains(t, appName, "autofocus")
	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="general-error">`)
}

// The same page in Brazilian Portuguese, the locale every other page in this package renders in: the
// caution and the hint come from that catalog, and no raw key leaks.
func TestRender_AdminSettingsGeneralRegistrationEmailStringsInPtBR(t *testing.T) {
	out := renderMenuPageIn(t, "/admin_settings_general.html", map[string]interface{}{
		"settings": adminsettingshandlers.SettingsGeneral{SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true, PasswordPolicy: "low"},
	}, "pt-BR", false)

	assert.Contains(t, html.UnescapeString(out), "O e-mail não está configurado, então ninguém consegue se cadastrar")
	assert.Contains(t, html.UnescapeString(out), "Isso exige o e-mail configurado.")
	assert.NotContains(t, out, "adminconsole.admin_settings.general.")
}
