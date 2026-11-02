package renderintegration

import (
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rememberConsentRe matches the Remember consent checkbox, whatever order its attributes come in.
var rememberConsentRe = regexp.MustCompile(`<input [^>]*id="rememberConsent"[^>]*>`)

// The agreed English wording of the checkbox, its hint and the question ticking it asks (#711
// decision 8), and of the make-public question's last sentence (decision 9).
const (
	rememberConsentLabel = "Remember consent"
	rememberConsentHint  = "Lets a user's earlier approval skip the consent screen. It starts off for a public client: " +
		"with no secret, nothing proves a request comes from this app rather than another app using its client ID, so " +
		"users are asked whenever the screen is owed, even if they approved before. Turn it on only when every redirect " +
		"URI is an https address that only this app receives."
	rememberConsentWarning = "You're letting an earlier approval skip the consent screen for this public client. " +
		"Another app that uses its client ID and receives its redirects would get tokens for any user who approved this " +
		"app before, without asking them."
	makePublicLastSentence = "Its introspection resources will be cleared, Remember consent will be turned off, and " +
		"users will stay signed in to other clients."
)

func renderClientSettingsIn(t *testing.T, locale string, client, stored adminclienthandlers.ClientSettings) string {
	t.Helper()
	return renderMenuPageIn(t, "/admin_clients_settings.html", map[string]interface{}{
		"client": client, "storedClient": stored, "savedSuccessfully": false, "isAdmin": true,
	}, locale, true)
}

// A public client's Settings tab draws Remember consent under Ask users for consent, before the
// administrative scopes and the one Save, with its hint, showing the stored value (#711 decision 8).
func TestRender_AdminClientSettings_APublicClientShowsRememberConsent(t *testing.T) {
	for _, remember := range []bool{true, false} {
		client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "spa", IsPublic: true, RememberConsent: remember}
		out := renderClientSettingsIn(t, "en", client, client)

		box := rememberConsentRe.FindString(out)
		require.NotEmpty(t, box, "the checkbox is drawn for a public client")
		assert.Contains(t, box, `type="checkbox"`)
		assert.Contains(t, box, `name="rememberConsent"`)
		assert.NotContains(t, box, `form=`, "it belongs to the settings form")
		assert.Equal(t, remember, hasAttr(box, "checked"), "checked shows the stored value: %s", box)
		assert.Contains(t, box, `aria-describedby="rememberConsentHint"`)

		label := regexp.MustCompile(`<label class="check-row" for="rememberConsent">\s*<input[^>]*>\s*<span[^>]*>\s*<span class="choice-label">([^<]*)</span>`).FindStringSubmatch(out)
		require.NotNil(t, label, "the checkbox is labelled")
		assert.Equal(t, rememberConsentLabel, html.UnescapeString(label[1]))
		hint := regexp.MustCompile(`<span class="field-hint" id="rememberConsentHint">([^<]*)</span>`).FindStringSubmatch(out)
		require.NotNil(t, hint, "the hint is drawn")
		assert.Equal(t, rememberConsentHint, html.UnescapeString(hint[1]))

		boxAt := strings.Index(out, `id="rememberConsent"`)
		assert.Greater(t, boxAt, strings.Index(out, `id="consentRequired"`), "under Ask users for consent")
		assert.Less(t, boxAt, strings.Index(out, `id="administrativeScopesAllowed"`), "directly, before the administrative scopes")
		formStart := strings.Index(out, `<form id="formClientSettings"`)
		assert.True(t, boxAt > formStart && boxAt < strings.Index(out[formStart:], "</form>")+formStart, "inside the settings form")
	}
}

// A confidential client's tab draws no Remember consent: it is always on for such a client, which
// proves itself with its secret (#711 decisions 4 and 8).
func TestRender_AdminClientSettings_AConfidentialClientShowsNoRememberConsent(t *testing.T) {
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "portal", RememberConsent: true}
	out := renderClientSettingsIn(t, "en", client, client)

	assert.NotContains(t, out, `rememberConsent`)
	assert.NotContains(t, out, rememberConsentLabel)
	assert.NotContains(t, html.UnescapeString(out), rememberConsentWarning)
	assert.Contains(t, out, `id="consentRequired"`, "the tab is otherwise drawn")
}

// Ticking Remember consent asks first, in the save's one dialog, against the stored value: a save
// that turns it on asks, one that keeps it on or turns it off does not. A refused save drawn again
// with the box ticked still compares against the stored off, so the second save asks too (#711
// decision 8).
func TestRender_AdminClientSettings_TickingRememberConsentAsksFirst(t *testing.T) {
	typed := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "spa", IsPublic: true, RememberConsent: true}
	stored := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "spa", IsPublic: true}
	out := renderClientSettingsIn(t, "en", typed, stored)

	box := rememberConsentRe.FindString(out)
	require.NotEmpty(t, box)
	m := regexp.MustCompile(`data-confirm="([^"]*)"`).FindStringSubmatch(box)
	require.NotNil(t, m, "ticking it asks: %s", box)
	assert.Equal(t, rememberConsentWarning, html.UnescapeString(m[1]))
	assert.Contains(t, box, `data-confirm-when="checked" data-stored-checked="false"`,
		"asked when ticked, against the value as stored")
	assert.True(t, hasAttr(box, "checked"), "the checkbox keeps what was submitted")

	on := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "spa", IsPublic: true, RememberConsent: true}
	assert.Contains(t, rememberConsentRe.FindString(renderClientSettingsIn(t, "en", on, on)), `data-stored-checked="true"`,
		"a client already remembering consent is asked nothing for keeping it")
}

// The checkbox, its hint and its question are in every built-in catalog: drawn in pt-BR, none of
// them falls back to the English text.
func TestRender_AdminClientSettings_RememberConsentIsTranslated(t *testing.T) {
	client := adminclienthandlers.ClientSettings{ClientId: 7, ClientIdentifier: "spa", IsPublic: true}
	for _, locale := range []string{"de", "es", "fr", "it", "pt-BR"} {
		out := html.UnescapeString(renderClientSettingsIn(t, locale, client, client))
		require.NotEmpty(t, rememberConsentRe.FindString(out), "%s: the checkbox is drawn", locale)
		assert.NotContains(t, out, ">"+rememberConsentLabel+"<", locale)
		assert.NotContains(t, out, rememberConsentHint, locale)
		assert.NotContains(t, out, rememberConsentWarning, locale)
	}
}

// The question asked before making a client public says the switch turns Remember consent off
// (#711 decision 9).
func TestRender_AdminClientAuthentication_MakingAClientPublicSaysRememberConsentGoesOff(t *testing.T) {
	client := adminclienthandlers.ClientAuthentication{ClientId: 7, ClientIdentifier: "portal"}
	out := renderMenuPageIn(t, "/admin_clients_authentication.html", map[string]interface{}{
		"client": client, "storedClient": client,
	}, "en", true)

	m := regexp.MustCompile(`data-confirm="([^"]*)" data-confirm-when="checked" data-stored-checked="false"`).FindStringSubmatch(out)
	require.NotNil(t, m, "making the client public asks first")
	question := html.UnescapeString(m[1])
	assert.True(t, strings.HasPrefix(question, "You're making the client public."), question)
	assert.True(t, strings.HasSuffix(question, " "+makePublicLastSentence), question)
}
