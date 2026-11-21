package renderintegration

import (
	"regexp"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refused secret, such as the empty one a client made confidential is saved with when no secret
// was generated, marks the secret field, described by the notice, and focuses it, as every other
// refused field is (#617).
func TestRender_AdminClientAuthentication_ARefusedSecretFocusesItsField(t *testing.T) {
	client := adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "portal"}

	out := renderMenuPage(t, "/admin_clients_authentication.html", map[string]interface{}{
		"client":       client,
		"storedClient": client,
		"error":        "The client secret is required.",
		"errorField":   "clientSecret",
	})

	secret := regexp.MustCompile(`<input [^>]*id="clientSecret"[^>]*>`).FindString(out)
	require.NotEmpty(t, secret, "the secret field renders")
	assert.Contains(t, secret, `aria-describedby="authentication-error clientSecretHint"`)
	assert.Contains(t, secret, ` aria-invalid="true"`)
	assert.True(t, hasAttr(secret, "autofocus"), "the refused secret takes the focus: %s", secret)
}

// The sentences the tab says for a client held to one method, written out here rather than read
// from the catalogs (#708 decision 5).
const (
	heldToBasicSentence = "This client registered itself for client_secret_basic, so it must send its secret in the Authorization header. A secret sent in the request body is refused."
	heldToPostSentence  = "This client registered itself for client_secret_post, so it must send its secret in the request body. A secret sent in the Authorization header is refused."
)

// registeredMethodNotice is the tab's line naming the method the client is held to, or empty when
// the tab draws none.
var registeredMethodNotice = regexp.MustCompile(`(?s)<div class="notice notice-note[^"]*" id="registered-method">.*?</div>`)

// A client held to one method is told which it is and that the other is refused, inside the
// confidential client's part of the tab; a client not held to one is drawn with no such line
// (#708 decision 5).
func TestRender_AdminClientAuthentication_NamesTheMethodTheClientIsHeldTo(t *testing.T) {
	for _, row := range []struct {
		held, sentence string
	}{
		{"client_secret_basic", heldToBasicSentence},
		{"client_secret_post", heldToPostSentence},
	} {
		t.Run(row.held, func(t *testing.T) {
			client := adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "dcr_a3f9",
				ClientSecret: "s", TokenEndpointAuthMethod: row.held}

			out := renderMenuPageIn(t, "/admin_clients_authentication.html", map[string]interface{}{
				"client": client, "storedClient": client}, "en", true)

			notice := registeredMethodNotice.FindString(out)
			require.NotEmpty(t, notice, "the tab names the method")
			assert.Contains(t, notice, "<p>"+row.sentence+"</p>")
			panel := regexp.MustCompile(`(?s)<div class="field" id="confidentialClientPanel">.*`).FindString(out)
			assert.Contains(t, panel, notice, "the line is in the confidential client's part, hidden with it")
		})
	}

	for _, row := range []struct {
		name   string
		client adminclienthandlers.ClientAuthentication
	}{
		{"a confidential client held to no method", adminclienthandlers.ClientAuthentication{ClientID: 7,
			ClientIdentifier: "portal", ClientSecret: "s"}},
		{"a public client", adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "spa", IsPublic: true}},
		{"a method the auth server does not hold a client to", adminclienthandlers.ClientAuthentication{ClientID: 7,
			ClientIdentifier: "portal", ClientSecret: "s", TokenEndpointAuthMethod: "private_key_jwt"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			out := renderMenuPageIn(t, "/admin_clients_authentication.html", map[string]interface{}{
				"client": row.client, "storedClient": row.client}, "en", true)

			assert.NotContains(t, out, `id="registered-method"`)
			assert.NotContains(t, out, "registered itself for")
		})
	}
}

// The line is drawn from the client as stored, so a refused save whose inputs show the submission
// still names the method the client is held to.
func TestRender_AdminClientAuthentication_NamesTheStoredMethodOnARefusedSave(t *testing.T) {
	stored := adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "dcr_a3f9",
		ClientSecret: "s", TokenEndpointAuthMethod: "client_secret_basic"}
	submitted := adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "dcr_a3f9", ClientSecret: ""}

	out := renderMenuPageIn(t, "/admin_clients_authentication.html", map[string]interface{}{
		"client": submitted, "storedClient": stored, "error": "The client secret is required.",
		"errorField": "clientSecret"}, "en", true)

	assert.Contains(t, registeredMethodNotice.FindString(out), heldToBasicSentence)
}

// Every built-in language says the line in its own words, naming the method as it is spelled on
// the wire.
func TestRender_AdminClientAuthentication_TheMethodLineIsInEveryLanguage(t *testing.T) {
	english := map[string]string{"client_secret_basic": heldToBasicSentence, "client_secret_post": heldToPostSentence}
	for _, locale := range []string{"en", "de", "es", "fr", "it", "pt-BR"} {
		for _, held := range []string{"client_secret_basic", "client_secret_post"} {
			t.Run(locale+"/"+held, func(t *testing.T) {
				client := adminclienthandlers.ClientAuthentication{ClientID: 7, ClientIdentifier: "dcr_a3f9",
					ClientSecret: "s", TokenEndpointAuthMethod: held}

				out := renderMenuPageIn(t, "/admin_clients_authentication.html", map[string]interface{}{
					"client": client, "storedClient": client}, locale, true)

				notice := registeredMethodNotice.FindString(out)
				require.NotEmpty(t, notice)
				assert.Contains(t, notice, held)
				assert.NotContains(t, notice, "adminconsole.", "a catalog message, not its ID")
				if locale == "en" {
					assert.Contains(t, notice, english[held])
				} else {
					assert.NotContains(t, notice, english[held], "translated, not the English sentence")
				}
			})
		}
	}
}
