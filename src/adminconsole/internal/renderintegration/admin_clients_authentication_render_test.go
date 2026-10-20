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
	client := adminclienthandlers.ClientAuthentication{ClientId: 7, ClientIdentifier: "portal"}

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
