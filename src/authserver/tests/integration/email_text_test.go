package integration

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every email is sent with a plain-text part the server works out of the HTML (#817 decisions 9
// and 10), read here from the mailbox after a real flow: a password reset in a brand with a logo,
// a footer link and a support contact. The text holds the reset link once, before anything else
// it links, and the footer written out, and nothing of the logo, so a reader of the text, and a
// test that pulls the first link out of an email, find the action link first.

// textLinkPattern is a URL as plain text writes it, up to the space or the angle bracket after it.
var textLinkPattern = regexp.MustCompile(`https?://[^\s<>]+`)

func TestEmails_AreSentWithTheirTextTheActionLinkFirst(t *testing.T) {
	useMailpitSMTP(t)
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)

	upload, _ := uploadBrandAsset(t, accessToken, "logo", createTestPNGImage(240, 80))
	require.Equal(t, http.StatusCreated, upload.StatusCode)
	logo := decodeBrandAsset(t, upload)

	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, brandBody(map[string]any{
		"name": brandName("Text"), "appearance": "light", "theme": "avocado",
		"logo":         map[string]any{"id": logo.Id},
		"footerLinks":  []any{map[string]any{"url": "https://acme.example/privacy", "label": "Privacy"}},
		"supportEmail": "help@acme.example",
	}))
	require.Equal(t, http.StatusCreated, status, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	status, answer, _ = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, "%v", answer)

	user, _ := createResetTestUser(t, plusAddress())
	requestResetAt(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/forgot-password", user.Email)
	message := onlyMailTo(t, user.Email)
	text := strings.ReplaceAll(message.Text, "\r\n", "\n")

	require.Contains(t, message.HTML, `src="`+logo.Url+`"`, "the HTML draws the brand's logo")
	assert.NotContains(t, text, logo.Url, "the text draws nothing of the brand")

	links := textLinkPattern.FindAllString(text, -1)
	require.Len(t, links, 2, "the reset link once, the button not repeated, then the footer link:\n%s", text)
	assert.Regexp(t, `^`+regexp.QuoteMeta(appConfig.AuthServer.BaseURL)+`/reset-password\?`, links[0])
	assert.Equal(t, "https://acme.example/privacy", links[1])
	assert.Contains(t, text, "\n\nPrivacy <https://acme.example/privacy>\n\nNeed help? help@acme.example",
		"the footer is written out under the body")

	assert.Equal(t, []string{links[0]}, emailedResetLinks(t, user.Email),
		"the helper the reset tests read their link with finds the action link")
}
