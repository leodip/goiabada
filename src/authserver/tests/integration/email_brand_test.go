package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/testutil/mailpit"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
)

// An email is drawn in the brand of the page it was sent from (#817 decisions 1 and 6), read here
// from the mailbox after a real flow, one email of each origin: one sent from a sign-in's own pages
// takes that sign-in's client's brand, one sent through the account API takes the brand of the
// client the caller's access token names, and one an administrator's action sends takes the default
// brand. An email sent from the pages of a sign-in that asked for safe mode is drawn in Blueberry's
// colors in place of its brand's custom palette.
//
// Each test makes a dark Plum brand the default and gives a client a light Avocado brand, so an
// email drawn in the wrong one fails on its color scheme and on every color of its frame.

// emailLook is what an email's frame says about its brand: the one color scheme it declares, the
// area behind the card, the card, and the card's text. The fields are exported because the tests
// read them only through struct equality, which the unused linter does not count as a read.
type emailLook struct {
	ColorScheme, Canvas, Surface, Ink string
}

// The frames of the brands these tests use, as brandthemes' presets hold their colors.
var (
	plumDarkEmail       = emailLook{"dark", "#120f15", "#1a161f", "#e9e5ec"}
	avocadoLightEmail   = emailLook{"light", "#f3f6f4", "#ffffff", "#18211c"}
	blueberryLightEmail = emailLook{"light", "#f4f5f7", "#ffffff", "#1a1f29"}
)

// emailStyle answers the declarations of an element's style attribute, by property.
func emailStyle(selection *goquery.Selection) map[string]string {
	declarations := map[string]string{}
	style, _ := selection.Attr("style")
	for _, declaration := range strings.Split(style, ";") {
		property, value, ok := strings.Cut(declaration, ":")
		if ok {
			declarations[strings.TrimSpace(property)] = strings.TrimSpace(value)
		}
	}
	return declarations
}

// readEmailLook reads an email's frame: the body is the area behind the card, the nested table the
// card, and its first cell the card's content.
func readEmailLook(t *testing.T, message mailpit.Message) emailLook {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	var look emailLook
	look.ColorScheme, _ = doc.Find(`meta[name="color-scheme"]`).Attr("content")
	look.Canvas = emailStyle(doc.Find("body"))["background-color"]
	card := doc.Find("body table table").First()
	look.Surface = emailStyle(card)["background-color"]
	look.Ink = emailStyle(card.Find("td").First())["color"]
	return look
}

// onlyMailTo waits for the message sent to an address and answers it, requiring there is one.
func onlyMailTo(t *testing.T, to string) mailpit.Message {
	t.Helper()
	messages := awaitMailTo(t, to)
	require.Len(t, messages, 1, "one email is sent to %s", to)
	return messages[0]
}

// requestResetAt asks for a password reset for email on the forgot-password page at forgotURL, in
// browser.
func requestResetAt(t *testing.T, browser *http.Client, forgotURL string, email string) {
	t.Helper()
	resp := postRegisterAt(t, browser, forgotURL, url.Values{"email": {email}})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, peekBody(t, resp), "Check your email")
}

func TestEmails_FromASignInsPagesAreDrawnInItsClientsBrand(t *testing.T) {
	useMailpitSMTP(t)
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, _, redirectURI := brandedSignInClient(t, record.AcrLevel1)
	browser := createHttpClient(t)
	forgotURL, _ := forgotPasswordLink(t, browser, brandAuthorizeURL(client, redirectURI, ""))

	t.Run("a password reset asked for from the sign-in's forgot password page", func(t *testing.T) {
		user, _ := createResetTestUser(t, plusAddress())
		requestResetAt(t, browser, forgotURL, user.Email)
		assert.Equal(t, avocadoLightEmail, readEmailLook(t, onlyMailTo(t, user.Email)))
	})

	t.Run("a password reset asked for from a page naming no sign-in", func(t *testing.T) {
		user, _ := createResetTestUser(t, plusAddress())
		requestResetAt(t, browser, appConfig.AuthServer.BaseURL+"/forgot-password", user.Email)
		assert.Equal(t, plumDarkEmail, readEmailLook(t, onlyMailTo(t, user.Email)))
	})
}

// accountAPIUserOfClient is a user holding an account-scoped token, issued to a client of its own,
// and that client.
func accountAPIUserOfClient(t *testing.T) (string, *record.User, *record.Client) {
	t.Helper()
	scope := "openid profile email " + builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier
	data, code, _, _ := userTokenResponseWithScope(t, scope, nil)
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "the token response carries an access token")
	return accessToken, &code.User, &code.Client
}

// sendVerificationCode asks the account API to email the caller's address its verification code.
func sendVerificationCode(t *testing.T, accessToken string) {
	t.Helper()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/account/email/verification/send",
		accessToken, map[string]string{})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEmails_ThroughTheAccountAPIAreDrawnInTheBrandOfTheTokensClient(t *testing.T) {
	useMailpitSMTP(t)
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")

	t.Run("the verification code", func(t *testing.T) {
		accessToken, user, client := accountAPIUserOfClient(t)
		giveClientBrand(t, client, record.BrandAppearanceLight, "avocado")
		sendVerificationCode(t, accessToken)
		assert.Equal(t, avocadoLightEmail, readEmailLook(t, onlyMailTo(t, user.Email)))
	})

	// A notice is sent after the response, in a job, which keeps the brand of the request.
	t.Run("the notice of a password changed", func(t *testing.T) {
		accessToken, user, client := accountAPIUserOfClient(t)
		giveClientBrand(t, client, record.BrandAppearanceLight, "avocado")
		givePassword(t, user, passwordNoticeCurrent)
		stored, err := database.GetUserById(context.Background(), nil, user.Id)
		require.NoError(t, err)
		stored.EmailVerified = true
		require.NoError(t, database.UpdateUser(context.Background(), nil, stored))

		changePassword(t, accessToken)
		assert.Equal(t, avocadoLightEmail, readEmailLook(t, onlyMailTo(t, user.Email)))
	})

	t.Run("the verification code, for a client with no brand of its own", func(t *testing.T) {
		accessToken, user, _ := accountAPIUserOfClient(t)
		sendVerificationCode(t, accessToken)
		assert.Equal(t, plumDarkEmail, readEmailLook(t, onlyMailTo(t, user.Email)))
	})
}

// The administrator's token is issued to a client with a brand of its own, which the email does not
// take.
func TestEmails_AnAdministratorsActionSendsInTheDefaultBrand(t *testing.T) {
	useMailpitSMTP(t)
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	accessToken, adminClient := createAdminClientWithToken(t)
	giveClientBrand(t, adminClient, record.BrandAppearanceLight, "avocado")

	email := plusAddress()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/users/create", accessToken,
		api.CreateUserAdminRequest{
			Email:           email,
			GivenName:       "Branded",
			FamilyName:      "Setup",
			SetPasswordType: api.SetPasswordTypeEmail,
		})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	t.Cleanup(func() {
		if created, err := database.GetUserByEmail(context.Background(), nil, email); err == nil && created != nil {
			_ = database.DeleteUser(context.Background(), nil, created.Id)
		}
	})

	assert.Equal(t, plumDarkEmail, readEmailLook(t, onlyMailTo(t, email)))
}

// A sign-in that asked for safe mode sends its emails safe: its client's custom palette, every
// token one gray, gives way to Blueberry's colors, and the brand's light appearance stays.
func TestEmails_FromASignInInSafeModeAreDrawnSafe(t *testing.T) {
	useMailpitSMTP(t)
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, redirectURI := brandSignInClient(t, record.AcrLevel1)
	giveClientSafeModeBrand(t, client)
	browser := createHttpClient(t)
	forgotURL, _ := forgotPasswordLink(t, browser, withSafeMode(t, brandAuthorizeURL(client, redirectURI, "")))

	user, _ := createResetTestUser(t, plusAddress())
	requestResetAt(t, browser, forgotURL, user.Email)
	message := onlyMailTo(t, user.Email)
	assert.Equal(t, blueberryLightEmail, readEmailLook(t, message))
	assert.NotContains(t, message.HTML, "#777777", "nothing of the custom palette is drawn")
}
