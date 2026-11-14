package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/testutil/mailpit"
	"github.com/leodip/goiabada/core/api"
)

// The activation link, the welcome email, the existing-account notice, the new user's setup email,
// the verification code and the test email are sent from their built-in definitions (#818), read
// here from the mailbox after the real flow that sends each: the subject, which is also the title,
// the language the email is marked with, and its plain-text part, where the activation link and the
// setup email say how long the link lasts in the link's lifetime, the verification code now says
// how long the code lasts, and a user with no name is greeted by their address.

// readEmail answers a message's title, the language it is marked with, and its plain-text part with
// its line endings as written here.
func readEmail(t *testing.T, message mailpit.Message) (title, lang, text string) {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	lang, _ = doc.Find("html").Attr("lang")
	return doc.Find("title").Text(), lang, strings.ReplaceAll(message.Text, "\r\n", "\n")
}

// appNameOfSettings is the app name the emails sign with.
func appNameOfSettings(t *testing.T) string {
	t.Helper()
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	return settings.AppName
}

// postRegisterAddressIn submits the address-only register form from a browser reading
// acceptLanguage, which is the language a registration's emails are written in.
func postRegisterAddressIn(t *testing.T, client *http.Client, email, acceptLanguage string) {
	t.Helper()
	destUrl := appConfig.AuthServer.BaseURL + "/account/register"
	req, err := http.NewRequest("POST", destUrl, strings.NewReader(url.Values{"email": {email}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", destUrl)
	req.Header.Set("Origin", appConfig.AuthServer.BaseURL)
	req.Header.Set("Accept-Language", acceptLanguage)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestActivationLinkEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	appName := appNameOfSettings(t)

	t.Run("in English", func(t *testing.T) {
		email := registerPlusAddress()
		client := createHttpClient(t)
		loadRegisterPage(t, client)
		postRegisterAddressIn(t, client, email, "en")

		message := onlyMailTo(t, email)
		title, lang, text := readEmail(t, message)
		assert.Equal(t, "Activate your account", message.Subject)
		assert.Equal(t, "Activate your account", title, "the title is the subject")
		assert.Equal(t, "en", lang)
		assert.True(t, strings.HasPrefix(text, "Hello,\n\n"+
			"To finish creating your "+appName+" account, click the link below and choose a password:\n\n"+
			appConfig.AuthServer.BaseURL+"/account/activate?"), text)
		assert.Contains(t, text, "\n\nThe link expires in 5 minutes. If you have trouble clicking it, copy and paste it into your web browser.\n\n"+
			"If you didn't ask to create an account, ignore this message: no account is created unless the link is used.\n\n"+
			"Best regards,\n"+appName+"\n")
	})

	t.Run("from a page read in Canadian French, in French", func(t *testing.T) {
		email := registerPlusAddress()
		client := createHttpClient(t)
		loadRegisterPage(t, client)
		postRegisterAddressIn(t, client, email, "fr-CA")

		message := onlyMailTo(t, email)
		title, lang, text := readEmail(t, message)
		assert.Equal(t, "Activez votre compte", message.Subject)
		assert.Equal(t, "Activez votre compte", title)
		assert.Equal(t, "fr", lang)
		assert.Contains(t, text, "\n\nLe lien expire dans 5 minutes. S’il ne s’ouvre pas, copiez-le et collez-le dans votre navigateur.\n\n")
	})
}

func TestWelcomeEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, false, true)
	appName := appNameOfSettings(t)

	email := registerPlusAddress()
	client := createHttpClient(t)
	loadRegisterPage(t, client)
	password := fake.Password(20)
	resp := postRegister(t, client, email, password, password)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	message := onlyMailTo(t, email)
	title, lang, text := readEmail(t, message)
	assert.Equal(t, "Welcome!", message.Subject)
	assert.Equal(t, "Welcome!", title, "the title is the subject, no longer \"Activate account\"")
	assert.Equal(t, "en", lang)
	assert.True(t, strings.HasPrefix(text, "Congratulations! Your account has been created.\n\n"+
		"You can login by clicking the link below:\n\n"+
		appConfig.AdminConsole.BaseURL+"/account/profile\n\n"+
		"If you have trouble clicking the link, you can copy and paste it into your web browser.\n\n"+
		"Best regards,\n"+appName+"\n"), text)
}

func TestExistingAccountNotice_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	setRegSettings(t, true, true, true)
	appName := appNameOfSettings(t)

	email := registerAddress()
	createResetTestUser(t, email)
	client := createHttpClient(t)
	loadRegisterPage(t, client)
	registerPage(t, client, email)

	message := onlyMailTo(t, email)
	title, lang, text := readEmail(t, message)
	assert.Equal(t, "You already have an account", message.Subject)
	assert.Equal(t, "You already have an account", title, "the title is the subject")
	assert.Equal(t, "en", lang)
	assert.True(t, strings.HasPrefix(text, "Hello,\n\n"+
		"Someone, possibly you, tried to create a new "+appName+" account with this email address. "+
		"This address already has an account, so no new account was created.\n\n"+
		"If it was you, sign in with your existing account. If you don't remember your password, you can reset it here: "+
		appConfig.AuthServer.BaseURL+"/forgot-password\n\n"+
		"If it wasn't you, you can ignore this message. Your account has not been changed.\n\n"+
		"Best regards,\n"+appName+"\n"), text)
}

func TestNewUserSetupEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	appName := appNameOfSettings(t)

	// A user created with no name is greeted by their address.
	email := plusAddress()
	status, _ := createUserMembers(t, api.CreateUserAdminRequest{
		Email:           email,
		SetPasswordType: api.SetPasswordTypeEmail,
	})
	require.Equal(t, http.StatusCreated, status)

	message := onlyMailTo(t, email)
	title, lang, text := readEmail(t, message)
	assert.Equal(t, appName+" - create a password for your new account", message.Subject)
	assert.Equal(t, appName+" - create a password for your new account", title, "the title is the subject")
	assert.Equal(t, "en", lang)
	resetLink := regexp.MustCompile(regexp.QuoteMeta(appConfig.AuthServer.BaseURL) + `/reset-password\?\S+`)
	assert.True(t, strings.HasPrefix(resetLink.ReplaceAllString(text, "<link>"), "Hello "+email+",\n\n"+
		"You can create your password by clicking the link below:\n\n"+
		"<link>\n\n"+
		"If you have trouble clicking the link, you can copy and paste it into your web browser.\n\n"+
		"The link works for 24 hours. If it has expired, contact your administrator, who can set your password "+
		"or let you request a new link from the sign-in page.\n\n"+
		"Best regards,\n"+appName+"\n"), text)
}

func TestVerificationCodeEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	appName := appNameOfSettings(t)

	// A user with no name is greeted by their address.
	accessToken, user := getUserAccessTokenWithAccountScope_EmailVerification(t)
	user.GivenName, user.MiddleName, user.FamilyName = "", "", ""
	require.NoError(t, database.UpdateUser(context.Background(), nil, user))

	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/account/email/verification/send", accessToken, map[string]string{})
	var sent api.AccountEmailVerificationSendResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sent))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, sent.EmailVerificationSent)

	message := onlyMailTo(t, user.Email)
	title, lang, text := readEmail(t, message)
	subject := regexp.MustCompile(`^Email verification - code (\S+)$`).FindStringSubmatch(message.Subject)
	require.Len(t, subject, 2, message.Subject)
	code := subject[1]
	assert.Equal(t, message.Subject, title, "the title is the subject")
	assert.Equal(t, "en", lang)
	assert.True(t, strings.HasPrefix(text, "Hello "+user.Email+",\n\n"+
		"This is your email verification code:\n\n"+
		code+"\n\n"+
		"The code expires in 5 minutes.\n\n"+
		"You can enter your code here: "+appConfig.AdminConsole.BaseURL+"/account/email-verification\n\n"+
		"Best regards,\n"+appName+"\n"), text)
}

func TestTestEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)
	appName := appNameOfSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	to := plusAddress()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/settings/email/send-test", accessToken,
		api.SendTestEmailRequest{To: to})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	message := onlyMailTo(t, to)
	title, lang, text := readEmail(t, message)
	assert.Equal(t, appName+" - test email", message.Subject)
	assert.Equal(t, appName+" - test email", title, "the title is the subject")
	assert.Equal(t, "en", lang)
	assert.True(t, strings.HasPrefix(text, "This is a test email from "+appName+".\n\n"+
		"It was sent from the email settings to check that email can be sent. If you can read it, there is nothing else to do.\n"), text)
}
