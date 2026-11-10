package renderintegration

import (
	"html"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
)

// The Delete account page and the page after it, through the real templates and layouts (#783
// decisions 6, 8 and 9). The English is decision 9's, written out here rather than read from the
// catalog, so a reworded catalog fails.

const (
	deletePageLead    = "Your Test account is deleted at once. This can't be undone."
	deletePageDeleted = "your profile, email address, phone and address; your password, authenticator and recovery codes; " +
		"your picture; your groups, permissions and attributes; the consents you gave apps; and your sessions, so you're " +
		"signed out everywhere and apps can no longer get access to your account."
	deletePageKept = "the audit log's entries about your account, which name it by an ID, not your email address, until " +
		"your organization's retention period removes them; server logs, which can include your IP address; backups made " +
		"before today, until they're replaced; and what apps already received about you, such as your name and email " +
		"address. Ask each app to delete what it holds."
	deletedPageText = "Your Test account is gone, and you're signed out everywhere. Apps you used keep what they already " +
		"received; ask them to delete it."
)

func deletionOn(on bool) *api.PublicSettingsResponse {
	return &api.PublicSettingsResponse{AppName: "Test", SMTPEnabled: true, AccountDeletionEnabled: on}
}

// renderDeletePage draws /account/delete in English with deletion on.
func renderDeletePage(t *testing.T, bind map[string]interface{}) string {
	t.Helper()
	return html.UnescapeString(renderPageWith(t, "/account/delete", "/layouts/menu_layout.html", "/account_delete.html",
		bind, nil, "en", deletionOn(true)))
}

var accountMenuLinkRe = regexp.MustCompile(`<a class="nav-link" href="(/account/[a-z-]+)"`)

// The account menu lists Delete account, last, only while the public settings say deletion is on,
// and marks it as the page the user is on at /account/delete (decision 6).
func TestRender_AccountMenuListsDeleteAccountOnlyWhileTheSettingIsOn(t *testing.T) {
	bind := map[string]interface{}{"otpEnabled": false, "useRecoveryCode": false}
	for _, on := range []bool{true, false} {
		out := renderPageWith(t, "/account/delete", "/layouts/menu_layout.html", "/account_delete.html", bind, nil, "en", deletionOn(on))
		links := accountMenuLinkRe.FindAllStringSubmatch(out, -1)
		require.NotEmpty(t, links, "the account menu is drawn")
		if !on {
			assert.NotContains(t, out, `href="/account/delete"`, "no Delete account item while deletion is off")
			continue
		}
		assert.Equal(t, "/account/delete", links[len(links)-1][1], "Delete account is the menu's last item")
		assert.Regexp(t, `<a class="nav-link" href="/account/delete" aria-current="page">(?s:.*?)Delete account</a>`, out)
	}

	other := renderPageWith(t, "/account/profile", "/layouts/menu_layout.html", "/account_delete.html", bind, nil, "en", deletionOn(true))
	assert.Regexp(t, `<a class="nav-link" href="/account/delete"><svg`, other, "not marked on another page")
}

// The page in decision 9's words: the title, the lead naming the app, what is deleted and what
// isn't, the password, and Delete my account in the danger style, asked first in a confirmation
// dialog with Cancel and Delete my account.
func TestRender_AccountDelete_SaysWhatIsDeletedAndWhatIsNot(t *testing.T) {
	out := renderDeletePage(t, map[string]interface{}{"otpEnabled": false, "useRecoveryCode": false})

	assert.Contains(t, out, `<h1 class="page-title">Delete your account</h1>`)
	assert.Contains(t, out, "<title>Delete your account – Test</title>")
	assert.Contains(t, out, deletePageLead)
	assert.Regexp(t, `<strong>What's deleted:</strong>\s*`+regexp.QuoteMeta(deletePageDeleted), out)
	assert.Regexp(t, `<strong>What isn't:</strong>\s*`+regexp.QuoteMeta(deletePageKept), out)

	assert.Contains(t, out, `<form class="panel" method="post" action="/account/delete" novalidate data-confirm-dialog="confirmDeletion" data-confirm-title="Delete your account?" data-confirm-always="This can't be undone.">`)
	assert.Regexp(t, `<input class="control" id="password" type="password" name="password" autocomplete="current-password"`, out)
	assert.Contains(t, out, `<button class="button button-danger" type="submit">Delete my account</button>`)
	assert.Regexp(t, `(?s)<dialog id="confirmDeletion_modalDialog".*<button id="confirmDeletion_btnModal1" class="button">Cancel</button>\s*<button id="confirmDeletion_btnModal2" class="button button-danger">Delete my account</button>`, out)

	assert.NotContains(t, out, `name="otp"`, "no code is asked for without two-factor authentication")
	assert.NotContains(t, out, `name="recoveryCode"`)
	assert.NotContains(t, out, "Use a recovery code instead")
}

// With two-factor authentication on, the page asks for the authentication code, and Use a recovery
// code instead shows the recovery code field in its place. The field not shown is disabled, so the
// form posts only the one the user chose; with JavaScript off, the choice is never offered.
func TestRender_AccountDelete_AsksForOneSecondFactor(t *testing.T) {
	codeField := regexp.MustCompile(`<div class="field" id="otp-field"( hidden)?>(?s:.*?)<input class="control control-mono" id="otp" type="text" name="otp" inputmode="numeric" autocomplete="one-time-code"[^>]*?( disabled)?>`)
	recoveryField := regexp.MustCompile(`<div class="field" id="recovery-code-field"( hidden)?>(?s:.*?)<input class="control control-mono" id="recoveryCode" type="text" name="recoveryCode" autocomplete="off"[^>]*?( disabled)?>`)

	for _, useRecoveryCode := range []bool{false, true} {
		out := renderDeletePage(t, map[string]interface{}{"otpEnabled": true, "useRecoveryCode": useRecoveryCode})

		code := codeField.FindStringSubmatch(out)
		require.NotNil(t, code, "the authentication code field is drawn")
		recovery := recoveryField.FindStringSubmatch(out)
		require.NotNil(t, recovery, "the recovery code field is drawn")

		assert.Equal(t, useRecoveryCode, code[1] != "", "the code field hidden: recovery chosen %v", useRecoveryCode)
		assert.Equal(t, useRecoveryCode, code[2] != "", "the code field disabled: recovery chosen %v", useRecoveryCode)
		assert.Equal(t, !useRecoveryCode, recovery[1] != "", "the recovery field hidden: recovery chosen %v", useRecoveryCode)
		assert.Equal(t, !useRecoveryCode, recovery[2] != "", "the recovery field disabled: recovery chosen %v", useRecoveryCode)

		assert.Contains(t, out, ">Authentication code</label>")
		assert.Contains(t, out, ">Recovery code</label>")
		assert.Regexp(t, `<button class="button button-quiet button-sm" type="button" data-second-factor-toggle[^>]*hidden>`, out,
			"the choice is drawn hidden, for the page's script to show")
		assert.Contains(t, out, `data-use-recovery-code="Use a recovery code instead"`)
	}
	out := renderDeletePage(t, map[string]interface{}{"otpEnabled": true, "useRecoveryCode": false})
	assert.Contains(t, out, `src="/static/pages/account-delete.js`)

	script, err := fs.ReadFile(web.StaticFS(), "pages/account-delete.js")
	require.NoError(t, err)
	assert.Contains(t, string(script), "disabled", "the script disables the field it hides, so it is not posted")
}

// A refusal is drawn at the top of the form and marks the field it is about.
func TestRender_AccountDelete_ARefusalMarksItsField(t *testing.T) {
	for _, field := range []string{"password", "otp", "recoveryCode"} {
		out := renderDeletePage(t, map[string]interface{}{"otpEnabled": true, "useRecoveryCode": field == "recoveryCode",
			"error": "That isn't right.", "errorField": field})

		assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="delete-error">`)
		assert.Contains(t, out, "That isn't right.")
		invalid := regexp.MustCompile(`<input [^>]*id="([A-Za-z]+)"[^>]*aria-invalid="true" aria-describedby="delete-error"`).FindAllStringSubmatch(out, -1)
		require.Len(t, invalid, 1, "exactly one field is marked for %s", field)
		assert.Equal(t, field, invalid[0][1])
	}

	formLevel := renderDeletePage(t, map[string]interface{}{"otpEnabled": false, "useRecoveryCode": false,
		"error": "You're the last administrator.", "errorField": ""})
	assert.Contains(t, formLevel, "You're the last administrator.")
	assert.NotContains(t, formLevel, `aria-invalid="true"`)
}

// /account/deleted, on the layout without a menu, in decision 9's words.
func TestRender_AccountDeleted(t *testing.T) {
	out := html.UnescapeString(renderPageWith(t, "/account/deleted", "/layouts/no_menu_layout.html", "/account_deleted.html",
		nil, nil, "en", deletionOn(true)))

	assert.Contains(t, out, `<h1 class="auth-title">Your account is deleted</h1>`)
	assert.Contains(t, out, "<title>Your account is deleted – Test</title>")
	assert.Contains(t, out, deletedPageText)
	assert.NotContains(t, out, `class="sidebar"`, "no menu")
	assert.Equal(t, 0, strings.Count(out, "<form "), "nothing on it posts")
}

// The page in another language reads its catalog, with no English left over.
func TestRender_AccountDelete_IsTranslated(t *testing.T) {
	bind := map[string]interface{}{"otpEnabled": true, "useRecoveryCode": false}
	for _, locale := range []string{"pt-BR", "es", "fr", "de", "it"} {
		t.Run(locale, func(t *testing.T) {
			out := html.UnescapeString(renderPageWith(t, "/account/delete", "/layouts/menu_layout.html", "/account_delete.html",
				bind, nil, locale, deletionOn(true)))
			for _, english := range []string{"Delete your account", deletePageLead, "What's deleted:", "What isn't:",
				"Delete my account", "Use a recovery code instead", "Authentication code"} {
				assert.NotContains(t, out, english)
			}
			deleted := html.UnescapeString(renderPageWith(t, "/account/deleted", "/layouts/no_menu_layout.html", "/account_deleted.html",
				nil, nil, locale, deletionOn(true)))
			assert.NotContains(t, deleted, "Your account is deleted")
			assert.NotContains(t, deleted, deletedPageText)
			assert.Contains(t, deleted, "Test", "the text names the app")
		})
	}
}
