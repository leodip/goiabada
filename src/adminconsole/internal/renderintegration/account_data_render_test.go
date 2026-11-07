package renderintegration

import (
	"html"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Your data page, through the real templates and layouts (#782 decision 6). The English is the
// decision's, written out here rather than read from the catalog, so a reworded catalog fails.

const (
	dataPageLead     = "A copy of your data in Test, in one JSON file."
	dataPageContents = "your profile and contact details; your groups and permissions, and the attributes apps can be " +
		"given; the consents you gave apps; your sessions; the apps that can still get access to your account, with the " +
		"IP address and browser you signed in from; the legal documents you accepted; your picture; and the audit log's " +
		"entries about your account. Changes an administrator made say so, without naming them."
	dataPageSignIn       = "If you haven't signed in during the last few minutes, you're asked to sign in again first."
	dataPageSignedInBack = "You've signed in again. Select Download my data to get your file."
)

// renderDataPage draws /account/data in locale, with account deletion on or off.
func renderDataPage(t *testing.T, path string, bind map[string]interface{}, locale string, deletion bool) string {
	t.Helper()
	return html.UnescapeString(renderPageWith(t, path, "/layouts/menu_layout.html", "/account_data.html",
		bind, nil, locale, deletionOn(deletion)))
}

// The account menu always lists Your data, just before Delete account while deletion is on and last
// while it is off, and marks it as the page the user is on at /account/data (decision 6).
func TestRender_AccountMenuListsYourDataJustBeforeDeleteAccount(t *testing.T) {
	bind := map[string]interface{}{"signedInAgain": false}

	on := renderDataPage(t, "/account/data", bind, "en", true)
	links := accountMenuLinkRe.FindAllStringSubmatch(on, -1)
	require.GreaterOrEqual(t, len(links), 2, "the account menu is drawn")
	assert.Equal(t, "/account/data", links[len(links)-2][1], "Your data is just before Delete account")
	assert.Equal(t, "/account/delete", links[len(links)-1][1])
	assert.Regexp(t, `<a class="nav-link" href="/account/data" aria-current="page"><svg[^>]*aria-hidden="true">(?s:.*?)</svg>Your data</a>`, on)

	off := renderDataPage(t, "/account/data", bind, "en", false)
	links = accountMenuLinkRe.FindAllStringSubmatch(off, -1)
	require.NotEmpty(t, links)
	assert.Equal(t, "/account/data", links[len(links)-1][1], "shown with deletion off too, as the last item")

	other := renderDataPage(t, "/account/profile", bind, "en", true)
	assert.Regexp(t, `<a class="nav-link" href="/account/data"><svg`, other, "not marked on another page")
}

// The page in decision 6's words: the title, the lead naming the app, what's in the file, the
// sign-in sentence, and Download my data, the form's one main action, posting to the page itself.
func TestRender_AccountData_SaysWhatIsInTheFile(t *testing.T) {
	out := renderDataPage(t, "/account/data", map[string]interface{}{"signedInAgain": false}, "en", true)

	assert.Contains(t, out, `<h1 class="page-title">Download your data</h1>`)
	assert.Contains(t, out, "<title>Download your data – Test</title>")
	assert.Contains(t, out, dataPageLead)
	assert.Regexp(t, `<strong>What's in it:</strong>\s*`+regexp.QuoteMeta(dataPageContents), out)
	assert.Contains(t, out, dataPageSignIn)
	assert.Regexp(t, `<form class="panel" method="post" action="/account/data">`, out)
	assert.Contains(t, out, `<button class="button button-primary" type="submit">Download my data</button>`)

	assert.NotContains(t, out, dataPageSignedInBack, "no notice on an ordinary visit")
	assert.NotContains(t, out, `role="alert"`)
}

// Back from the sign-in, a notice above the button says to press it again (decision 6).
func TestRender_AccountData_TheNoticeOnReturn(t *testing.T) {
	out := renderDataPage(t, "/account/data", map[string]interface{}{"signedInAgain": true}, "en", true)

	assert.Regexp(t, `(?s)<div class="notice notice-positive" role="status">.*?`+regexp.QuoteMeta(dataPageSignedInBack)+
		`.*?<button class="button button-primary" type="submit">Download my data</button>`, out)
}

// A refusal the user waits out is drawn at the top of the form as an alert.
func TestRender_AccountData_ARefusal(t *testing.T) {
	out := renderDataPage(t, "/account/data", map[string]interface{}{"signedInAgain": false,
		"error": "Too many requests in a short time."}, "en", true)

	assert.Regexp(t, `(?s)<form class="panel" method="post" action="/account/data">\s*<div class="panel-body stacked">\s*`+
		`<div class="notice notice-danger" role="alert">.*?Too many requests in a short time\.`, out)
}

// The page in another language reads its catalog, with no English left over.
func TestRender_AccountData_IsTranslated(t *testing.T) {
	bind := map[string]interface{}{"signedInAgain": true}
	for _, locale := range []string{"pt-BR", "es", "fr", "de", "it"} {
		t.Run(locale, func(t *testing.T) {
			out := renderDataPage(t, "/account/data", bind, locale, true)
			for _, english := range []string{"Download your data", dataPageLead, "What's in it:", dataPageContents,
				dataPageSignIn, dataPageSignedInBack, "Download my data", ">Your data<"} {
				assert.NotContains(t, out, english)
			}
			assert.Contains(t, out, "Test", "the lead names the app")
		})
	}
}
