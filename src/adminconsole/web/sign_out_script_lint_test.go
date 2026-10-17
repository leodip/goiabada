package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sessions pages' sign-out (#411, decision 1 of its review).
//
// GET /auth/logout only renders the confirmation since #411, so a script that navigates there
// after its own modal confirmed ending the current session asks the administrator a second time,
// against the modal's "immediate sign-out". The three pages that can end the current session post
// the sign-out instead, through utils.js's submitSignOut, which builds the same form the
// confirmation page's button submits.
//
// Lexical, like its neighbours, because no tier runs JavaScript: it holds utils.js to building a
// POST to /auth/logout, the three pages to calling it, and every template and script to navigating
// to /auth/logout nowhere.

// signOutNavigation is a script navigating to the console's sign-out route, by assignment or by
// assign or replace, in either quote style.
var signOutNavigation = regexp.MustCompile(`location(\.href)?\s*=\s*["']/auth/logout["']|location\.(assign|replace)\(\s*["']/auth/logout["']`)

// submitSignOutBody captures the body of function submitSignOut, up to the first closing brace in
// column zero.
var submitSignOutBody = regexp.MustCompile(`(?s)function\s+submitSignOut\s*\(\s*\)\s*\{(.*?)\n\}`)

func TestUtilsJS_SubmitSignOutPostsTheSignOutForm(t *testing.T) {
	m := submitSignOutBody.FindStringSubmatch(utilsJS(t))
	require.NotNil(t, m, "utils.js declares no function submitSignOut()")
	body := m[1]

	assert.Contains(t, body, `document.createElement("form")`)
	assert.Contains(t, body, `form.method = "post";`,
		"a GET would land on the confirmation page again, and the origin check reads only unsafe methods")
	assert.Contains(t, body, `form.action = "/auth/logout";`)
	assert.Contains(t, body, `document.body.appendChild(form);`, "a detached form is not submitted")
	assert.Contains(t, body, `form.submit();`)
}

func TestTemplates_TheSessionsPagesPostTheSignOutRatherThanNavigateToIt(t *testing.T) {
	for _, name := range []string{
		"template/account_user_sessions.html",
		"template/admin_users_sessions.html",
		"template/admin_clients_usersessions.html",
	} {
		b, err := templateFS.ReadFile(name)
		require.NoError(t, err)
		source := string(b)

		current := strings.Index(source, "result.IsCurrentSession")
		require.NotEqualf(t, -1, current, "%s no longer branches on the current session", name)
		assert.Containsf(t, source[current:], "submitSignOut();",
			"%s must post the sign-out once its modal has confirmed ending the current session", name)
	}

	reached := 0
	for _, root := range []fs.FS{templateFS, staticFS} {
		err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (!strings.HasSuffix(path, ".html") && !strings.HasSuffix(path, ".js")) {
				return nil
			}
			b, err := fs.ReadFile(root, path)
			if err != nil {
				return err
			}
			reached++
			for _, site := range signOutNavigation.FindAllString(string(b), -1) {
				t.Errorf("%s: %s navigates to the confirmation page; call submitSignOut() instead", path, site)
			}
			return nil
		})
		require.NoError(t, err)
	}
	require.Positive(t, reached, "the walk reached no template or script")
}

// The pattern above has to recognise the shape it refuses, or the walk proves nothing.
func TestTemplates_SignOutNavigationRecognisesTheShapesItRefuses(t *testing.T) {
	for _, refused := range []string{
		`window.location.href = "/auth/logout";`,
		`window.location = '/auth/logout';`,
		`window.location.assign("/auth/logout")`,
		`location.replace('/auth/logout')`,
	} {
		assert.Truef(t, signOutNavigation.MatchString(refused), "%s is not recognised", refused)
	}
	for _, allowed := range []string{
		`form.action = "/auth/logout";`,
		`<a href="/auth/logout">`,
		`window.location.href = "/account/sessions";`,
	} {
		assert.Falsef(t, signOutNavigation.MatchString(allowed), "%s is refused", allowed)
	}
}
