package oauthclient

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Personal data page lists the cookies a stock deployment sets, one table per server, and
// operators copy those tables into their privacy notices. So the admin console's table is held to
// the names the admin console sets on https, in both directions: a cookie renamed in the code
// fails, and so does a name the page lists that the console never sets (#745 decision 3).
const (
	personalDataPage           = "site/src/content/docs/deploy/personal-data.mdx"
	adminConsoleCookiesHeading = "### On the admin console"
)

func TestPersonalDataPage_ListsExactlyTheAdminConsolesCookies(t *testing.T) {
	repoRoot := filepath.Dir(guard.SourceRoot(t))
	page, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(personalDataPage)))
	require.NoError(t, err, "unable to read the Personal data page")

	listed, err := cookieNamesUnder(string(page), adminConsoleCookiesHeading)
	require.NoError(t, err, personalDataPage)

	set := adminConsoleCookieNames(t)
	slices.Sort(listed)
	slices.Sort(set)
	assert.Equal(t, set, listed, "%s lists the cookies under %q as %q; the admin console sets %q",
		personalDataPage, adminConsoleCookiesHeading, listed, set)
}

// adminConsoleCookieNames is the name of every cookie the admin console sets on https: its browser
// session's, as its session store names it, and the sign-in handshake's, as the store builds it.
func adminConsoleCookieNames(t *testing.T) []string {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, true,
		sessionstore.BrowserSessionCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)

	return []string{
		store.CookieName(builtin.AdminConsoleSessionName),
		store.ValuesCookie(SignInHandshakeCookie, "sealed").Name,
	}
}

func TestCookieNamesUnder_ReadsTheTableUnderItsHeadingAlone(t *testing.T) {
	page := "## Cookies\n\n" +
		"### On the auth server\n\n" +
		"| Cookie | What it's for | How long it lasts |\n|---|---|---|\n" +
		"| `__Host-one` | Signing in. | The session. |\n\n" +
		"### On the admin console\n\n" +
		"| Cookie | What it's for | How long it lasts |\n|---|---|---|\n" +
		"| `__Host-two` | Signing in. | The browser. |\n" +
		"| `__Host-three` | The handshake. | 30 minutes. |\n\n" +
		"## Next\n\n| Cookie |\n|---|\n| `__Host-four` |\n"

	listed, err := cookieNamesUnder(page, "### On the admin console")

	require.NoError(t, err)
	assert.Equal(t, []string{"__Host-two", "__Host-three"}, listed)
}

func TestCookieNamesUnder_AMissingHeadingIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("## Cookies\n\n| Cookie |\n|---|\n| `__Host-one` |\n", "### On the admin console")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "### On the admin console")
}

func TestCookieNamesUnder_AHeadingWithNoCookieTableIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("### On the admin console\n\nIt sets `__Host-one`.\n\n| Name | Why |\n|---|---|\n| `x` | y |\n",
		"### On the admin console")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cookie")
}

func TestCookieNamesUnder_ACellThatIsNotOneCodeSpanIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("### On the admin console\n\n| Cookie |\n|---|\n| `__Host-one` or `one` |\n",
		"### On the admin console")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "`__Host-one` or `one`")
}

var cookieNameCell = regexp.MustCompile("^`([^`]+)`$")

// cookieNamesUnder returns the cookie names in the Cookie column of the one table under heading,
// each written as a code span. A page without the heading, a section with no such table or more
// than one, and a cell that is not one code span are each an error, so the check never passes
// having read nothing. The auth server's docs test reads its own table the same way; the two
// modules cannot share a test helper.
func cookieNamesUnder(page, heading string) ([]string, error) {
	section, found := docsreader.SectionText(page, heading)
	if !found {
		return nil, fmt.Errorf("the page has no %q section", heading)
	}
	var tables []docsreader.Table
	for _, table := range docsreader.Tables(section) {
		if slices.Contains(table.Header, "Cookie") {
			tables = append(tables, table)
		}
	}
	if len(tables) != 1 {
		return nil, fmt.Errorf("want exactly one table with a Cookie column under %q, found %d", heading, len(tables))
	}
	cells, err := tables[0].Columns("Cookie")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, row := range cells {
		name := cookieNameCell.FindStringSubmatch(row[0])
		if name == nil {
			return nil, fmt.Errorf("a Cookie cell under %q is not one code span: %s", heading, row[0])
		}
		names = append(names, name[1])
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("the cookie table under %q has no row", heading)
	}
	return names, nil
}
