package handlers

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Personal data page lists the cookies a stock deployment sets, one table per server, and
// operators copy those tables into their privacy notices. So the auth server's table is held to
// the names the auth server sets on https, in both directions: a cookie renamed in the code fails,
// and so does a name the page lists that the auth server never sets (#745 decision 3).
const (
	personalDataPage         = "site/src/content/docs/deploy/personal-data.mdx"
	authServerCookiesHeading = "### On the auth server"
)

func TestPersonalDataPage_ListsExactlyTheAuthServersCookies(t *testing.T) {
	repoRoot := filepath.Dir(guard.SourceRoot(t))
	page, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(personalDataPage)))
	require.NoError(t, err, "unable to read the Personal data page")

	listed, err := cookieNamesUnder(string(page), authServerCookiesHeading)
	require.NoError(t, err, personalDataPage)

	set := authServerCookieNames(t)
	slices.Sort(listed)
	slices.Sort(set)
	assert.Equal(t, set, listed, "%s lists the cookies under %q as %q; the auth server sets %q",
		personalDataPage, authServerCookiesHeading, listed, set)
}

// authServerCookieNames is the name of every cookie the auth server sets on https: its browser
// session's, as its session store names it, and the device cookie's, as it is written.
func authServerCookieNames(t *testing.T) []string {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.SessionIdentifier, true,
		sessionstore.PersistentCookie(sessiontest.KeepEverySignedInSession), sessionstore.KeyPair{
			AuthenticationKey: []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			EncryptionKey:     []byte("0123456789abcdef0123456789abcdef"),
		}, nil)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	NewDeviceCookie(true).write(rec, strings.Repeat("ab", deviceIdBytes), 60)
	written := rec.Result().Cookies()
	require.Len(t, written, 1, "the device cookie wrote %d cookies", len(written))

	return []string{store.CookieName(sessionkeys.AuthServerSessionName), written[0].Name}
}

func TestCookieNamesUnder_ReadsTheTableUnderItsHeadingAlone(t *testing.T) {
	page := "## Cookies\n\n" +
		"### On the auth server\n\n" +
		"| Cookie | What it's for | How long it lasts |\n|---|---|---|\n" +
		"| `__Host-one` | Signing in. | The session. |\n" +
		"| `__Host-two` | The browser. | A day. |\n\n" +
		"### On the admin console\n\n" +
		"| Cookie | What it's for | How long it lasts |\n|---|---|---|\n" +
		"| `__Host-three` | Signing in. | The browser. |\n"

	listed, err := cookieNamesUnder(page, "### On the auth server")

	require.NoError(t, err)
	assert.Equal(t, []string{"__Host-one", "__Host-two"}, listed)
}

func TestCookieNamesUnder_AMissingHeadingIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("## Cookies\n\n| Cookie |\n|---|\n| `__Host-one` |\n", "### On the auth server")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "### On the auth server")
}

func TestCookieNamesUnder_AHeadingWithNoCookieTableIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("### On the auth server\n\nIt sets `__Host-one`.\n\n| Name | Why |\n|---|---|\n| `x` | y |\n",
		"### On the auth server")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cookie")
}

func TestCookieNamesUnder_ACellThatIsNotOneCodeSpanIsAnError(t *testing.T) {
	_, err := cookieNamesUnder("### On the auth server\n\n| Cookie |\n|---|\n| `__Host-one` or `one` |\n",
		"### On the auth server")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "`__Host-one` or `one`")
}

var cookieNameCell = regexp.MustCompile("^`([^`]+)`$")

// cookieNamesUnder returns the cookie names in the Cookie column of the one table under heading,
// each written as a code span. A page without the heading, a section with no such table or more
// than one, and a cell that is not one code span are each an error, so the check never passes
// having read nothing.
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
