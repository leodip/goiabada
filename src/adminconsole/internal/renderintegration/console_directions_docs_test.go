package renderintegration

// The docs site's directions into the admin console, held to the labels the console draws (#135).
//
// A docs page sends an administrator to a user's tab ("the user's **Sessions** tab") and a user to
// one of their Account pages ("**Account**, **Sessions**"). A label the console no longer draws
// leaves the reader looking for a page that isn't there, which is what renaming the Consents pages
// to Connected clients and Applications left on seven pages. The Users and groups page also lists
// the user's tabs, which must be the tab bar's, in its order.
//
// It renders two pages in English and reads every docs page.

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// docsDir is the docs site's pages, relative to the repository root.
const docsDir = "site/src/content/docs"

// tabListPage is the page listing the user's tabs, and tabListOpening the sentence that does.
const (
	tabListPage    = docsDir + "/concepts/users-and-groups.mdx"
	tabListOpening = "The user's page has these tabs:"
)

// consoleDirection is one place a docs page names a console label for the reader to find.
type consoleDirection struct {
	// where is the page, relative to the root, and its line.
	where string
	// account is true for an Account page, false for a user's tab.
	account bool
	label   string
}

var (
	accountDirectionRe = regexp.MustCompile(`\*\*Account\*\*,\s+\*\*([^*]+)\*\*`)
	userTabDirectionRe = regexp.MustCompile(`(?:user's|their)\s+\*\*([^*]+)\*\*\s+tab\b`)
	boldRe             = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	tabItemRe          = regexp.MustCompile(`<a class="tab-item"[^>]*>([^<]+)</a>`)
	accountMenuItemRe  = regexp.MustCompile(`(?s)<a class="nav-link" href="/account/[^"]*"[^>]*>(?:<svg.*?</svg>)?([^<]+)</a>`)
)

// consoleDirections is every direction into the console the docs pages under root give, in walk
// order.
func consoleDirections(root string) ([]consoleDirection, error) {
	var found []consoleDirection
	err := filepath.WalkDir(filepath.Join(root, docsDir), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".mdx" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		text := string(b)
		for _, kind := range []struct {
			re      *regexp.Regexp
			account bool
		}{{accountDirectionRe, true}, {userTabDirectionRe, false}} {
			for _, m := range kind.re.FindAllStringSubmatchIndex(text, -1) {
				line := strings.Count(text[:m[0]], "\n") + 1
				found = append(found, consoleDirection{where: fmt.Sprintf("%s:%d", filepath.ToSlash(rel), line),
					account: kind.account, label: text[m[2]:m[3]]})
			}
		}
		return nil
	})
	return found, err
}

// docsTabList is the user's tabs as the tab list page names them, in order, or nil when the page
// has no such sentence.
func docsTabList(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, tabListPage))
	if err != nil {
		return nil, err
	}
	_, after, ok := strings.Cut(string(b), tabListOpening)
	if !ok {
		return nil, nil
	}
	sentence, _, _ := strings.Cut(after, ".")
	var tabs []string
	for _, m := range boldRe.FindAllStringSubmatch(sentence, -1) {
		tabs = append(tabs, m[1])
	}
	return tabs, nil
}

// assertConsoleDirections holds the docs pages under root to the user's tabs and the Account pages
// named, and the tab list page to naming the tabs in their order.
func assertConsoleDirections(r guard.Reporter, root string, userTabs, accountPages []string) {
	r.Helper()
	directions, err := consoleDirections(root)
	if err != nil {
		r.Fatalf("reading the docs pages: %v", err)
	}
	if len(directions) == 0 {
		r.Fatalf("no docs page under %s names a user's tab or an Account page", docsDir)
	}
	for _, d := range directions {
		if d.account && !slices.Contains(accountPages, d.label) {
			r.Errorf("%s sends the reader to Account, %s, which the console's account menu doesn't have", d.where, d.label)
		}
		if !d.account && !slices.Contains(userTabs, d.label) {
			r.Errorf("%s sends the reader to the user's %s tab, which the console doesn't draw", d.where, d.label)
		}
	}

	listed, err := docsTabList(root)
	if err != nil {
		r.Fatalf("reading the tab list: %v", err)
	}
	if listed == nil {
		r.Fatalf("%s has no sentence opening %q", tabListPage, tabListOpening)
	}
	if !slices.Equal(listed, userTabs) {
		r.Errorf("%s lists the user's tabs as %q, but the console draws %q", tabListPage, listed, userTabs)
	}
}

// consoleLabels is the labels of the user's tabs and of the Account pages, in English, in the order
// the console draws them.
func consoleLabels(t *testing.T) (userTabs, accountPages []string) {
	t.Helper()
	userPage := renderMenuPageIn(t, "/admin_users_connected_clients.html", connectedClientsBind(nil), "en", true)
	for _, m := range tabItemRe.FindAllStringSubmatch(userPage, -1) {
		userTabs = append(userTabs, html.UnescapeString(strings.TrimSpace(m[1])))
	}
	accountPage := renderMenuPageIn(t, "/account_applications.html", map[string]interface{}{}, "en", true)
	for _, m := range accountMenuItemRe.FindAllStringSubmatch(accountPage, -1) {
		accountPages = append(accountPages, html.UnescapeString(strings.TrimSpace(m[1])))
	}
	if len(userTabs) == 0 || len(accountPages) == 0 {
		t.Fatalf("read %d user tabs and %d Account pages off the rendered pages", len(userTabs), len(accountPages))
	}
	return userTabs, accountPages
}

// Every user's tab and Account page a docs page sends the reader to is one the console draws, and
// Users and groups lists the user's tabs as the tab bar draws them.
func TestDocs_DirectionsIntoTheConsoleNameWhatItDraws(t *testing.T) {
	userTabs, accountPages := consoleLabels(t)
	assertConsoleDirections(t, filepath.Dir(guard.SourceRoot(t)), userTabs, accountPages)
}

// writeDocsFixture writes content to name, a path under root.
func writeDocsFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	fixtureUserTabs     = []string{"Details", "Connected clients", "Sessions"}
	fixtureAccountPages = []string{"Applications", "Sessions"}
)

func TestDocs_DirectionsToLabelsTheConsoleLacksFail(t *testing.T) {
	root := t.TempDir()
	writeDocsFixture(t, root, tabListPage, "The user's page has these tabs: **Details**, **Consents** and **Sessions**.\n")
	writeDocsFixture(t, root, docsDir+"/concepts/ending-sessions.mdx", "Intro.\n\n"+
		"Withdraw it on the user's **Consents** tab, or under **Account**,\n**Consents**.\n"+
		"End it on their **Sessions** tab or under **Account**, **Sessions**.\n"+
		"An administrator revokes it on their **Consents** tab.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsoleDirections(r, root, fixtureUserTabs, fixtureAccountPages)
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		docsDir + "/concepts/ending-sessions.mdx:3 sends the reader to Account, Consents, which the console's account menu doesn't have",
		docsDir + "/concepts/ending-sessions.mdx:3 sends the reader to the user's Consents tab, which the console doesn't draw",
		docsDir + "/concepts/ending-sessions.mdx:6 sends the reader to the user's Consents tab, which the console doesn't draw",
		tabListPage + ` lists the user's tabs as ["Details" "Consents" "Sessions"], but the console draws ["Details" "Connected clients" "Sessions"]`,
	}
	got := slices.Clone(report.Errors)
	slices.Sort(got)
	slices.Sort(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("failures\n%q\nwant\n%q", got, want)
	}
}

func TestDocs_ATabListOutOfOrderFails(t *testing.T) {
	root := t.TempDir()
	writeDocsFixture(t, root, tabListPage, "The user's page has these tabs: **Details**, **Sessions** and **Connected clients**.\n"+
		"See the user's **Sessions** tab.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsoleDirections(r, root, fixtureUserTabs, fixtureAccountPages)
	})

	if report.Stopped || len(report.Errors) != 1 || !strings.Contains(report.Errors[0], "lists the user's tabs") {
		t.Errorf("a tab list out of the tab bar's order was not refused alone: %+v", report)
	}
}

func TestDocs_DirectionsToLabelsTheConsoleDrawsPass(t *testing.T) {
	root := t.TempDir()
	writeDocsFixture(t, root, tabListPage, "The user's page has these tabs: **Details**, **Connected clients** and **Sessions**.\n")
	writeDocsFixture(t, root, docsDir+"/concepts/ending-sessions.mdx",
		"Disconnect it on the user's **Connected clients** tab, or under **Account**, **Applications**.\n"+
			"End it on their **Sessions** tab, and see the **Settings** tab of a client.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsoleDirections(r, root, fixtureUserTabs, fixtureAccountPages)
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("directions the console draws were refused: %+v", report)
	}
}

func TestDocs_PagesGivingNoDirectionsStop(t *testing.T) {
	root := t.TempDir()
	writeDocsFixture(t, root, tabListPage, "Users and groups, with no tab list and no directions.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsoleDirections(r, root, fixtureUserTabs, fixtureAccountPages)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "names a user's tab or an Account page") {
		t.Errorf("a walk reaching no direction did not stop the check: %+v", report)
	}
}

func TestDocs_ATabListPageWithoutItsSentenceStops(t *testing.T) {
	root := t.TempDir()
	writeDocsFixture(t, root, tabListPage, "Open the user's **Sessions** tab.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertConsoleDirections(r, root, fixtureUserTabs, fixtureAccountPages)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, tabListOpening) {
		t.Errorf("a tab list page without its sentence did not stop the check naming it: %+v", report)
	}
}
