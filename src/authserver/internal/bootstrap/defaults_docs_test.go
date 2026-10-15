package bootstrap

// The defaults the concept pages state, held to the settings row a first start seeds (#522, #526).
//
// Tokens, Refresh tokens and Sessions each state how long the thing lasts, and Self-registration
// who can register, in a table of the settings that decide it, named as the admin console names
// them, with the value a new install starts with. An operator sizing or opening a deployment reads
// those values there, so each table is held to the row the seed writes, in both directions: a value
// the seed does not write fails, and so does a setting the page owes and leaves out.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/require"
)

// defaultsSection is one page's table of default settings: the page, its heading as written, and
// the settings it owes, by the admin console's label.
type defaultsSection struct {
	page, heading string
	settings      []string
}

var defaultsSections = []defaultsSection{
	{"site/src/content/docs/concepts/tokens.mdx", "## How long tokens last", []string{
		"Token expiration in seconds",
		"Include OpenID Connect claims in the access token",
		"Include OpenID Connect claims in the ID token",
	}},
	{"site/src/content/docs/concepts/refresh-tokens.mdx", "## How long a refresh token lasts", []string{
		"Offline refresh token - idle timeout in seconds",
		"Offline refresh token - max lifetime in seconds",
	}},
	{"site/src/content/docs/concepts/sessions.mdx", "## How long a session lasts", []string{
		"User session - idle timeout in seconds",
		"User session - max lifetime in seconds",
		"User session - max sessions per user",
	}},
	{"site/src/content/docs/concepts/self-registration.mdx", "## Who can register", []string{
		"User self registration enabled",
		"User self registration requires email verification",
	}},
}

// seededDefaults is the value a seeded settings row holds for each admin console label: a number
// of seconds as digits, a switch as On or Off.
func seededDefaults(settings *record.Settings) map[string]string {
	onOff := map[bool]string{false: "Off", true: "On"}
	return map[string]string{
		"Token expiration in seconds":                        strconv.Itoa(settings.TokenExpirationInSeconds),
		"Include OpenID Connect claims in the access token":  onOff[settings.IncludeOpenIDConnectClaimsInAccessToken],
		"Include OpenID Connect claims in the ID token":      onOff[settings.IncludeOpenIDConnectClaimsInIdToken],
		"Offline refresh token - idle timeout in seconds":    strconv.Itoa(settings.RefreshTokenOfflineIdleTimeoutInSeconds),
		"Offline refresh token - max lifetime in seconds":    strconv.Itoa(settings.RefreshTokenOfflineMaxLifetimeInSeconds),
		"User session - idle timeout in seconds":             strconv.Itoa(settings.UserSessionIdleTimeoutInSeconds),
		"User session - max lifetime in seconds":             strconv.Itoa(settings.UserSessionMaxLifetimeInSeconds),
		"User session - max sessions per user":               strconv.Itoa(settings.MaxUserSessionsPerUser),
		"User self registration enabled":                     onOff[settings.SelfRegistrationEnabled],
		"User self registration requires email verification": onOff[settings.SelfRegistrationRequiresEmailVerification],
	}
}

// The tables of default settings on Tokens, Refresh tokens, Sessions and Self-registration are the
// values a new install starts with. Each row's default is what the seed writes, and each page names every
// setting it owes.
func TestConceptDocs_TheDefaultsAreWhatTheSeedWrites(t *testing.T) {
	db := newSeedDB(t)
	_, err := testRunner(db, singleStepConfig()).run(context.Background())
	require.NoError(t, err)
	settings, err := db.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)

	root := filepath.Dir(guard.SourceRoot(t))
	for _, section := range defaultsSections {
		assertDefaultsTable(t, root, section, seededDefaults(settings))
	}
}

func TestConceptDocs_ADefaultsTableDisagreeingWithTheSeedFails(t *testing.T) {
	root := t.TempDir()
	writeDefaultsFixture(t, root, "site/sessions.mdx", "## How long a session lasts\n\n"+
		"| Setting | Default |\n|---|---|\n"+
		"| **User session - idle timeout in seconds** | 3600 (an hour) |\n"+
		"| **User session - lifetime** | 86400 (a day) |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDefaultsTable(r, root, defaultsSection{"site/sessions.mdx", "## How long a session lasts", []string{
			"User session - idle timeout in seconds",
			"User session - max lifetime in seconds",
		}}, map[string]string{
			"User session - idle timeout in seconds": "7200",
			"User session - max lifetime in seconds": "86400",
		})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/sessions.mdx: ## How long a session lasts row 1 says User session - idle timeout in seconds starts at 3600, the seed writes 7200",
		"site/sessions.mdx: ## How long a session lasts row 2 names User session - lifetime, which is none of the settings it owes",
		"site/sessions.mdx: ## How long a session lasts has no row for User session - max lifetime in seconds",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestConceptDocs_ADefaultsTableAgreeingWithTheSeedPasses(t *testing.T) {
	root := t.TempDir()
	writeDefaultsFixture(t, root, "site/tokens.mdx", "## How long tokens last\n\n"+
		"| Setting | Default |\n|---|---|\n"+
		"| **Token expiration in seconds** | 300 (5 minutes) |\n"+
		"| **Include OpenID Connect claims in the ID token** | On |\n\n"+
		"## Next\n\n| Setting | Default |\n|---|---|\n| **Token expiration in seconds** | 1 |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDefaultsTable(r, root, defaultsSection{"site/tokens.mdx", "## How long tokens last", []string{
			"Token expiration in seconds",
			"Include OpenID Connect claims in the ID token",
		}}, map[string]string{
			"Token expiration in seconds":                   "300",
			"Include OpenID Connect claims in the ID token": "On",
		})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the seed was refused: %+v", report)
	}
}

func TestConceptDocs_AMissingDefaultsSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDefaultsFixture(t, root, "site/tokens.mdx", "## Lifetimes\n\n"+
		"| Setting | Default |\n|---|---|\n| **Token expiration in seconds** | 300 |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDefaultsTable(r, root, defaultsSection{"site/tokens.mdx", "## How long tokens last",
			[]string{"Token expiration in seconds"}}, map[string]string{"Token expiration in seconds": "300"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## How long tokens last") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestConceptDocs_ADefaultsSectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDefaultsFixture(t, root, "site/tokens.mdx", "## How long tokens last\n\nFive minutes.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDefaultsTable(r, root, defaultsSection{"site/tokens.mdx", "## How long tokens last",
			[]string{"Token expiration in seconds"}}, map[string]string{"Token expiration in seconds": "300"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "has no Setting and Default table") {
		t.Errorf("a section with no table did not stop the check: %+v", report)
	}
}

// assertDefaultsTable is the reporting half of the defaults check: one failure per row whose
// default is not the seed's, per row naming a setting the section does not owe, and per owed
// setting with no row; a stop for a section or table not found. A default is read as its first
// word, so "300 (5 minutes)" is 300.
func assertDefaultsTable(r guard.Reporter, root string, section defaultsSection, seeded map[string]string) {
	r.Helper()
	rows, err := defaultsTableRows(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	seen := map[string]bool{}
	for i, row := range rows {
		setting, value := row[0], row[1]
		if !slices.Contains(section.settings, setting) {
			r.Errorf("%s: %s row %d names %s, which is none of the settings it owes",
				section.page, section.heading, i+1, setting)
			continue
		}
		seen[setting] = true
		if value != seeded[setting] {
			r.Errorf("%s: %s row %d says %s starts at %s, the seed writes %s",
				section.page, section.heading, i+1, setting, value, seeded[setting])
		}
	}
	for _, setting := range section.settings {
		if !seen[setting] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, setting)
		}
	}
}

// defaultsTableRows is the Setting and Default table of the section heading opens, one row per
// setting: its name and the default the page shows. The section is read through the shared reader,
// and the table the section's tables hold whose header names the two columns.
func defaultsTableRows(root string, section defaultsSection) ([][2]string, error) {
	text, err := docsreader.Section(root, section.page, section.heading)
	if err != nil {
		return nil, err
	}
	var rows [][2]string
	found := false
	for _, table := range docsreader.Tables(text) {
		if len(table.Header) < 2 || table.Header[0] != "Setting" || table.Header[1] != "Default" {
			continue
		}
		found = true
		for _, cells := range table.Rows {
			if len(cells) >= 2 {
				value, _, _ := strings.Cut(cells[1], " ")
				rows = append(rows, [2]string{strings.Trim(cells[0], "*"), value})
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("%s: %s has no Setting and Default table", section.page, section.heading)
	}
	return rows, nil
}

func writeDefaultsFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}
