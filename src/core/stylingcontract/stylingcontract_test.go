package stylingcontract

import (
	"html/template"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The contract's three lists are the sizes #816 decision 7 published: 28 variables, 44 data-page
// values (23 on the auth server, 14 Account pages and 7 console cards) and 45 hook classes, with
// no entry twice.
func TestStylingContract_TheListsAreTheSizesTheContractPublishes(t *testing.T) {
	assert.Len(t, Variables(), 28)
	assert.Len(t, distinct(Variables()), 28, "a variable is listed twice")

	var pages []string
	sizes := map[string]int{}
	for _, g := range pageGroups {
		sizes[g.Name] = len(g.Pages)
		pages = append(pages, g.Pages...)
	}
	assert.Equal(t, map[string]int{"Auth server pages": 23, "Account pages": 14, "Other console pages": 7}, sizes)
	assert.Len(t, pages, 44)
	assert.Len(t, distinct(pages), 44, "a data-page value is listed twice")
	assert.Len(t, PagesOn(AuthServer), 23)
	assert.Len(t, PagesOn(AdminConsole), 21)

	var classes []string
	for _, g := range classGroups {
		for _, c := range g.Classes {
			classes = append(classes, c.Name)
			assert.NotEmptyf(t, c.Servers, "%s is promised on no server", c.Name)
		}
	}
	assert.Len(t, classes, 45)
	assert.Len(t, distinct(classes), 45, "a hook class is listed twice")
}

// The 23 color tokens, the two radii, the font family and the two shadows; neither --radius-box
// nor --app-header-height.
func TestStylingContract_TheVariablesAreTheTokensARestyleReachesFor(t *testing.T) {
	for _, want := range []string{"--color-canvas", "--color-focus", "--color-note-ink", "--radius-control",
		"--radius-panel", "--font-sans", "--shadow-panel", "--shadow-overlay"} {
		assert.Contains(t, Variables(), want)
	}
	assert.NotContains(t, Variables(), "--radius-box")
	assert.NotContains(t, Variables(), "--app-header-height")
}

// Every console value has a prefix, account- or console-, so a prefix selects a group.
func TestStylingContract_EveryConsoleValueHasItsGroupsPrefix(t *testing.T) {
	prefixes := map[string]string{"Account pages": "account-", "Other console pages": "console-"}
	for _, g := range pageGroups {
		if g.Server != AdminConsole {
			continue
		}
		for _, page := range g.Pages {
			assert.Regexpf(t, "^"+prefixes[g.Name], page, "%s, in %s", page, g.Name)
		}
	}
}

func TestStylingContract_ClassesOnAServerAreThosePromisedThere(t *testing.T) {
	auth, console := ClassesOn(AuthServer), ClassesOn(AdminConsole)

	assert.Contains(t, auth, "auth-client")
	assert.NotContains(t, console, "auth-client")
	assert.Contains(t, console, "app-shell")
	assert.NotContains(t, auth, "app-shell")
	assert.Contains(t, auth, "button")
	assert.Contains(t, console, "button")
}

// A copy the caller changes leaves the contract as it was.
func TestStylingContract_TheListsAnswerCopies(t *testing.T) {
	Variables()[0] = "--changed"
	PagesOn(AuthServer)[0] = "changed"
	ClassesOn(AuthServer)[0] = "changed"

	assert.Equal(t, "--color-canvas", Variables()[0])
	assert.Equal(t, "sign-in", PagesOn(AuthServer)[0])
	assert.Equal(t, "auth-page", ClassesOn(AuthServer)[0])
}

func TestPageName_IsTheTextOfThePagesDataPageTemplate(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{"a page naming itself", `{{define "data-page"}}sign-in{{end}}{{define "body"}}<p>x</p>{{end}}`, "sign-in"},
		{"space around the name", "{{define \"data-page\"}}\n  account-profile \n{{end}}", "account-profile"},
		{"a page defining none", `{{define "body"}}<p>x</p>{{end}}`, ""},
		{"an action in the template", `{{define "data-page"}}sign-{{ .step }}{{end}}`, ""},
		{"an empty template", `{{define "data-page"}}{{end}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := template.New("page").Parse(tc.src)
			require.NoError(t, err)

			assert.Equal(t, tc.want, PageName(parsed))
		})
	}
}

func distinct(values []string) map[string]bool {
	set := map[string]bool{}
	for _, v := range values {
		set[v] = true
	}
	return set
}
