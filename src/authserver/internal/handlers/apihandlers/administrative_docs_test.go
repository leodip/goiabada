package apihandlers

// The documentation of the administrative model, held to the code (#402 decision 15).
//
// The pages an operator and an integrator read are where the boundary is decided: the built-in
// permission table is what an operator consults before granting one, the audit-log page is where an
// alert rule is written from, and the REST API page is where an integration learns which error codes
// it must handle. Each names facts the code owns, the administrative set, the seeded descriptions,
// the audit catalog and the error codes, and a page naming one the code does not hold, or leaving
// out one the model rests on, misleads with nothing going red. So each section is held to the code
// in both directions it can drift: every name it uses is live, and every name the model rests on
// is there.
//
// It reads files and nothing else.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root.
const (
	restAPIPage              = "site/src/content/docs/reference/rest-api.mdx"
	resourcesPermissionsPage = "site/src/content/docs/concepts/resources-and-permissions.mdx"
	usersGroupsPage          = "site/src/content/docs/concepts/users-and-groups.mdx"
	auditLogPage             = "site/src/content/docs/concepts/audit-log.mdx"
	kubernetesPage           = "site/src/content/docs/deploy/kubernetes.mdx"
)

// docSection is one section of a page: from its heading line to the next heading of the same level
// or above, headings inside a code fence not counting.
type docSection struct{ page, heading string }

// seededPermissionDescriptions is the description each built-in authserver permission is seeded
// with: #402 decision 3's wording for the four it rewrote, and the unchanged wording of the three
// it kept. The data tier's migration 000058 test pins the same strings against the seed.
var seededPermissionDescriptions = map[string]string{
	builtin.ManageAccountPermissionIdentifier:   "View and update user account data for the current user",
	builtin.ManagePermissionIdentifier:          "Full administration, including administrators and administrative permissions",
	builtin.AdminReadPermissionIdentifier:       "Read-only access to all admin API endpoints",
	builtin.ManageUsersPermissionIdentifier:     "Manage users and groups that are not administrators, and their non-administrative permissions",
	builtin.ManageClientsPermissionIdentifier:   "Manage OAuth2 clients that are not administrators",
	builtin.ManageSettingsPermissionIdentifier:  "Manage system settings, except email and audit logging, and signing keys",
	builtin.BrowserSessionsPermissionIdentifier: "Read and write admin console browser sessions",
}

// The patterns a section's names are read with, each capturing the name.
var (
	// docAuditEvent is a backticked snake_case identifier, the spelling of every audit event.
	docAuditEvent = regexp.MustCompile("`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")
	// docErrorCode is a backticked UPPER_SNAKE identifier, the spelling of every API error code.
	docErrorCode = regexp.MustCompile("`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")
	// docErrorCodeItem is an error code leading a list item, the shape of the REST API page's list
	// of codes, which also names the UPPER_SNAKE convention itself in backticks.
	docErrorCodeItem = regexp.MustCompile("(?m)^- `([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")
	// docScopeRequest is a token request's scope parameter on the authserver resource, as a curl
	// example spells it.
	docScopeRequest = regexp.MustCompile(`scope=(` + builtin.AuthServerResourceIdentifier + `:[a-z][a-z0-9-]*)`)
	// docAuthServerScope is a backticked scope on the authserver resource.
	docAuthServerScope = regexp.MustCompile("`(" + builtin.AuthServerResourceIdentifier + ":[a-z][a-z0-9-]*)`")
)

// docNames is one check of a section's names: every name pattern captures in it is in live, and
// every name in want appears.
type docNames struct {
	section docSection
	pattern *regexp.Regexp
	// kind names what pattern reads, in a failure.
	kind string
	live map[string]bool
	want []string
}

// administrativeIdentifiers is the built-in authserver permissions the administrative set names,
// by permission identifier, as the policy reads it.
func administrativeIdentifiers() map[string]bool {
	administrative := make(map[string]bool)
	for _, identifier := range builtin.AuthServerPermissionIdentifiers() {
		if permissions.IsAdministrativeScope(builtin.AuthServerResourceIdentifier + ":" + identifier) {
			administrative[identifier] = true
		}
	}
	return administrative
}

// The built-in permission table says, for each built-in authserver permission, the description it
// is seeded with and whether it is administrative, as the policy's set has it: an operator choosing
// a permission to grant reads the boundary there (#402 decisions 2, 3 and 15).
func TestAdministrativeDocs_TheBuiltInPermissionTableIsTheSeedAndThePolicy(t *testing.T) {
	assertBuiltInPermissionTable(t, filepath.Dir(guard.SourceRoot(t)),
		docSection{resourcesPermissionsPage, "## System-level resource"},
		builtin.AuthServerPermissionIdentifiers(), seededPermissionDescriptions, administrativeIdentifiers())
}

// Every audit event, error code and authserver scope the administrative model's sections name is
// live, and each section names those the model rests on: the three events an operator alerts on,
// the two codes the policy and the guard answer beside the route gate's, and every scope the
// granular-scope section describes (#402 decision 15).
func TestAdministrativeDocs_NameWhatTheModelRestsOn(t *testing.T) {
	events := make(map[string]bool)
	for _, event := range audit.EventTypes() {
		events[event] = true
	}
	codes := make(map[string]bool, len(apiErrorCodes))
	for code := range apiErrorCodes {
		codes[code] = true
	}
	scopes := make(map[string]bool)
	for _, identifier := range builtin.AuthServerPermissionIdentifiers() {
		scopes[builtin.AuthServerResourceIdentifier+":"+identifier] = true
	}

	assertDocNames(t, filepath.Dir(guard.SourceRoot(t)), []docNames{
		{
			section: docSection{auditLogPage, "## Events to alert on"},
			pattern: docAuditEvent, kind: "audit event", live: events,
			want: []string{"administrator_change_refused", "administrative_permission_changed", "viewed_client_secret"},
		},
		{
			section: docSection{restAPIPage, "## Error responses"},
			pattern: docErrorCodeItem, kind: "error code", live: codes,
			want: []string{"INSUFFICIENT_SCOPE", "MANAGE_SCOPE_REQUIRED", "LAST_ADMINISTRATOR"},
		},
		{
			section: docSection{restAPIPage, "### Granular Admin API scopes"},
			pattern: docErrorCode, kind: "error code", live: codes,
			want: []string{"MANAGE_SCOPE_REQUIRED", "LAST_ADMINISTRATOR"},
		},
		{
			section: docSection{restAPIPage, "### Granular Admin API scopes"},
			pattern: docAuthServerScope, kind: "scope", live: scopes,
			want: []string{
				"authserver:manage", "authserver:admin-read", "authserver:manage-users",
				"authserver:manage-clients", "authserver:manage-settings",
			},
		},
		{
			section: docSection{restAPIPage, "#### Get client secret"},
			pattern: docAuditEvent, kind: "audit event", live: events,
			want: []string{"viewed_client_secret"},
		},
		{
			section: docSection{usersGroupsPage, "## The last administrator"},
			pattern: docErrorCode, kind: "error code", live: codes,
			want: []string{"LAST_ADMINISTRATOR"},
		},
	})
}

// The deployment guides' way back into a locked-out admin console sets the admin console's client
// secret through the admin API. That client is an administrator, so only a token with
// authserver:manage writes to it, and a procedure requesting any other scope ends in 403
// MANAGE_SCOPE_REQUIRED at the moment an operator has no other way in (#402 decisions 1 and 15).
// The Docker and native-binaries pages link to this one rather than repeat it.
func TestAdministrativeDocs_TheConsoleLockoutRecoveryRequestsManage(t *testing.T) {
	assertScopeRequests(t, filepath.Dir(guard.SourceRoot(t)),
		docSection{kubernetesPage, "#### The admin console's client secret"},
		builtin.AuthServerResourceIdentifier+":"+builtin.ManagePermissionIdentifier)
}

func TestAdministrativeDocs_ARecoveryRequestingAGranularScopeFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/deploy.mdx", "#### Client secret\n\n"+
		"```bash\ncurl -d scope=authserver:manage-clients\ncurl -d scope=authserver:manage\n```\n\n"+
		"#### Next\n\n-d scope=authserver:admin-read\n")

	report := guard.Run(func(r guard.Reporter) {
		assertScopeRequests(r, root, docSection{"site/deploy.mdx", "#### Client secret"}, "authserver:manage")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{"site/deploy.mdx: #### Client secret requests scope=authserver:manage-clients, want authserver:manage"}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAdministrativeDocs_ARecoveryRequestingNoScopeStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/deploy.mdx", "#### Client secret\n\nUse the admin console.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertScopeRequests(r, root, docSection{"site/deploy.mdx", "#### Client secret"}, "authserver:manage")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "requests no authserver scope") {
		t.Errorf("a section requesting no scope did not stop the check: %+v", report)
	}
}

func TestAdministrativeDocs_ATableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/permissions.mdx", "## System-level resource\n\n"+
		"| Permission identifier | Description | Administrative |\n"+
		"|---|---|---|\n"+
		"| `reader` | Reads | No |\n"+
		"| `writer` | Writes everything | No |\n"+
		"| `stranger` | Not built in | No |\n\n"+
		"## Next\n\n| `admin` | Administers | Yes |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertBuiltInPermissionTable(r, root, docSection{"site/permissions.mdx", "## System-level resource"},
			[]string{"reader", "writer", "admin"},
			map[string]string{"reader": "Reads", "writer": "Writes", "admin": "Administers"},
			map[string]bool{"writer": true, "admin": true})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		`site/permissions.mdx: ## System-level resource describes writer as "Writes everything", but it is seeded as "Writes"`,
		"site/permissions.mdx: ## System-level resource says writer is not administrative, but the policy's set holds it",
		"site/permissions.mdx: ## System-level resource lists stranger, which is not a built-in authserver permission",
		"site/permissions.mdx: ## System-level resource does not list admin",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAdministrativeDocs_ASectionNamingTheWrongNamesFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Events to alert on\n\n"+
		"| `administrator_change_refused` | refused |\n"+
		"| `administrator_changed` | misspelt |\n\n"+
		"```text\n# not a heading\n`still_inside`\n```\n\n"+
		"### A subsection is still the section\n\n`nested_event`\n\n"+
		"## Next\n\n`viewed_client_secret`\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocNames(r, root, []docNames{{
			section: docSection{"site/audit.mdx", "## Events to alert on"},
			pattern: docAuditEvent, kind: "audit event",
			live: map[string]bool{"administrator_change_refused": true, "still_inside": true, "viewed_client_secret": true},
			want: []string{"administrator_change_refused", "viewed_client_secret"},
		}})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/audit.mdx: ## Events to alert on names the audit event administrator_changed, which the code does not hold",
		"site/audit.mdx: ## Events to alert on names the audit event nested_event, which the code does not hold",
		"site/audit.mdx: ## Events to alert on does not name the audit event viewed_client_secret",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAdministrativeDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/audit.mdx", "## Events worth alerting on\n\n`viewed_client_secret`\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDocNames(r, root, []docNames{{
			section: docSection{"site/audit.mdx", "## Events to alert on"},
			pattern: docAuditEvent, kind: "audit event",
			live: map[string]bool{"viewed_client_secret": true}, want: []string{"viewed_client_secret"},
		}})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Events to alert on") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestAdministrativeDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/permissions.mdx", "## System-level resource\n\nThe table moved.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertBuiltInPermissionTable(r, root, docSection{"site/permissions.mdx", "## System-level resource"},
			[]string{"reader"}, map[string]string{"reader": "Reads"}, map[string]bool{})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

// assertBuiltInPermissionTable is the reporting half of the built-in permission table's check: one
// failure per row whose description or administrative cell disagrees with the code, per row naming
// no built-in permission, and per built-in permission with no row; a stop for a section not found
// or holding no table.
func assertBuiltInPermissionTable(r guard.Reporter, root string, section docSection,
	builtIn []string, descriptions map[string]string, administrative map[string]bool) {
	r.Helper()
	text, err := docSectionText(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	rows := docTableRows(text)
	if len(rows) == 0 {
		r.Fatalf("%s: %s holds no table of the built-in permissions", section.page, section.heading)
		return
	}

	listed := make(map[string]bool)
	for _, cells := range rows {
		if len(cells) != 3 {
			r.Errorf("%s: %s has a row of %d cells, want identifier, description and administrative: %q",
				section.page, section.heading, len(cells), cells)
			continue
		}
		identifier := strings.Trim(cells[0], "`")
		if !slices.Contains(builtIn, identifier) {
			r.Errorf("%s: %s lists %s, which is not a built-in authserver permission", section.page, section.heading, identifier)
			continue
		}
		listed[identifier] = true
		if cells[1] != descriptions[identifier] {
			r.Errorf("%s: %s describes %s as %q, but it is seeded as %q",
				section.page, section.heading, identifier, cells[1], descriptions[identifier])
		}
		switch says := cells[2]; {
		case says != "Yes" && says != "No":
			r.Errorf("%s: %s says %q of whether %s is administrative, want Yes or No",
				section.page, section.heading, says, identifier)
		case says == "Yes" && !administrative[identifier]:
			r.Errorf("%s: %s says %s is administrative, but the policy's set does not hold it",
				section.page, section.heading, identifier)
		case says == "No" && administrative[identifier]:
			r.Errorf("%s: %s says %s is not administrative, but the policy's set holds it",
				section.page, section.heading, identifier)
		}
	}
	for _, identifier := range builtIn {
		if !listed[identifier] {
			r.Errorf("%s: %s does not list %s", section.page, section.heading, identifier)
		}
	}
}

// assertScopeRequests is the reporting half of the recovery procedure's check: one failure per
// token request in the section naming an authserver scope other than want; a stop for a section not
// found or requesting no authserver scope, since a check that read no request proves nothing.
func assertScopeRequests(r guard.Reporter, root string, section docSection, want string) {
	r.Helper()
	text, err := docSectionText(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	matches := docScopeRequest.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		r.Fatalf("%s: %s requests no authserver scope", section.page, section.heading)
		return
	}
	for _, match := range matches {
		if match[1] != want {
			r.Errorf("%s: %s requests scope=%s, want %s", section.page, section.heading, match[1], want)
		}
	}
}

// assertDocNames is the reporting half of the name checks: one failure per name a section uses that
// the code does not hold, and per name the model rests on that it leaves out; a stop for a section
// not found.
func assertDocNames(r guard.Reporter, root string, checks []docNames) {
	r.Helper()
	for _, check := range checks {
		text, err := docSectionText(root, check.section)
		if err != nil {
			r.Fatalf("%v", err)
			return
		}
		assertNamesIn(r, text, check)
	}
}

// assertNamesIn is one of assertDocNames' checks over text, read from check's section by its
// caller: a text that is no Markdown section, such as an openapi.yaml description, is checked the
// same way.
func assertNamesIn(r guard.Reporter, text string, check docNames) {
	r.Helper()
	named := make(map[string]bool)
	for _, match := range check.pattern.FindAllStringSubmatch(text, -1) {
		name := match[1]
		if named[name] {
			continue
		}
		named[name] = true
		if !check.live[name] {
			r.Errorf("%s: %s names the %s %s, which the code does not hold",
				check.section.page, check.section.heading, check.kind, name)
		}
	}
	for _, name := range check.want {
		if !named[name] {
			r.Errorf("%s: %s does not name the %s %s", check.section.page, check.section.heading, check.kind, name)
		}
	}
}

// docSectionText is the section's text, without its heading line: from the line after the heading
// to the next heading of the same level or above. A line inside a code fence is never a heading,
// so a shell comment in an example does not end the section.
func docSectionText(root string, section docSection) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(section.page)))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", section.page, err)
	}
	level := docHeadingLevel(section.heading)
	var body []string
	inFence, inSection := false, false
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if !inFence {
			if inSection {
				if headingLevel := docHeadingLevel(line); headingLevel > 0 && headingLevel <= level {
					return strings.Join(body, "\n"), nil
				}
			} else if strings.TrimRight(line, " \r") == section.heading {
				inSection = true
				continue
			}
		}
		if inSection {
			body = append(body, line)
		}
	}
	if !inSection {
		return "", fmt.Errorf("%s has no section headed %q", section.page, section.heading)
	}
	return strings.Join(body, "\n"), nil
}

// docHeadingLevel is the number of #s a Markdown heading line opens with, or 0 for any other line.
func docHeadingLevel(line string) int {
	level := len(line) - len(strings.TrimLeft(line, "#"))
	if level == 0 || !strings.HasPrefix(line[level:], " ") {
		return 0
	}
	return level
}

// docTableRows is the body rows of the first Markdown table in text, each trimmed cell in order:
// the header row and the delimiter row under it are left out.
func docTableRows(text string) [][]string {
	var rows [][]string
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if !inTable {
			inTable = true // the header row
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the delimiter row
		}
		rows = append(rows, cells)
	}
	return rows
}

// writeDocFixture writes content to root/name, creating its directory.
func writeDocFixture(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
