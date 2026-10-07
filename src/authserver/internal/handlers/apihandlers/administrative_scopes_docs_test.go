package apihandlers

// The documentation of which clients may request the administrative scopes, held to the code (#499
// decisions 5, 7, 9 and 11).
//
// An operator learns from the clients page and the REST API page which clients may request the six
// administrative scopes and how to allow one, an integrator learns from the endpoints page what a
// refused client is answered, and an alert rule is written from the audit-log page. Each names facts
// the code owns, the scopes, the route, the response field, the error codes, the refusal's sentence
// and the audit events, and a page naming one the code does not hold, or leaving out one the
// allowance rests on, misleads with nothing going red. The Account API setup is held too: it told
// the reader to obtain a token with client credentials, which the Account API refuses.
//
// It reads files and nothing else.

import (
	"context"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

// The pages, relative to the repository root, beside administrative_docs_test.go's.
const (
	clientsPage   = "site/src/content/docs/concepts/clients.mdx"
	endpointsPage = "site/src/content/docs/reference/endpoints.mdx"
)

// The sections the allowance is described in.
var (
	allowanceRouteSection   = docSection{restAPIPage, "#### Switch the administrative scopes allowance"}
	allowanceRESTSection    = docSection{restAPIPage, "### Clients that may request the administrative scopes"}
	allowanceClientsSection = docSection{clientsPage, "### Administrative scopes"}
	accountAPISetupSection  = docSection{restAPIPage, "### Account API access"}
	clientCredentialsSetup  = docSection{restAPIPage, "### Setting up API access"}
	authorizeSection        = docSection{endpointsPage, "## /auth/authorize (GET or POST)"}
	tokenSection            = docSection{endpointsPage, "## /auth/token (POST)"}
)

// The patterns the allowance's sections are read with, each capturing the name.
var (
	// docJSONField is a backticked camelCase identifier, the spelling of every field of the API's
	// JSON bodies that is more than one word.
	docJSONField = regexp.MustCompile("`([a-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+)`")
	// docAdminRoute is an Admin API route as a page spells it, in a code block or in backticks.
	docAdminRoute = regexp.MustCompile(`(?:PUT|GET|POST|DELETE) (/api/v1/admin/[A-Za-z0-9{}/_-]+)`)
)

// administrativeScopes is the six administrative scopes, as resource:permission, in the order the
// built-in identifiers list them.
func administrativeScopes() []string {
	var scopes []string
	for _, identifier := range builtin.AuthServerPermissionIdentifiers() {
		scope := builtin.AuthServerResourceIdentifier + ":" + identifier
		if permissions.IsAdministrativeScope(scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// clientJSONFields is every JSON field of the client response and the allowance's request.
func clientJSONFields() map[string]bool {
	fields := make(map[string]bool)
	for _, value := range []any{api.ClientResponse{}, api.UpdateClientAdministrativeScopesRequest{}} {
		typ := reflect.TypeOf(value)
		for i := range typ.NumField() {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			fields[name] = true
		}
	}
	return fields
}

// openAPIPaths is every path openapi.yaml documents, which the OpenAPI contract lint holds to the
// routes the server registers.
func openAPIPaths(t *testing.T) map[string]bool {
	t.Helper()
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(web.OpenAPISpec(), &doc); err != nil {
		t.Fatalf("parsing %s: %v", openAPISpecPath, err)
	}
	paths := make(map[string]bool, len(doc.Paths))
	for path := range doc.Paths {
		paths[path] = true
	}
	return paths
}

// Every scope, route, field, error code and audit event the allowance's sections name is live, and
// each section names those the allowance rests on: the clients page and the REST API page the six
// scopes it covers, the route's section its path, its field, the two codes its ceiling and the admin
// console's client answer and its audit event, and the events to alert on both new events (#499
// decisions 5 and 9).
func TestAdministrativeScopesDocs_NameWhatTheAllowanceRestsOn(t *testing.T) {
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
			want: []string{"updated_client_administrative_scopes", "administrative_scope_refused"},
		},
		{
			section: allowanceClientsSection,
			pattern: docAuthServerScope, kind: "scope", live: scopes,
			want: administrativeScopes(),
		},
		{
			section: allowanceRESTSection,
			pattern: docAuthServerScope, kind: "scope", live: scopes,
			want: administrativeScopes(),
		},
		{
			section: allowanceRouteSection,
			pattern: docAdminRoute, kind: "route", live: openAPIPaths(t),
			want: []string{"/api/v1/admin/clients/{id}/administrative-scopes"},
		},
		{
			section: allowanceRouteSection,
			pattern: docJSONField, kind: "client field", live: clientJSONFields(),
			want: []string{"administrativeScopesAllowed"},
		},
		{
			section: allowanceRouteSection,
			pattern: docErrorCode, kind: "error code", live: codes,
			want: []string{"MANAGE_SCOPE_REQUIRED", "VALIDATION_ERROR"},
		},
		{
			section: allowanceRouteSection,
			pattern: docAuditEvent, kind: "audit event", live: events,
			want: []string{"updated_client_administrative_scopes"},
		},
	})
}

// The clients page tells an operator which switch allows a client, as the admin console labels it,
// and what a client that is not allowed is answered: invalid_scope at the authorization endpoint and
// on the password grant, invalid_grant when it redeems a code or refreshes (#499 decision 7, #519
// decision 8).
func TestAdministrativeScopesDocs_TheClientsPageNamesTheSwitchAndTheRefusal(t *testing.T) {
	label := i18n.T(context.Background(), "adminconsole.admin_clients.settings.field.administrative_scopes_allowed")

	assertSectionText(t, filepath.Dir(guard.SourceRoot(t)), allowanceClientsSection,
		[]string{"**" + label + "**", "`invalid_scope`", "`invalid_grant`"}, nil)
}

// The endpoints page quotes what a client that may not request an administrative scope is answered,
// as the code answers it: the authorization endpoint's invalid_scope, and on the token endpoint the
// password grant's invalid_scope, the authorization code grant's invalid_grant with the same
// sentence, and the refresh token grant's invalid_grant carrying it (#499 decision 7).
func TestAdministrativeScopesDocs_TheEndpointsPageQuotesTheRefusal(t *testing.T) {
	refusal := protocolvalidation.AdministrativeScopeRefusal([]string{"authserver:manage"}).Description()
	root := filepath.Dir(guard.SourceRoot(t))

	assertSectionText(t, root, authorizeSection, []string{"`invalid_scope`", refusal}, nil)
	assertSectionText(t, root, tokenSection,
		[]string{"`invalid_scope`", "`invalid_grant`", refusal, "Scope 'authserver:manage' is not recognized. " + refusal}, nil)
}

// The Account API takes a signed-in user's token, from the authorization code flow requesting
// authserver:manage-account, and refuses a client-credentials token, so the page's setup for it asks
// for the first and never the second, and the client-credentials setup no longer tells the reader to
// grant manage-account to a client (#499 decision 11).
func TestAdministrativeScopesDocs_TheAccountAPISetupUsesAUserToken(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))

	assertSectionText(t, root, accountAPISetupSection,
		[]string{"response_type=code", "authserver:manage-account", "grant_type=authorization_code"},
		[]string{"grant_type=client_credentials"})
	assertSectionText(t, root, clientCredentialsSetup, nil, []string{"manage-account"})
}

func TestAdministrativeScopesDocs_ASectionMissingOrHoldingTextFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/api.mdx", "### Account API\n\n"+
		"```bash\ncurl -d grant_type=client_credentials -d scope=authserver:manage-account\n```\n\n"+
		"### Next\n\nresponse_type=code\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionText(r, root, docSection{"site/api.mdx", "### Account API"},
			[]string{"authserver:manage-account", "response_type=code"}, []string{"grant_type=client_credentials"})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		`site/api.mdx: ### Account API does not say "response_type=code"`,
		`site/api.mdx: ### Account API says "grant_type=client_credentials"`,
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestAdministrativeScopesDocs_ASectionSayingWhatItShouldPasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/api.mdx", "### Account API\n\n"+
		"response_type=code&scope=authserver:manage-account\n\n### Next\n\ngrant_type=client_credentials\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionText(r, root, docSection{"site/api.mdx", "### Account API"},
			[]string{"authserver:manage-account", "response_type=code"}, []string{"grant_type=client_credentials"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a section saying what it should failed: %+v", report)
	}
}

func TestAdministrativeScopesDocs_AMissingSectionStopsTheTextCheck(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/api.mdx", "### Account API setup\n\nresponse_type=code\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionText(r, root, docSection{"site/api.mdx", "### Account API"}, []string{"response_type=code"}, nil)
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### Account API") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertSectionText is the reporting half of the text checks: one failure per text in present the
// section does not hold verbatim, and per text in absent it does; a stop for a section not found.
func assertSectionText(r guard.Reporter, root string, section docSection, present, absent []string) {
	r.Helper()
	text, err := docSectionText(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, want := range present {
		if !strings.Contains(text, want) {
			r.Errorf("%s: %s does not say %q", section.page, section.heading, want)
		}
	}
	for _, refused := range absent {
		if strings.Contains(text, refused) {
			r.Errorf("%s: %s says %q", section.page, section.heading, refused)
		}
	}
}
