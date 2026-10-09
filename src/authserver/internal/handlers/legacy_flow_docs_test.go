package handlers

// The Legacy flows pages, held to the code that answers each flow (#522).
//
// Implicit lists the parameters the browser comes back with, which is what an app still on that
// flow reads its tokens from. The table is held to what issueImplicitTokens writes for a response
// carrying every token, in both directions: a parameter the auth server never sends fails, and so
// does one it sends that the table leaves out.
//
// ROPC lists the errors the password grant answers, each with its status. The token endpoint runs
// with the real writer and the real validator over a stubbed database, driven through every way a
// password grant is refused, and each error code it answers must have a row naming its status, with
// no row for a code it never answers.
//
// It reads files, and runs the implicit response writer and the token endpoint.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root.
const (
	implicitPage = "site/src/content/docs/legacy-flows/implicit.mdx"
	ropcPage     = "site/src/content/docs/legacy-flows/ropc.mdx"
)

var (
	implicitAnswerSection = conceptSection{implicitPage, "## What comes back"}
	ropcErrorsSection     = conceptSection{ropcPage, "## Errors"}
)

// implicitAnswerParameters is every parameter an implicit response can carry, read off the
// fragment issueImplicitTokens writes for a response with an access token, an ID token, a scope and
// a state.
func implicitAnswerParameters(t *testing.T) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/issue", nil)
	rr := httptest.NewRecorder()
	err := issueImplicitTokens(rr, req, nil, "", "https://app.example.com/callback", "af0ifjsldkj",
		&issuance.ImplicitGrantResponse{
			AccessToken: "an-access-token",
			IdToken:     "an-id-token",
			TokenType:   "Bearer",
			ExpiresIn:   300,
			Scope:       "openid email",
		})
	if err != nil {
		t.Fatalf("writing the implicit response: %v", err)
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || location.Fragment == "" {
		t.Fatalf("the implicit response answered %d with Location %q, not a fragment", rr.Code,
			rr.Header().Get("Location"))
	}
	var names []string
	for _, field := range strings.Split(location.Fragment, "&") {
		name, _, _ := strings.Cut(field, "=")
		names = append(names, name)
	}
	return names
}

// The table on Implicit names every parameter the implicit response carries, and nothing else.
func TestLegacyFlowDocs_TheImplicitAnswerTableIsWhatTheResponseCarries(t *testing.T) {
	assertNamedTable(t, filepath.Dir(guard.SourceRoot(t)), implicitAnswerSection, "Parameter",
		implicitAnswerParameters(t), "the response")
}

// fixedPermissionChecker answers every permission question with held.
type fixedPermissionChecker struct{ held bool }

func (c fixedPermissionChecker) UserHasScopePermission(context.Context, int64, string) (bool, error) {
	return c.held, nil
}

// passwordRefusal is one way to drive the token endpoint into refusing a password grant.
type passwordRefusal struct {
	name string
	// ropcOff leaves the flow off for the client and globally; every other refusal has it on.
	ropcOff bool
	// public makes the client public; the others are confidential, with clientSecret as its secret.
	public bool
	form   url.Values
	// user is the account the username names, or nil for none.
	user *record.User
}

// passwordRefusals is every branch on which the password grant answers an error after the client
// is found: the flow off, a missing username, a wrong client secret, an unknown account, a wrong
// password, a disabled account, an account with two-factor authentication, a scope the user does
// not hold, and an administrative scope the client may not request.
func passwordRefusals(t *testing.T) []passwordRefusal {
	t.Helper()
	hash, err := passwordhash.Hash("the-password")
	if err != nil {
		t.Fatalf("hashing the password: %v", err)
	}
	user := func(edit func(*record.User)) *record.User {
		u := &record.User{Id: 42, Subject: "f2a3c1e0-0000-4000-8000-000000000042", Email: "user@example.com",
			Enabled: true, PasswordHash: hash}
		if edit != nil {
			edit(u)
		}
		return u
	}
	form := func(edit func(url.Values)) url.Values {
		values := url.Values{
			"grant_type":    {"password"},
			"client_id":     {"legacy-app"},
			"client_secret": {"the-client-secret"},
			"username":      {"user@example.com"},
			"password":      {"the-password"},
		}
		if edit != nil {
			edit(values)
		}
		return values
	}
	return []passwordRefusal{
		{name: "the flow off", ropcOff: true, form: form(nil), user: user(nil)},
		{name: "no username", form: form(func(v url.Values) { v.Del("username") })},
		{name: "a wrong client secret", form: form(func(v url.Values) { v.Set("client_secret", "wrong") })},
		{name: "a public client sending a secret", public: true, form: form(nil)},
		{name: "an unknown account", form: form(nil)},
		{name: "a wrong password", form: form(func(v url.Values) { v.Set("password", "wrong") }), user: user(nil)},
		{name: "a disabled account", form: form(nil), user: user(func(u *record.User) { u.Enabled = false })},
		{name: "two-factor authentication", form: form(nil), user: user(func(u *record.User) { u.OTPEnabled = true })},
		{name: "a scope the user does not hold", form: form(func(v url.Values) { v.Set("scope", "openid product-api:write") }),
			user: user(nil)},
		{name: "an administrative scope", form: form(func(v url.Values) { v.Set("scope", "openid authserver:manage") }),
			user: user(nil)},
	}
}

// passwordGrantErrors is the status the token endpoint answers each error code of a password grant
// with, read by driving it through every refusal. A code answered with two statuses is a failure of
// its own, since the page's table gives one status per code.
func passwordGrantErrors(t *testing.T) map[string]string {
	t.Helper()
	secret, err := testDataCipher.Encrypt("the-client-secret")
	if err != nil {
		t.Fatalf("encrypting the client secret: %v", err)
	}
	answered := make(map[string]string)
	for _, refusal := range passwordRefusals(t) {
		on := !refusal.ropcOff
		client := &record.Client{Id: 7, ClientIdentifier: "legacy-app", Enabled: true, IsPublic: refusal.public,
			ResourceOwnerPasswordCredentialsEnabled: &on}
		if !refusal.public {
			client.ClientSecretEncrypted = secret
		}

		database := datamocks.NewDatabase(t)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "legacy-app").Return(client, nil).Maybe()
		database.On("GetUserByEmail", mock.Anything, mock.Anything, "user@example.com").Return(refusal.user, nil).Maybe()
		database.On("UserLoadPermissions", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		database.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "product-api").
			Return(&record.Resource{Id: 3, ResourceIdentifier: "product-api"}, nil).Maybe()
		database.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(3)).
			Return([]record.Permission{{Id: 5, PermissionIdentifier: "write", ResourceId: 3}}, nil).Maybe()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		handler := HandleTokenPost(render.New(nil), datamocks.NewDatabase(t), handlersmocks.NewTokenIssuer(t),
			protocolvalidation.NewTokenValidator(database, nil, fixedPermissionChecker{held: false}, testDataCipher),
			auditLogger, noCredentialFailures{}, testTokenMetrics())

		req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(refusal.form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withSettings(req, &record.Settings{})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error == "" {
			t.Fatalf("%s: the endpoint answered %d with %q, not an error", refusal.name, rr.Code, rr.Body.String())
		}
		status := strconv.Itoa(rr.Code)
		if earlier, ok := answered[body.Error]; ok && earlier != status {
			t.Fatalf("%s: the endpoint answers %s with %s here and %s elsewhere", refusal.name, body.Error, status, earlier)
		}
		answered[body.Error] = status
	}
	return answered
}

// The error table on ROPC has one row per error code the password grant answers, with the status it
// answers it with, and none for a code it never answers.
func TestLegacyFlowDocs_TheROPCErrorTableIsWhatTheGrantAnswers(t *testing.T) {
	assertValueTable(t, filepath.Dir(guard.SourceRoot(t)), ropcErrorsSection, "`error`", "Status",
		passwordGrantErrors(t), "the password grant")
}

// A table of names held by its own column header, not only Field: the reporting half the field
// tables share, read through the Parameter column the implicit page uses.
func TestLegacyFlowDocs_AParameterTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/implicit.mdx", "## What comes back\n\n"+
		"| Parameter | When |\n|---|---|\n"+
		"| `access_token` | Always |\n"+
		"| `refresh_token` | Never sent |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNamedTable(r, root, conceptSection{"site/implicit.mdx", "## What comes back"}, "Parameter",
			[]string{"access_token", "state"}, "the response")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/implicit.mdx: ## What comes back row 2 names refresh_token, which the response never carries",
		"site/implicit.mdx: ## What comes back has no row for state",
	}
	if strings.Join(report.Errors, "\n") != strings.Join(want, "\n") {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestLegacyFlowDocs_AParameterTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/implicit.mdx", "## What comes back\n\n"+
		"| Parameter | When |\n|---|---|\n| `access_token` | Always |\n| `state` | When sent |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNamedTable(r, root, conceptSection{"site/implicit.mdx", "## What comes back"}, "Parameter",
			[]string{"access_token", "state"}, "the response")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestLegacyFlowDocs_AParameterTableWithoutItsColumnStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/implicit.mdx", "## What comes back\n\n"+
		"| Field | When |\n|---|---|\n| `access_token` | Always |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertNamedTable(r, root, conceptSection{"site/implicit.mdx", "## What comes back"}, "Parameter",
			[]string{"access_token"}, "the response")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "Parameter") {
		t.Errorf("a table without its Parameter column did not stop the check naming it: %+v", report)
	}
}
