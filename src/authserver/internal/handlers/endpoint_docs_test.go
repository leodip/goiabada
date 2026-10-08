package handlers

// The endpoint reference pages, held to the code that answers them (#522).
//
// The discovery document is what most client libraries configure themselves from, and the
// Discovery and JWKS page lists its fields for a reader who wants to know what each one says
// before they trust it. The fields are oidc.WellKnownConfig's, so the page's table is held to that
// struct in both directions: a field the document never carries fails, and so does one the table
// leaves out.
//
// The Logo and picture page tells a reader how long a browser or a proxy may keep each image, which
// is the Cache-Control header each handler sets. The handlers are driven over a stub database to
// read the header they answer with, and the page's section on each image must quote it.
//
// The Dynamic client registration page lists the fields a registration reads and the fields its
// answer carries, which are oidc.DynamicClientRegistrationRequest's and
// oidc.DynamicClientRegistrationResponse's, held both ways like the discovery table. Its error table
// is held to what the handler answers: the handler is driven through every refusal it has, and each
// error code it writes must have a row naming its status, with no row for a code it never writes.
//
// The Logout page gives the protected header an encrypted id_token_hint carries. A relying party
// copies it into its own JOSE library, so the table is held to the header idtokenhint.Encrypt writes,
// which is the one Decrypt is tested to take, member for member and value for value.
//
// It reads files, and runs the two image handlers and the registration handler over a stub
// database.

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/idtokenhint"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root.
const (
	discoveryPage      = "site/src/content/docs/reference/endpoints/discovery-and-jwks.mdx"
	logoAndPicturePage = "site/src/content/docs/reference/endpoints/logo-and-picture.mdx"
	registrationPage   = "site/src/content/docs/reference/endpoints/dynamic-client-registration.mdx"
	logoutPage         = "site/src/content/docs/reference/endpoints/logout.mdx"
	userInfoPage       = "site/src/content/docs/reference/endpoints/userinfo.mdx"
)

var (
	discoveryFieldsSection     = conceptSection{discoveryPage, "### The discovery document"}
	clientLogoSection          = conceptSection{logoAndPicturePage, "### The client logo"}
	profilePictureSection      = conceptSection{logoAndPicturePage, "### The profile picture"}
	registrationRequestSection = conceptSection{registrationPage, "### The request"}
	registrationAnswerSection  = conceptSection{registrationPage, "### The answer"}
	registrationErrorsSection  = conceptSection{registrationPage, "### Errors"}
	hintHeaderSection          = conceptSection{logoutPage, "### Encrypting the hint"}
	readClaimsSection          = conceptSection{userInfoPage, "## Read a user's claims"}
)

// discoveryFields is every field the discovery document can carry, as its JSON names it, in the
// order oidc.WellKnownConfig declares them.
func discoveryFields() []string {
	return jsonFields(oidc.WellKnownConfig{})
}

// jsonFields is every field a struct can carry on the wire, as its JSON tags name them, in the order
// the struct declares them.
func jsonFields(value any) []string {
	var fields []string
	typ := reflect.TypeOf(value)
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	return fields
}

// The discovery document's table on Discovery and JWKS has one row per field the auth server
// writes, and none for a field it never does.
func TestEndpointDocs_TheDiscoveryTableIsTheDocumentsFields(t *testing.T) {
	assertFieldTable(t, filepath.Dir(guard.SourceRoot(t)), discoveryFieldsSection, discoveryFields(), "the document")
}

func TestEndpointDocs_ADiscoveryTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/discovery.mdx", "### The discovery document\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| `issuer` | The issuer |\n"+
		"| `check_session_iframe` | Not a field |\n"+
		"| `issuer` | Twice |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertFieldTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer", "jwks_uri"}, "the document")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/discovery.mdx: ### The discovery document row 2 names check_session_iframe, which the document never carries",
		"site/discovery.mdx: ### The discovery document row 3 names issuer, which an earlier row already does",
		"site/discovery.mdx: ### The discovery document has no row for jwks_uri",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestEndpointDocs_ADiscoveryTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/discovery.mdx", "### The discovery document\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| `jwks_uri` | The key set |\n"+
		"| `issuer` | The issuer |\n\n"+
		"### Next\n\n| Field | Value |\n|---|---|\n| `other` | Another table |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertFieldTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer", "jwks_uri"}, "the document")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestEndpointDocs_AMissingDiscoverySectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/discovery.mdx", "### Discovery\n\n"+
		"| Field | Value |\n|---|---|\n| `issuer` | The issuer |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertFieldTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer"}, "the document")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### The discovery document") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestEndpointDocs_ADiscoveryTableWithoutItsFieldColumnStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/discovery.mdx", "### The discovery document\n\n"+
		"| Name | Value |\n|---|---|\n| `issuer` | The issuer |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertFieldTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer"}, "the document")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "Field") {
		t.Errorf("a table without its Field column did not stop the check naming it: %+v", report)
	}
}

// assertFieldTable is the reporting half of the field tables' checks: one failure per row naming a
// field the carrier never carries or one an earlier row named, and per field with no row; a stop
// for a section, table or column not found. carrier names what holds the fields, such as "the
// document", in the failure.
func assertFieldTable(r guard.Reporter, root string, section conceptSection, fields []string, carrier string) {
	r.Helper()
	assertNamedTable(r, root, section, "Field", fields, carrier)
}

// assertNamedTable is assertFieldTable for a table whose names sit under another column header,
// such as Parameter.
func assertNamedTable(r guard.Reporter, root string, section conceptSection, column string, fields []string,
	carrier string) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, column)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	named := make(map[string]bool)
	for i, row := range columns {
		field := row[0]
		switch {
		case named[field]:
			r.Errorf("%s: %s row %d names %s, which an earlier row already does", section.page, section.heading, i+1, field)
		case !slices.Contains(fields, field):
			r.Errorf("%s: %s row %d names %s, which %s never carries", section.page, section.heading, i+1, field, carrier)
		}
		named[field] = true
	}
	for _, field := range fields {
		if !named[field] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, field)
		}
	}
}

// clientLogoCacheControl is the Cache-Control HandleClientLogoGet answers a logo with.
func clientLogoCacheControl(t *testing.T) string {
	t.Helper()
	database := datamocks.NewDatabase(t)
	client := &record.Client{Id: 1, ClientIdentifier: "my-app"}
	database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "my-app").Return(client, nil)
	database.On("GetClientLogoByClientId", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(&record.ClientLogo{ClientId: 1, Logo: createTestLogoData(10, 10), ContentType: "image/png"}, nil)

	req := setChiURLParamForHandlers(httptest.NewRequest(http.MethodGet, "/client/logo/my-app", nil), "clientIdentifier", "my-app")
	rr := httptest.NewRecorder()
	HandleClientLogoGet(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("the logo handler answered %d", rr.Code)
	}
	return rr.Header().Get("Cache-Control")
}

// profilePictureCacheControl is the Cache-Control HandleProfilePictureGet answers a picture with.
func profilePictureCacheControl(t *testing.T) string {
	t.Helper()
	database := datamocks.NewDatabase(t)
	user := &record.User{Id: 1, Subject: "2bd9ff17-7cb1-4c11-8d6d-6a3e1a0f5a6b", Enabled: true}
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), user.Subject).Return(user, nil)
	database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(&record.UserProfilePicture{UserId: 1, Picture: createTestLogoData(10, 10), ContentType: "image/png"}, nil)

	req := setChiURLParamForHandlers(httptest.NewRequest(http.MethodGet, "/userinfo/picture/"+user.Subject, nil), "subject", user.Subject)
	rr := httptest.NewRecorder()
	HandleProfilePictureGet(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("the profile picture handler answered %d", rr.Code)
	}
	return rr.Header().Get("Cache-Control")
}

// Each image's section on Logo and picture quotes the Cache-Control its handler answers with: a
// logo cached for five minutes and revalidated by its ETag, a profile picture never cached.
func TestEndpointDocs_TheImageSectionsQuoteTheirCacheControl(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))

	assertSectionSays(t, root, clientLogoSection, []string{"`Cache-Control: " + clientLogoCacheControl(t) + "`"})
	assertSectionSays(t, root, profilePictureSection, []string{"`Cache-Control: " + profilePictureCacheControl(t) + "`"})
}

func TestEndpointDocs_ASectionNotQuotingTheHeaderFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/images.mdx", "### The client logo\n\n`Cache-Control: no-store`\n\n"+
		"### Next\n\n`Cache-Control: public, max-age=300`\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionSays(r, root, conceptSection{"site/images.mdx", "### The client logo"},
			[]string{"`Cache-Control: public, max-age=300`"})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{"site/images.mdx: ### The client logo does not say \"`Cache-Control: public, max-age=300`\""}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestEndpointDocs_ASectionQuotingTheHeaderPasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/images.mdx", "### The client logo\n\nIt carries `Cache-Control: public, max-age=300`.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionSays(r, root, conceptSection{"site/images.mdx", "### The client logo"},
			[]string{"`Cache-Control: public, max-age=300`"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a section quoting the header was refused: %+v", report)
	}
}

func TestEndpointDocs_AMissingImageSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/images.mdx", "### Client logo\n\n`Cache-Control: public, max-age=300`\n")

	report := guard.Run(func(r guard.Reporter) {
		assertSectionSays(r, root, conceptSection{"site/images.mdx", "### The client logo"},
			[]string{"`Cache-Control: public, max-age=300`"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### The client logo") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

// assertSectionSays is the reporting half of the quote checks: one failure per text the section does
// not hold verbatim; a stop for a section not found.
func assertSectionSays(r guard.Reporter, root string, section conceptSection, texts []string) {
	r.Helper()
	text, err := conceptSectionText(root, section)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, want := range texts {
		if !strings.Contains(text, want) {
			r.Errorf("%s: %s does not say %q", section.page, section.heading, want)
		}
	}
}

// The procedure on UserInfo has a client check the answer's sub against the ID token's before it reads
// a claim, and discard the answer when they differ, which OpenID Connect Core 5.3.2 requires of every
// client: the check is its own step, ahead of the step that reads the claims.
func TestEndpointDocs_TheUserInfoProcedureChecksTheSubjectFirst(t *testing.T) {
	root := filepath.Dir(guard.SourceRoot(t))
	check := "**Check `sub` before you use any claim.** It must be exactly the `sub` of the ID token you validated at sign-in."
	assertSectionSays(t, root, readClaimsSection, []string{
		check,
		"discard the whole answer and use none of its claims",
		"[OpenID Connect Core section 5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)",
	})

	text, err := conceptSectionText(root, readClaimsSection)
	if err != nil {
		t.Fatal(err)
	}
	if read := strings.Index(text, "Read the claims"); read < 0 || strings.Index(text, check) > read {
		t.Errorf("%s: %s reads the claims before it checks sub", readClaimsSection.page, readClaimsSection.heading)
	}
}

// The request table on Dynamic client registration has one row per field a registration reads, and
// none for a field the auth server ignores.
func TestEndpointDocs_TheRegistrationRequestTableIsTheFieldsItReads(t *testing.T) {
	assertFieldTable(t, filepath.Dir(guard.SourceRoot(t)), registrationRequestSection,
		jsonFields(oidc.DynamicClientRegistrationRequest{}), "a registration")
}

// The answer table on Dynamic client registration has one row per field a registration's answer
// can carry, and none for a field it never does.
func TestEndpointDocs_TheRegistrationAnswerTableIsTheAnswersFields(t *testing.T) {
	assertFieldTable(t, filepath.Dir(guard.SourceRoot(t)), registrationAnswerSection,
		jsonFields(oidc.DynamicClientRegistrationResponse{}), "the answer")
}

// registrationRefusal is one way to drive the registration handler into an error answer.
type registrationRefusal struct {
	name     string
	settings *record.Settings
	body     string
	// database stubs what the refusal reaches, or is nil for a refusal decided before any write.
	database func(*datamocks.Database)
}

// registrationRefusals is every branch on which HandleDynamicClientRegistrationPost answers an
// error: registration turned off, a body that is not JSON, metadata it refuses, a redirect URI it
// refuses, missing settings, and a write the database refuses.
func registrationRefusals() []registrationRefusal {
	on := &record.Settings{Id: 1, DynamicClientRegistrationEnabled: true}
	valid := `{"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none"}`
	return []registrationRefusal{
		{name: "registration off", settings: &record.Settings{Id: 1}, body: valid},
		{name: "a body that is not JSON", settings: on, body: `{`},
		{name: "an unsupported grant", settings: on, body: `{"grant_types":["password"]}`},
		{name: "a refused redirect URI", settings: on, body: `{"redirect_uris":["ftp://example.com/cb"]}`},
		{name: "no settings", body: valid},
		{name: "a refused write", settings: on, body: valid, database: func(database *datamocks.Database) {
			datamocks.ExpectRunInTransactionRefused(database, errs.New("the database is unavailable"))
		}},
	}
}

// registrationErrors is the status the registration handler answers each error code it writes with,
// read by driving it through every refusal. A code answered with two statuses is a failure of its
// own, since the page's table gives one status per code.
func registrationErrors(t *testing.T) map[string]string {
	t.Helper()
	answered := make(map[string]string)
	for _, refusal := range registrationRefusals() {
		database := datamocks.NewDatabase(t)
		if refusal.database != nil {
			refusal.database(database)
		}
		req := httptest.NewRequest(http.MethodPost, "/connect/register", strings.NewReader(refusal.body))
		req.Header.Set("Content-Type", "application/json")
		if refusal.settings != nil {
			req = req.WithContext(reqctx.WithSettings(req.Context(), refusal.settings))
		}
		rr := httptest.NewRecorder()
		HandleDynamicClientRegistrationPost(database, handlersmocks.NewAuditLogger(t), nil).ServeHTTP(rr, req)

		var body oidc.DynamicClientRegistrationError
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Error == "" {
			t.Fatalf("%s: the handler answered %d with %q, not an error", refusal.name, rr.Code, rr.Body.String())
		}
		status := strconv.Itoa(rr.Code)
		if earlier, ok := answered[body.Error]; ok && earlier != status {
			t.Fatalf("%s: the handler answers %s with %s here and %s elsewhere", refusal.name, body.Error, status, earlier)
		}
		answered[body.Error] = status
	}
	return answered
}

// The error table on Dynamic client registration has one row per error code the handler writes,
// with the status it answers it with, and none for a code it never writes.
func TestEndpointDocs_TheRegistrationErrorTableIsWhatTheHandlerAnswers(t *testing.T) {
	assertValueTable(t, filepath.Dir(guard.SourceRoot(t)), registrationErrorsSection, "`error`", "Status",
		registrationErrors(t), "the handler")
}

// hintHeader is the protected header idtokenhint.Encrypt writes on an encrypted id_token_hint, member
// by member.
func hintHeader(t *testing.T) map[string]string {
	t.Helper()
	jwe, err := idtokenhint.Encrypt("header.payload.signature", "a client secret")
	if err != nil {
		t.Fatalf("encrypting a hint: %v", err)
	}
	segment, _, _ := strings.Cut(jwe, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("the protected header is not base64url: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("the protected header %s is not an object of strings: %v", raw, err)
	}
	return header
}

// The header table on Logout gives every member of the protected header an encrypted hint carries,
// with its value, and no member the auth server's encryptor does not write.
func TestEndpointDocs_TheHintHeaderTableIsTheHeaderEncryptWrites(t *testing.T) {
	assertValueTable(t, filepath.Dir(guard.SourceRoot(t)), hintHeaderSection, "Member", "Value",
		hintHeader(t), "the header")
}

func TestEndpointDocs_AValueTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/logout.mdx", "### Encrypting the hint\n\n"+
		"| Member | Value | Meaning |\n|---|---|---|\n"+
		"| `alg` | `dir` | Direct |\n"+
		"| `enc` | `A128GCM` | The cipher |\n"+
		"| `zip` | `DEF` | Not written |\n"+
		"| `alg` | `dir` | Twice |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertValueTable(r, root, conceptSection{"site/logout.mdx", "### Encrypting the hint"}, "Member", "Value",
			map[string]string{"alg": "dir", "enc": "A256GCM", "cty": "JWT"}, "the header")
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/logout.mdx: ### Encrypting the hint row 2 gives enc as A128GCM, where the header has A256GCM",
		"site/logout.mdx: ### Encrypting the hint row 3 names zip, which the header never has",
		"site/logout.mdx: ### Encrypting the hint row 4 names alg, which an earlier row already does",
		"site/logout.mdx: ### Encrypting the hint has no row for cty",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestEndpointDocs_AValueTableAgreeingWithTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/register.mdx", "### Errors\n\n"+
		"| `error` | Status | When |\n|---|---|---|\n"+
		"| `invalid_client_metadata` | 400 | Metadata refused |\n"+
		"| `access_denied` | 403 | Registration is off |\n\n"+
		"### Next\n\n| `error` | Status |\n|---|---|\n| `other` | 418 |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertValueTable(r, root, conceptSection{"site/register.mdx", "### Errors"}, "`error`", "Status",
			map[string]string{"access_denied": "403", "invalid_client_metadata": "400"}, "the handler")
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a table agreeing with the code was refused: %+v", report)
	}
}

func TestEndpointDocs_AMissingValueTableSectionStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/register.mdx", "### Error codes\n\n"+
		"| `error` | Status |\n|---|---|\n| `access_denied` | 403 |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertValueTable(r, root, conceptSection{"site/register.mdx", "### Errors"}, "`error`", "Status",
			map[string]string{"access_denied": "403"}, "the handler")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "### Errors") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestEndpointDocs_AValueTableWithoutItsValueColumnStops(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/register.mdx", "### Errors\n\n"+
		"| `error` | Code |\n|---|---|\n| `access_denied` | 403 |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertValueTable(r, root, conceptSection{"site/register.mdx", "### Errors"}, "`error`", "Status",
			map[string]string{"access_denied": "403"}, "the handler")
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "Status") {
		t.Errorf("a table without its value column did not stop the check naming it: %+v", report)
	}
}

// assertValueTable is the reporting half of the checks holding a table of names and values to the
// code: one failure per row naming something the code never has, giving a value the code does not,
// or naming what an earlier row named, and one per name with no row; a stop for a section, table or
// column not found. carrier names what holds the values, such as "the header", in the failure.
func assertValueTable(r guard.Reporter, root string, section conceptSection, nameColumn, valueColumn string,
	want map[string]string, carrier string) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, nameColumn, valueColumn)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	named := make(map[string]bool)
	for i, row := range columns {
		name, value := row[0], row[1]
		wantValue, known := want[name]
		switch {
		case named[name]:
			r.Errorf("%s: %s row %d names %s, which an earlier row already does", section.page, section.heading, i+1, name)
		case !known:
			r.Errorf("%s: %s row %d names %s, which %s never has", section.page, section.heading, i+1, name, carrier)
		case value != wantValue:
			r.Errorf("%s: %s row %d gives %s as %s, where %s has %s", section.page, section.heading, i+1, name, value,
				carrier, wantValue)
		}
		named[name] = true
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if !named[name] {
			r.Errorf("%s: %s has no row for %s", section.page, section.heading, name)
		}
	}
}
