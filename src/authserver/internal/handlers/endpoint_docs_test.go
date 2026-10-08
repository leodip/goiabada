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
// It reads files, and runs the two image handlers over a stub database.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
)

// The pages, relative to the repository root.
const (
	discoveryPage      = "site/src/content/docs/reference/endpoints/discovery-and-jwks.mdx"
	logoAndPicturePage = "site/src/content/docs/reference/endpoints/logo-and-picture.mdx"
)

var (
	discoveryFieldsSection = conceptSection{discoveryPage, "### The discovery document"}
	clientLogoSection      = conceptSection{logoAndPicturePage, "### The client logo"}
	profilePictureSection  = conceptSection{logoAndPicturePage, "### The profile picture"}
)

// discoveryFields is every field the discovery document can carry, as its JSON names it, in the
// order oidc.WellKnownConfig declares them.
func discoveryFields() []string {
	var fields []string
	typ := reflect.TypeOf(oidc.WellKnownConfig{})
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	return fields
}

// The discovery document's table on Discovery and JWKS has one row per field the auth server
// writes, and none for a field it never does.
func TestEndpointDocs_TheDiscoveryTableIsTheDocumentsFields(t *testing.T) {
	assertDiscoveryTable(t, filepath.Dir(guard.SourceRoot(t)), discoveryFieldsSection, discoveryFields())
}

func TestEndpointDocs_ADiscoveryTableDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeConceptFixture(t, root, "site/discovery.mdx", "### The discovery document\n\n"+
		"| Field | Value |\n|---|---|\n"+
		"| `issuer` | The issuer |\n"+
		"| `check_session_iframe` | Not a field |\n"+
		"| `issuer` | Twice |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertDiscoveryTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer", "jwks_uri"})
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
		assertDiscoveryTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer", "jwks_uri"})
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
		assertDiscoveryTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer"})
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
		assertDiscoveryTable(r, root, conceptSection{"site/discovery.mdx", "### The discovery document"},
			[]string{"issuer"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "Field") {
		t.Errorf("a table without its Field column did not stop the check naming it: %+v", report)
	}
}

// assertDiscoveryTable is the reporting half of the discovery table's check: one failure per row
// naming a field the document never carries or one an earlier row named, and per field with no
// row; a stop for a section, table or column not found.
func assertDiscoveryTable(r guard.Reporter, root string, section conceptSection, fields []string) {
	r.Helper()
	columns, err := conceptTableColumns(root, section, "Field")
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
			r.Errorf("%s: %s row %d names %s, which the document never carries", section.page, section.heading, i+1, field)
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
