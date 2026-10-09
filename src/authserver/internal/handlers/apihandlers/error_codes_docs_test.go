package apihandlers

// The API reference's error-code catalog, held to the survivor table (#519 decision 6).
//
// The errors page is where an integrator learns which error_code values the admin and account API
// can answer and what each one means. apiErrorCodes in api_error_code_lint_test.go is the whole set
// the surface writes, held there to every write site in both directions. This holds the page's
// table to that set in both directions too: a code the API gains without its row fails, and so
// does a row naming a code the API no longer writes.
//
// It reads files and nothing else.

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// errorCodesSection is the section of the errors page that holds the catalog.
var errorCodesSection = docSection{apiErrorsPage, "## Error codes"}

// docErrorCodeCell is a table cell holding one backticked UPPER_SNAKE code and nothing else. A
// code may be one word, as FORBIDDEN is.
var docErrorCodeCell = regexp.MustCompile("^`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)`$")

func TestErrorCodesDocs_TheCatalogIsTheSurvivorTable(t *testing.T) {
	assertErrorCodeCatalog(t, filepath.Dir(guard.SourceRoot(t)), errorCodesSection,
		slices.Sorted(maps.Keys(apiErrorCodes)))
}

func TestErrorCodesDocs_ACatalogDisagreeingWithTheCodeFails(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/errors.mdx", "## Error codes\n\n"+
		"| Code | Status | Meaning |\n"+
		"|---|---|---|\n"+
		"| `NOT_FOUND` | `404` | Nothing has that id. |\n"+
		"| `RETIRED_CODE` | `400` | Gone from the API. |\n"+
		"| `NOT_FOUND` | `404` | Listed twice. |\n"+
		"| `VALIDATION_ERROR` | `400` | |\n"+
		"| INVALID_TOKEN | `401` | Not backticked. |\n"+
		"| `TOO_MANY_REQUESTS` | A limit was reached. |\n\n"+
		"## Next\n\n| `INVALID_REQUEST_BODY` | `400` | Outside the section. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorCodeCatalog(r, root, docSection{"site/errors.mdx", "## Error codes"},
			[]string{"INVALID_REQUEST_BODY", "INVALID_TOKEN", "NOT_FOUND", "TOO_MANY_REQUESTS", "VALIDATION_ERROR"})
	})

	if report.Stopped {
		t.Fatalf("the check stopped rather than reporting: %s", report.Fatal)
	}
	want := []string{
		"site/errors.mdx: ## Error codes lists RETIRED_CODE, which the API does not write",
		"site/errors.mdx: ## Error codes lists NOT_FOUND twice",
		"site/errors.mdx: ## Error codes gives VALIDATION_ERROR no meaning",
		`site/errors.mdx: ## Error codes has a row whose code is not one backticked UPPER_SNAKE code: "INVALID_TOKEN"`,
		`site/errors.mdx: ## Error codes has a row of 2 cells, want code, status and meaning: ["` + "`TOO_MANY_REQUESTS`" + `" "A limit was reached."]`,
		"site/errors.mdx: ## Error codes does not list INVALID_REQUEST_BODY",
		"site/errors.mdx: ## Error codes does not list INVALID_TOKEN",
		"site/errors.mdx: ## Error codes does not list TOO_MANY_REQUESTS",
	}
	if !slices.Equal(report.Errors, want) {
		t.Errorf("failures\n%q\nwant\n%q", report.Errors, want)
	}
}

func TestErrorCodesDocs_ACatalogMatchingTheCodePasses(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/errors.mdx", "## Error codes\n\n"+
		"| Code | Status | Meaning |\n"+
		"|---|---|---|\n"+
		"| `NOT_FOUND` | `404` | Nothing has that id. |\n"+
		"| `FORBIDDEN` | `403` | It belongs to another user. |\n"+
		"| `VALIDATION_ERROR` | `400` | A value was refused. |\n\n"+
		"## Next\n\nText.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorCodeCatalog(r, root, docSection{"site/errors.mdx", "## Error codes"},
			[]string{"FORBIDDEN", "NOT_FOUND", "VALIDATION_ERROR"})
	})

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("a catalog matching the code failed: %+v", report)
	}
}

func TestErrorCodesDocs_AMissingSectionStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/errors.mdx", "## Codes\n\n"+
		"| Code | Status | Meaning |\n|---|---|---|\n| `NOT_FOUND` | `404` | Nothing has that id. |\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorCodeCatalog(r, root, docSection{"site/errors.mdx", "## Error codes"}, []string{"NOT_FOUND"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "## Error codes") {
		t.Errorf("a page without the section did not stop the check naming it: %+v", report)
	}
}

func TestErrorCodesDocs_ASectionWithNoTableStops(t *testing.T) {
	root := t.TempDir()
	writeDocFixture(t, root, "site/errors.mdx", "## Error codes\n\n- `NOT_FOUND`: `404`, nothing has that id.\n")

	report := guard.Run(func(r guard.Reporter) {
		assertErrorCodeCatalog(r, root, docSection{"site/errors.mdx", "## Error codes"}, []string{"NOT_FOUND"})
	})

	if !report.Stopped || !strings.Contains(report.Fatal, "no table") {
		t.Errorf("a section without its table did not stop the check: %+v", report)
	}
}

// assertErrorCodeCatalog is the reporting half of the catalog's check: one failure per finding of
// errorCodeCatalogFindings; a stop for a section not found or holding no table, since a check that
// read no row proves nothing.
func assertErrorCodeCatalog(r guard.Reporter, root string, section docSection, codes []string) {
	r.Helper()
	findings, err := errorCodeCatalogFindings(root, section, codes)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// errorCodeCatalogFindings reads the first table in section, one row per code with its status and
// its meaning, and returns one finding per row that is not a code the API writes, lists a code a
// second time, or gives it no meaning, and then one per code in codes with no row. It returns an
// error, and no findings, for a section not found or holding no table.
func errorCodeCatalogFindings(root string, section docSection, codes []string) ([]string, error) {
	text, err := docSectionText(root, section)
	if err != nil {
		return nil, err
	}
	rows := docTableRows(text)
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s: %s holds no table of the error codes", section.page, section.heading)
	}

	where := section.page + ": " + section.heading
	var findings []string
	listed := make(map[string]bool)
	for _, cells := range rows {
		if len(cells) != 3 {
			findings = append(findings, fmt.Sprintf("%s has a row of %d cells, want code, status and meaning: %q",
				where, len(cells), cells))
			continue
		}
		match := docErrorCodeCell.FindStringSubmatch(cells[0])
		if match == nil {
			findings = append(findings, fmt.Sprintf("%s has a row whose code is not one backticked UPPER_SNAKE code: %q",
				where, cells[0]))
			continue
		}
		code := match[1]
		switch {
		case !slices.Contains(codes, code):
			findings = append(findings, where+" lists "+code+", which the API does not write")
		case listed[code]:
			findings = append(findings, where+" lists "+code+" twice")
		case cells[2] == "":
			findings = append(findings, where+" gives "+code+" no meaning")
		}
		listed[code] = true
	}
	for _, code := range codes {
		if !listed[code] {
			findings = append(findings, where+" does not list "+code)
		}
	}
	return findings, nil
}
