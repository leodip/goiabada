package i18n

// The translated refusal on the API's Errors page, held to the catalogs (#559 decision 9).
//
// The page shows an error answer and the same answer to a request sent with an Accept-Language
// header, which is how it says the description follows the request's language and error_code
// does not. An example is a json block holding the envelope's two fields; the one after a line
// naming `Accept-Language: <tag>` is that answer in <tag>. Each such example must share its
// error_code with an English example earlier on the page, and its error_description must be what
// that locale renders for the catalog key whose English text the English example shows.
//
// It reads files and the embedded catalogs, and nothing else.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"golang.org/x/text/language"
)

// The API's Errors page, relative to the repository root.
const apiErrorsPage = "site/src/content/docs/reference/api/errors.mdx"

// The translated example on the API's Errors page keeps its error_code and shows what the catalog
// renders in the language its request names.
func TestErrorsDocs_TheTranslatedExampleIsWhatTheServerAnswers(t *testing.T) {
	assertTranslatedErrorExamples(t, filepath.Dir(guard.SourceRoot(t)), apiErrorsPage)
}

func TestErrorsDocs_ATranslatedExampleWithAnotherCodeOrSentenceFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/errors.mdx", "## The fields\n\n"+
		"```json\n{\"error_code\": \"VALIDATION_ERROR\", \"error_description\": \"SMTP host is required.\"}\n```\n\n"+
		"The same refusal, to a request sent with `Accept-Language: pt-BR`:\n\n"+
		"```json\n{\"error_code\": \"handler.settings_email.smtp_host_required\", \"error_description\": \"O host SMTP é obrigatório.\"}\n```\n\n"+
		"And again:\n\n"+
		"`Accept-Language: pt-BR`\n\n"+
		"```json\n{\"error_code\": \"VALIDATION_ERROR\", \"error_description\": \"O host SMTP é necessário.\"}\n```\n")

	report := guard.Run(func(r guard.Reporter) { assertTranslatedErrorExamples(r, root, "site/errors.mdx") })

	want := []string{
		`site/errors.mdx: the pt-BR example answers error_code "handler.settings_email.smtp_host_required", which no English example above it shows`,
		`site/errors.mdx: the pt-BR example shows "O host SMTP é necessário.", but the catalog renders "SMTP host is required." in pt-BR as "O host SMTP é obrigatório."`,
	}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestErrorsDocs_ATranslatedExampleOfAnUntranslatableSentenceFails(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/errors.mdx", "## The fields\n\n"+
		"```json\n{\"error_code\": \"VALIDATION_ERROR\", \"error_description\": \"No catalog says this.\"}\n```\n\n"+
		"With `Accept-Language: pt-BR`:\n\n"+
		"```json\n{\"error_code\": \"VALIDATION_ERROR\", \"error_description\": \"Nenhum catálogo diz isto.\"}\n```\n")

	report := guard.Run(func(r guard.Reporter) { assertTranslatedErrorExamples(r, root, "site/errors.mdx") })

	want := []string{`site/errors.mdx: the pt-BR example translates "No catalog says this.", which is no sentence of the English catalog`}
	if report.Stopped || !slices.Equal(report.Errors, want) {
		t.Errorf("failures %+v\nwant %q", report, want)
	}
}

func TestErrorsDocs_ATranslatedExampleTheCatalogRendersPasses(t *testing.T) {
	root := t.TempDir()
	// An English example nobody translates is fine beside it: most of the API's sentences are.
	writeGuideFixture(t, root, "site/errors.mdx", "## The fields\n\n"+
		"```json\n{\"error_code\": \"INVALID_REQUEST_BODY\", \"error_description\": \"Invalid request body\"}\n```\n\n"+
		"```json\n{\n  \"error_code\": \"VALIDATION_ERROR\",\n  \"error_description\": \"SMTP host is required.\"\n}\n```\n\n"+
		"The same refusal, to a request sent with `Accept-Language: pt-BR`:\n\n"+
		"```json\n{\n  \"error_code\": \"VALIDATION_ERROR\",\n  \"error_description\": \"O host SMTP é obrigatório.\"\n}\n```\n")

	report := guard.Run(func(r guard.Reporter) { assertTranslatedErrorExamples(r, root, "site/errors.mdx") })

	if report.Stopped || len(report.Errors) > 0 {
		t.Errorf("an example the catalog renders was refused: %+v", report)
	}
}

func TestErrorsDocs_APageWithNoTranslatedExampleStops(t *testing.T) {
	root := t.TempDir()
	writeGuideFixture(t, root, "site/errors.mdx", "## The fields\n\n"+
		"```json\n{\"error_code\": \"VALIDATION_ERROR\", \"error_description\": \"SMTP host is required.\"}\n```\n")

	report := guard.Run(func(r guard.Reporter) { assertTranslatedErrorExamples(r, root, "site/errors.mdx") })

	if !report.Stopped || !strings.Contains(report.Fatal, "no error example after a line naming `Accept-Language") {
		t.Errorf("a page with no translated example did not stop the check: %+v", report)
	}
}

func TestErrorsDocs_AMissingPageStopsTheCheck(t *testing.T) {
	report := guard.Run(func(r guard.Reporter) { assertTranslatedErrorExamples(r, t.TempDir(), "site/errors.mdx") })

	if !report.Stopped || !strings.Contains(report.Fatal, "site/errors.mdx") {
		t.Errorf("a missing page did not stop the check naming it: %+v", report)
	}
}

// errorExample is one json block on the page holding the error envelope, and the language the
// line before it names, or "" for an English example.
type errorExample struct {
	locale      string
	code        string
	description string
}

// assertTranslatedErrorExamples is the reporting half: one failure per translated example whose
// code no earlier English example shows, whose English example is no catalog sentence, or whose
// sentence is not what its locale renders. A stop for a page not read, or one with no translated
// example, since a check that compared nothing proves nothing.
func assertTranslatedErrorExamples(r guard.Reporter, root, page string) {
	r.Helper()
	findings, err := translatedErrorExampleFindings(root, page)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, finding := range findings {
		r.Errorf("%s", finding)
	}
}

// translatedErrorExampleFindings reads the page's error examples and checks each translated one
// against the embedded catalogs.
func translatedErrorExampleFindings(root, page string) ([]string, error) {
	examples, err := errorExamples(root, page)
	if err != nil {
		return nil, err
	}
	embedded, err := load("")
	if err != nil {
		return nil, fmt.Errorf("loading the embedded catalogs: %w", err)
	}
	english := embedded.messages[language.English]

	var findings []string
	translated := 0
	for i, example := range examples {
		if example.locale == "" {
			continue
		}
		translated++
		source := -1
		for j := i - 1; j >= 0; j-- {
			if examples[j].locale == "" && examples[j].code == example.code {
				source = j
				break
			}
		}
		if source < 0 {
			findings = append(findings, fmt.Sprintf("%s: the %s example answers error_code %q, which no English "+
				"example above it shows", page, example.locale, example.code))
			continue
		}
		sentence := examples[source].description
		var keys []string
		for key, message := range english {
			if message.raw == sentence {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			findings = append(findings, fmt.Sprintf("%s: the %s example translates %q, which is no sentence of "+
				"the English catalog", page, example.locale, sentence))
			continue
		}
		slices.Sort(keys)
		ctx := ctxForBundle(embedded, example.locale)
		var rendered []string
		for _, key := range keys {
			rendered = append(rendered, T(ctx, key))
		}
		if !slices.Contains(rendered, example.description) {
			findings = append(findings, fmt.Sprintf("%s: the %s example shows %q, but the catalog renders %q in %s as %q",
				page, example.locale, example.description, sentence, example.locale, rendered[0]))
		}
	}
	if translated == 0 {
		return nil, fmt.Errorf("%s has no error example after a line naming `Accept-Language: <tag>`", page)
	}
	return findings, nil
}

// acceptLanguageNamed is a line naming the language of the example that follows it.
var acceptLanguageNamed = regexp.MustCompile("`Accept-Language: ([A-Za-z0-9-]+)`")

// errorExamples is every json block on the page that decodes to exactly error_code and
// error_description, with the language named by the last non-blank line between its fence and the
// block before it.
func errorExamples(root, page string) ([]errorExample, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(page)))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", page, err)
	}
	var examples []errorExample
	var block []string
	inJSON, inOther := false, false
	previous := ""
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case inJSON && strings.HasPrefix(trimmed, "```"):
			inJSON = false
			locale := ""
			if match := acceptLanguageNamed.FindStringSubmatch(previous); match != nil {
				locale = match[1]
			}
			previous = ""
			var envelope map[string]string
			if json.Unmarshal([]byte(strings.Join(block, "\n")), &envelope) != nil || len(envelope) != 2 {
				continue
			}
			code, hasCode := envelope["error_code"]
			description, hasDescription := envelope["error_description"]
			if !hasCode || !hasDescription {
				continue
			}
			examples = append(examples, errorExample{locale: locale, code: code, description: description})
		case inJSON:
			block = append(block, trimmed)
		case inOther:
			if strings.HasPrefix(trimmed, "```") {
				inOther, previous = false, ""
			}
		case trimmed == "```json":
			inJSON, block = true, nil
		case strings.HasPrefix(trimmed, "```"):
			inOther = true
		case trimmed != "":
			previous = trimmed
		}
	}
	return examples, nil
}
