package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/leodip/goiabada/core/errs"
)

// AssertErrorCodeDoc holds src/core/i18n/error_codes.md to the English catalog.
//
// The document is a hand-maintained table carrying the English sentence for
// every validator.* and handler.* code, and until this guard landed nothing
// compared it to anything: no Go file so much as names it. That made it a second
// uncontrolled copy of every user-visible error message, free to drift from the
// catalog the server actually renders, and the drift would show up as a reader
// being told something the software does not do.
//
// Worse, it hid the gap it sat next to. A sweep for "is this sentence asserted
// anywhere?" found 54 of 54 validator messages covered, because the document
// repeats each sentence verbatim; the real number of messages asserted by a test
// was 30. Closing the assertion gap without closing this one leaves the next
// sweep reading the same false positive (#230, #344 decision 9).
//
// Three rules, checked in both directions:
//
//   - every validator.* and handler.* key in catalogs/active.en.toml has exactly
//     one row in the document;
//   - a row's English message equals the catalog value byte for byte, template
//     placeholders included, since both sides carry the raw {{.max}} form;
//   - no row names a key the catalog does not have.
//
// The args column is prose for a reader and is not checked: it describes a shape
// the call sites choose, not a value the catalog holds.
//
// Every module's unit tier calls this, so the guard fires whichever tier is run.
func AssertErrorCodeDoc(t *testing.T) {
	t.Helper()

	assertErrorCodeDoc(t, SourceRoot(t))
}

// assertErrorCodeDoc is the reporting half, taking the source root as a parameter and failing
// through a Reporter so a rule test can drive it against a fixture tree. See Reporter in guard.go.
//
// A finder error is fatal rather than an ordinary finding: it means the document or the catalog
// could not be read or parsed, or that one of them held nothing to compare, and every per-code
// check would then pass vacuously. That is the direction a guard fails in silently.
func assertErrorCodeDoc(r Reporter, sourceRoot string) {
	r.Helper()

	findings, err := checkErrorCodeDoc(sourceRoot)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, f := range findings {
		r.Errorf("%s", f)
	}
}

// errorCodeDocFinding is one violation, named by the code it is about so the message points at a
// row or a catalog key rather than at a line number that moves.
type errorCodeDocFinding struct {
	Code   string
	Reason string
}

func (f errorCodeDocFinding) String() string {
	return fmt.Sprintf("%s: %s", f.Code, f.Reason)
}

// errorCodeDocPrefixes are the key families the document is responsible for. The catalog also
// carries page copy, field labels and button text, none of which is an error code, so a rule over
// every key would ask the document to grow into a translation memory.
var errorCodeDocPrefixes = []string{"validator.", "handler."}

// checkErrorCodeDoc returns one finding per violation, sorted by code so the message is stable.
//
// The error return is reserved for the cases that make the findings meaningless: a file that could
// not be read or parsed, a document with no rows in it, and a catalog with no keys in these
// families. Ordinary violations are findings, because each one names a row somebody has to fix.
func checkErrorCodeDoc(sourceRoot string) ([]errorCodeDocFinding, error) {
	docPath := filepath.Join(sourceRoot, "core", "i18n", "error_codes.md")
	catalogPath := filepath.Join(sourceRoot, "core", "i18n", "catalogs", "active.en.toml")

	catalog, err := readEnglishCatalog(catalogPath)
	if err != nil {
		return nil, err
	}
	rows, err := readErrorCodeDocRows(docPath)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errs.Errorf("%s holds no code rows; every comparison below would pass vacuously", docPath)
	}

	owned := make(map[string]string)
	for key, message := range catalog {
		if errorCodeDocOwns(key) {
			owned[key] = message
		}
	}
	if len(owned) == 0 {
		return nil, errs.Errorf("%s holds no %s keys; every comparison below would pass vacuously",
			catalogPath, strings.Join(errorCodeDocPrefixes, " or "))
	}

	var findings []errorCodeDocFinding

	// The message comparison is the loop below, over every row, so a row naming a key from
	// another family is held to the catalog too. This loop is only about how many rows exist.
	for key, message := range owned {
		switch n := len(rows[key]); {
		case n == 0:
			findings = append(findings, errorCodeDocFinding{key, fmt.Sprintf(
				"the English catalog has this key but error_codes.md has no row for it; add one carrying %q",
				message)})
		case n > 1:
			findings = append(findings, errorCodeDocFinding{key, fmt.Sprintf(
				"error_codes.md has %d rows for this key; exactly one row per code is what makes the table readable as a catalog",
				n)})
		}
	}

	for key, rowsForKey := range rows {
		message, inCatalog := catalog[key]
		if !inCatalog {
			findings = append(findings, errorCodeDocFinding{key, fmt.Sprintf(
				"error_codes.md has a row for this key, which %s does not declare; either the key was renamed or the row is stale",
				filepath.ToSlash(catalogPath))})
			continue
		}
		for _, row := range rowsForKey {
			if row != message {
				findings = append(findings, errorCodeDocFinding{key, fmt.Sprintf(
					"error_codes.md says %q and the English catalog says %q; the catalog is what the server renders",
					row, message)})
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Reason < findings[j].Reason
	})
	return findings, nil
}

// errorCodeDocOwns reports whether a catalog key is one the document is responsible for.
func errorCodeDocOwns(key string) bool {
	for _, prefix := range errorCodeDocPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// readEnglishCatalog returns the raw key-to-message map, templates unrendered. It parses the file
// on disk rather than going through i18n.LoadBundle because the bundle renders: EnglishFallback
// substitutes args, and comparing a rendered sentence against a documented one would make every
// row carrying a {{.max}} fail for the wrong reason.
func readEnglishCatalog(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Errorf("reading %s: %w", path, err)
	}
	var parsed map[string]any
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return nil, errs.Errorf("parsing %s: %w", path, err)
	}
	out := make(map[string]string, len(parsed))
	for key, value := range parsed {
		s, ok := value.(string)
		if !ok {
			return nil, errs.Errorf("%s: key %q is a %T, not a string", path, key, value)
		}
		out[key] = s
	}
	return out, nil
}

// readErrorCodeDocRows returns every table row keyed by the code in its first cell, as a slice so a
// duplicated code is visible rather than silently collapsed.
//
// A row is a line whose first cell is a single backticked token: that is what distinguishes a code
// row from the header, the separator and the prose between sections, none of which the document
// needs marked up any further. A line that looks like a code row but does not have three cells is
// reported rather than skipped, since a message holding an unescaped pipe would otherwise drop out
// of the comparison entirely.
func readErrorCodeDocRows(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.Errorf("reading %s: %w", path, err)
	}

	rows := make(map[string][]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		code, ok := backtickedCode(strings.TrimSpace(cells[0]))
		if !ok {
			continue
		}
		if len(cells) != 3 {
			return nil, errs.Errorf(
				"%s: the row for %q has %d cells rather than 3, so its message cannot be read; an unescaped | in a message is the usual cause",
				path, code, len(cells))
		}
		rows[code] = append(rows[code], strings.TrimSpace(cells[2]))
	}
	return rows, nil
}

// backtickedCode returns the token inside a cell that is exactly one backticked value.
func backtickedCode(cell string) (string, bool) {
	if len(cell) < 3 || !strings.HasPrefix(cell, "`") || !strings.HasSuffix(cell, "`") {
		return "", false
	}
	inner := cell[1 : len(cell)-1]
	if inner == "" || strings.Contains(inner, "`") {
		return "", false
	}
	return inner, true
}
