package apihandlers

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestAPIHandlers_DoNotRenderPages refuses a call to a page-rendering writer inside the admin and
// account API's handlers.
//
// Every handler in this package answers JSON, and every 500 here is writeInternalServerError, one
// structured log record and one INTERNAL_SERVER_ERROR envelope (#279 decision 7). The HttpHelper
// some handlers receive also carries InternalServerError and NotFound, which render error.html and
// not_found.html, and six branches still called the first of those after decision 7 landed: the
// five database failures in handler_api_user_consents.go and the GetUserBySubject failure in
// HandleAPIAccountProfilePictureDelete. A database outage on those routes handed the console's
// fetch an HTML page to JSON.parse, and logged nothing under the request id the envelope would have
// carried. The pull request review for #279 found them; this is the guard that keeps the count at
// zero, because the mistake is one a handler written from an older one makes.
//
// The scan is lexical, like TestAPIErrorCodes_MatchTheSurvivorTable beside it: the two names are
// only ever spelled as a direct selector call on the helper, so a regexp finds every real site and
// a type checker would find nothing more.
func TestAPIHandlers_DoNotRenderPages(t *testing.T) {
	pageWriter := regexp.MustCompile(`\.(InternalServerError|NotFound)\(`)

	var offences []string
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(string(source), "\n") {
			if pageWriter.MatchString(line) {
				offences = append(offences, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(path), i+1, strings.TrimSpace(line)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the apihandlers package: %v", err)
	}
	// A walk that reached nothing would pass, which is the one way a guard like this fails in the
	// permissive direction.
	if scanned < 20 {
		t.Fatalf("scanned only %d non-test Go files; the walk is no longer reaching the handlers", scanned)
	}

	sort.Strings(offences)
	if len(offences) > 0 {
		t.Errorf("%d API handler branch(es) render a page instead of the JSON envelope; use "+
			"writeInternalServerError or writeJSONError:\n  %s", len(offences), strings.Join(offences, "\n  "))
	}
}
