package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestHandlers_AjaxHandlersDoNotUsePageWriters refuses a handler that answers a request with JSON
// and, on one of its branches, with an HTML page.
//
// The console has two families of writer for the same three conditions. NotFound renders
// not_found.html, InternalServerError renders error.html, and HandleAPIError routes to both;
// JsonNotFound, JsonError and HandleAPIErrorJson answer the same statuses as JSON. Mixing them
// inside one handler is invisible in Go and invisible in a passing test suite, and it breaks at
// exactly the moment the branch fires: the browser has already committed to response.json(), so an
// HTML body makes the fetch throw, the modal shows a generic failure, and the status and sentence
// the handler chose never reach the screen. sendAjaxRequest in utils.js does JSON.parse inside a
// try/catch for that reason, and image-upload.js does not catch it at all.
//
// It had happened 36 times across 10 handlers when #279 found it, and a third of those were fresh:
// this issue's own console sweep turned InternalServerError into NotFound wherever a stale URL was
// answered, correctly by condition, which upgraded "the wrong page in a JSON response" to "a
// different wrong page in a JSON response" in the handlers that answer JSON. That is why the guard
// is a lint rather than a note: the mistake is one a correct-looking sweep makes.
//
// The rule is per function, and the classification is what a handler writes on its success path. A
// function that calls RenderTemplate or Redirect is a page handler and may use anything; a function
// that calls no JSON writer is not covered; everything else is an AJAX handler and every branch of
// it must answer JSON.
//
// It parses by brace matching over source text rather than with go/ast. The unit it needs is the
// top-level func, the markers are all direct calls spelled in full, and neither is worth a type
// checker here. A page writer reached through an alias or a variable would evade it, which is a
// deliberate boundary and not an oversight: this catches the regression that actually happens,
// which is a branch written from the page handler beside it.
func TestHandlers_AjaxHandlersDoNotUsePageWriters(t *testing.T) {
	// go test runs with the package directory as the working directory, so ".." is
	// src/adminconsole/internal.
	const root = "../handlers"

	funcStart := regexp.MustCompile(`(?m)^func ([A-Za-z0-9_]+)\(`)
	jsonWriter := regexp.MustCompile(`EncodeJson\(|JsonError\(|JsonNotFound\(|JsonBadRequestBody\(|HandleAPIErrorJson\(`)
	// HandleAPIErrorJson contains HandleAPIError as a substring, so the page-writer pattern has to
	// exclude it explicitly rather than by matching the shorter name.
	pageWriter := regexp.MustCompile(`httpHelper\.NotFound\(|httpHelper\.InternalServerError\(|HandleAPIError\((?:[^)]*)\)`)

	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		text := string(source)

		for _, match := range funcStart.FindAllStringSubmatchIndex(text, -1) {
			name := text[match[2]:match[3]]
			body, ok := functionBody(text, match[1]-1)
			if !ok {
				continue
			}
			scanned++
			if strings.Contains(body, "RenderTemplate(") || strings.Contains(body, "Redirect(") {
				continue
			}
			if !jsonWriter.MatchString(body) {
				continue
			}
			for _, hit := range pageWriter.FindAllString(body, -1) {
				if strings.HasPrefix(hit, "HandleAPIErrorJson(") {
					continue
				}
				t.Errorf("%s: %s answers with JSON but reaches %s on one branch; "+
					"use JsonNotFound, JsonError or HandleAPIErrorJson instead, so every branch "+
					"of an AJAX handler answers JSON (#279)",
					filepath.ToSlash(path), name, strings.TrimSuffix(hit, "("))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// A walk that silently found nothing would pass forever. The package had well over 200
	// top-level functions when this was written; 100 is a floor that cannot be reached by the
	// tree shrinking for any ordinary reason.
	if scanned < 100 {
		t.Fatalf("scanned only %d functions under %s, so the walk is not reaching the handlers", scanned, root)
	}
}

// functionBody returns the text from the opening brace at or after start to its matching close.
func functionBody(text string, start int) (string, bool) {
	open := strings.IndexByte(text[start:], '{')
	if open < 0 {
		return "", false
	}
	open += start
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[open : i+1], true
			}
		}
	}
	return "", false
}
