package handlerhelpers

import (
	"html/template"
	"reflect"
	"sort"
	"testing"

	"github.com/leodip/goiabada/core/constants"
)

func TestArgsFuncMap(t *testing.T) {
	tests := []struct {
		name     string
		input    []any
		expected []any
	}{
		{
			name:     "Empty input",
			input:    []any{},
			expected: []any{},
		},
		{
			name:     "Single argument",
			input:    []any{"test"},
			expected: []any{"test"},
		},
		{
			name:     "Multiple arguments",
			input:    []any{1, "two", 3.14},
			expected: []any{1, "two", 3.14},
		},
	}

	argsFunc, ok := templateFuncMap["args"].(func(...any) []any)
	if !ok {
		t.Fatalf("templateFuncMap[\"args\"] is not of type func(...any) []any")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := argsFunc(tt.input...)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("args() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersionCommentFuncMap(t *testing.T) {
	expectedHTML := template.HTML("<!-- version: " + constants.Version + "; build date: " + constants.BuildDate + "; git commit: " + constants.GitCommit + "-->")

	result := templateFuncMap["versionComment"].(func() template.HTML)()

	if result != expectedHTML {
		t.Errorf("versionComment() = %v, want %v", result, expectedHTML)
	}
}

// TestDateTimeAndSinceFuncMap holds the two date entries to being registered
// under the names the templates call and to reaching the i18n formatters
// rather than any local copy of them. The formatter's own exhaustive table
// lives beside it, in core/i18n; these two wrappers own only the name and the
// clock (#373).

// TestTemplateFuncMap_IsThisApplicationsFour pins the split #385 made. The one map in core held
// twenty-two entries and both binaries parsed every template with all of them; these four are what
// src/authserver/web/template actually calls. A new entry here means an auth server template calls
// it, and one the admin console alone calls belongs in the console's copy of this file.
func TestTemplateFuncMap_IsThisApplicationsFour(t *testing.T) {
	keys := make([]string, 0, len(templateFuncMap))
	for k := range templateFuncMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if !reflect.DeepEqual(keys, []string{"Lang", "T", "args", "versionComment"}) {
		t.Errorf("templateFuncMap = %v, want exactly Lang, T, args, versionComment", keys)
	}
}
