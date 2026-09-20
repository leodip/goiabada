package handlerhelpers

import (
	"context"
	"html/template"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
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
func TestDateTimeAndSinceFuncMap(t *testing.T) {
	ctx := context.Background()
	instant := time.Date(2026, 9, 14, 21, 3, 7, 0, time.UTC)

	dateTime, ok := templateFuncMap["DateTime"].(func(context.Context, any) string)
	if !ok {
		t.Fatalf(`templateFuncMap["DateTime"] is not func(context.Context, any) string`)
	}
	if got, want := dateTime(ctx, &instant), i18n.FormatDateTime(ctx, &instant); got != want {
		t.Errorf("DateTime() = %q, want %q", got, want)
	}
	if got := dateTime(ctx, nil); got != "" {
		t.Errorf("DateTime(nil) = %q, want the empty string", got)
	}

	since, ok := templateFuncMap["Since"].(func(context.Context, any) string)
	if !ok {
		t.Fatalf(`templateFuncMap["Since"] is not func(context.Context, any) string`)
	}
	// Three days and an hour back, so the answer is "3 days" on either side of
	// the clock read Since performs for itself: the wrapper supplies
	// time.Now().UTC(), which this test cannot pass in.
	then := time.Now().UTC().Add(-73 * time.Hour)
	if got, want := since(ctx, &then), i18n.FormatSince(ctx, &then, time.Now().UTC()); got != want {
		t.Errorf("Since() = %q, want %q", got, want)
	}
	if got := since(ctx, nil); got != "" {
		t.Errorf("Since(nil) = %q, want the empty string", got)
	}
}

// TestInstantOf holds the adapter the two entries above normalize through. It
// exists because the responses the console binds carry both shapes deliberately:
// a nullable column reaches the wire as *time.Time, and an audit entry's
// createdAt as a time.Time, since its column cannot be null. A template cannot
// take the address of a value, so a page binding the second shape renders a
// blank cell rather than a date unless this switch answers it (#373).
func TestInstantOf(t *testing.T) {
	instant := time.Date(2026, 9, 14, 21, 3, 7, 0, time.UTC)
	var nilPointer *time.Time

	if got := instantOf(&instant); got == nil || !got.Equal(instant) {
		t.Errorf("instantOf(*time.Time) = %v, want %v", got, instant)
	}
	if got := instantOf(instant); got == nil || !got.Equal(instant) {
		t.Errorf("instantOf(time.Time) = %v, want %v", got, instant)
	}
	if got := instantOf(nilPointer); got != nil {
		t.Errorf("instantOf((*time.Time)(nil)) = %v, want nil", got)
	}
	if got := instantOf(nil); got != nil {
		t.Errorf("instantOf(nil) = %v, want nil", got)
	}
	// Anything else renders blank rather than reaching the formatter, which is
	// what deref does for a *bool: a template naming the wrong field is a bug
	// the rendertest seam catches, not one worth a panic in a page.
	if got := instantOf("2026-09-14"); got != nil {
		t.Errorf("instantOf(string) = %v, want nil", got)
	}
}

// TestTemplateFuncMap_IsThisApplicationsTwentyTwo pins the split #385 made. The one map in core
// held these same twenty-two and the auth server parsed every template with all of them, though
// its pages call four: T, Lang, args and versionComment, which are also here. The other eighteen
// -- the five page predicates over this console's own URL paths, the JS bootstrap block, the
// reference-data formatters -- are this application's alone, and a new entry here means one of its
// templates calls it.
func TestTemplateFuncMap_IsThisApplicationsTwentyTwo(t *testing.T) {
	keys := make([]string, 0, len(templateFuncMap))
	for k := range templateFuncMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	want := []string{
		"DateTime", "JSBootstrap", "Lang", "LocaleLabel", "RefCountry", "RefPhoneCountry",
		"RefTimezone", "Since", "T", "add", "addUrlParam", "args", "concat", "deref",
		"isAdminClientPage", "isAdminGroupPage", "isAdminResourcePage", "isAdminSettingsEmailPage",
		"isAdminUserPage", "isLast", "marshal", "versionComment",
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("templateFuncMap = %v, want %v", keys, want)
	}
}
