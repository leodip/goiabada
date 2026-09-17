package handlerhelpers

import (
	"context"
	"html/template"
	"reflect"
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

	dateTime, ok := templateFuncMap["DateTime"].(func(context.Context, *time.Time) string)
	if !ok {
		t.Fatalf(`templateFuncMap["DateTime"] is not func(context.Context, *time.Time) string`)
	}
	if got, want := dateTime(ctx, &instant), i18n.FormatDateTime(ctx, &instant); got != want {
		t.Errorf("DateTime() = %q, want %q", got, want)
	}
	if got := dateTime(ctx, nil); got != "" {
		t.Errorf("DateTime(nil) = %q, want the empty string", got)
	}

	since, ok := templateFuncMap["Since"].(func(context.Context, *time.Time) string)
	if !ok {
		t.Fatalf(`templateFuncMap["Since"] is not func(context.Context, *time.Time) string`)
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
