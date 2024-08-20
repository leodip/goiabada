package handlerhelpers

import (
	"html/template"
	"reflect"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := templateFuncMap["args"].(func(...any) []any)(tt.input...)
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
