package models

import (
	"testing"

	"github.com/leodip/goiabada/core/constants"
)

func TestIsSystemLevelResource(t *testing.T) {
	tests := []struct {
		name               string
		resourceIdentifier string
		expected           bool
	}{
		{"AuthServer", constants.AuthServerResourceIdentifier, true},
		{"AdminConsole", constants.AdminConsoleResourceIdentifier, true},
		{"CustomResource", "custom-resource", false},
		{"EmptyIdentifier", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resource{ResourceIdentifier: tt.resourceIdentifier}
			if got := r.IsSystemLevelResource(); got != tt.expected {
				t.Errorf("IsSystemLevelResource() = %v, want %v", got, tt.expected)
			}
		})
	}
}
