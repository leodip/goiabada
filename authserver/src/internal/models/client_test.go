package models

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
)

func TestIsSystemLevelClient(t *testing.T) {
	tests := []struct {
		name             string
		clientIdentifier string
		expected         bool
	}{
		{"AdminConsoleClient", constants.AdminConsoleClientIdentifier, true},
		{"NonSystemClient", "regular-client", false},
		{"EmptyIdentifier", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{ClientIdentifier: tt.clientIdentifier}
			if got := client.IsSystemLevelClient(); got != tt.expected {
				t.Errorf("IsSystemLevelClient() = %v, want %v", got, tt.expected)
			}
		})
	}
}
