package models

import (
	"testing"
)

func TestUserConsent_HasScope(t *testing.T) {
	tests := []struct {
		name     string
		consent  UserConsent
		scope    string
		expected bool
	}{
		{"Empty scope", UserConsent{Scope: ""}, "read", false},
		{"Single scope match", UserConsent{Scope: "read"}, "read", true},
		{"Single scope no match", UserConsent{Scope: "write"}, "read", false},
		{"Multiple scopes with match", UserConsent{Scope: "read write delete"}, "write", true},
		{"Multiple scopes without match", UserConsent{Scope: "read write delete"}, "update", false},
		{"Partial scope match", UserConsent{Scope: "read write"}, "read-only", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.consent.HasScope(tt.scope); got != tt.expected {
				t.Errorf("UserConsent.HasScope() = %v, want %v", got, tt.expected)
			}
		})
	}
}
