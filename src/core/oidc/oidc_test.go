package oidc

import "testing"

func TestIsIdTokenScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"OpenID scope", "openid", true},
		{"Profile scope", "profile", true},
		{"Email scope", "email", true},
		{"Address scope", "address", true},
		{"Phone scope", "phone", true},
		{"Groups scope", "groups", true},
		{"Attributes scope", "attributes", true},
		{"Non-OIDC scope", "custom_scope", false},
		{"Empty scope", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsIdTokenScope(tc.scope)
			if result != tc.expected {
				t.Errorf("IsIdTokenScope(%q) = %v; want %v", tc.scope, result, tc.expected)
			}
		})
	}
}

func TestIsOfflineAccessScope(t *testing.T) {
	testCases := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"Exact match", "offline_access", true},
		{"Case insensitive", "OFFLINE_ACCESS", true},
		{"With spaces", "  offline_access  ", true},
		{"Different scope", "online_access", false},
		{"Empty string", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsOfflineAccessScope(tc.scope)
			if result != tc.expected {
				t.Errorf("IsOfflineAccessScope(%q) = %v; want %v", tc.scope, result, tc.expected)
			}
		})
	}
}
