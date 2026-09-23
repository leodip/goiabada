package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser_GetFullName(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected string
	}{
		{"Nil user", nil, ""},
		{"Empty names", &User{}, ""},
		{"Only GivenName", &User{GivenName: "John"}, "John"},
		{"Only MiddleName", &User{MiddleName: "Doe"}, "Doe"},
		{"Only FamilyName", &User{FamilyName: "Smith"}, "Smith"},
		{"GivenName and FamilyName", &User{GivenName: "John", FamilyName: "Smith"}, "John Smith"},
		{"Full name", &User{GivenName: "John", MiddleName: "Doe", FamilyName: "Smith"}, "John Doe Smith"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.GetFullName())
		})
	}
}
