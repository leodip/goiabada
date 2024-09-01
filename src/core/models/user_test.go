package models

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUser_HasAddress(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected bool
	}{
		{"Empty address", User{}, false},
		{"Only AddressLine1", User{AddressLine1: "123 Main St"}, true},
		{"Only AddressLine2", User{AddressLine2: "Apt 4B"}, true},
		{"Only AddressLocality", User{AddressLocality: "Springfield"}, true},
		{"Only AddressRegion", User{AddressRegion: "IL"}, true},
		{"Only AddressPostalCode", User{AddressPostalCode: "12345"}, true},
		{"Only AddressCountry", User{AddressCountry: "USA"}, true},
		{"Full address", User{
			AddressLine1:      "123 Main St",
			AddressLine2:      "Apt 4B",
			AddressLocality:   "Springfield",
			AddressRegion:     "IL",
			AddressPostalCode: "12345",
			AddressCountry:    "USA",
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.HasAddress())
		})
	}
}

func TestUser_GetAddressClaim(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected map[string]string
	}{
		{"Empty address", User{}, map[string]string{}},
		{"Full address", User{
			AddressLine1:      "123 Main St",
			AddressLine2:      "Apt 4B",
			AddressLocality:   "Springfield",
			AddressRegion:     "IL",
			AddressPostalCode: "12345",
			AddressCountry:    "USA",
		}, map[string]string{
			"street_address": "123 Main St\r\nApt 4B",
			"locality":       "Springfield",
			"region":         "IL",
			"postal_code":    "12345",
			"country":        "USA",
			"formatted":      "123 Main St\r\nApt 4B\r\nSpringfield\r\nIL\r\n12345\r\nUSA",
		}},
		{"Partial address", User{
			AddressLine1:    "123 Main St",
			AddressLocality: "Springfield",
			AddressCountry:  "USA",
		}, map[string]string{
			"street_address": "123 Main St\r\n",
			"locality":       "Springfield",
			"country":        "USA",
			"formatted":      "123 Main St\r\n\r\nSpringfield\r\nUSA",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.GetAddressClaim()
			assert.Equal(t, tt.expected, result)

			// Additional check for the "formatted" field
			if formatted, ok := result["formatted"]; ok {
				assert.Equal(t, tt.expected["formatted"], formatted, "Formatted address mismatch")
			}
		})
	}
}

func TestUser_GetDateOfBirthFormatted(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected string
	}{
		{"Nil user", nil, ""},
		{"Invalid BirthDate", &User{BirthDate: sql.NullTime{Valid: false}}, ""},
		{"Valid BirthDate", &User{BirthDate: sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}}, "1990-01-01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.user.GetDateOfBirthFormatted())
		})
	}
}

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
