package phonecountries

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet(t *testing.T) {
	phoneCountries := Get()

	if len(phoneCountries) == 0 {
		t.Error("Get() returned empty slice")
	}

	assert.True(t, len(phoneCountries) > 255, "Expected at least 255 countries, found %d", len(phoneCountries))
	assert.True(t, len(phoneCountries) < 265, "Expected at most 265 countries, found %d", len(phoneCountries))

	seen := make(map[string]bool)
	for _, pc := range phoneCountries {
		if seen[pc.UniqueId] {
			t.Errorf("Duplicate UniqueId found: %s", pc.UniqueId)
		}
		seen[pc.UniqueId] = true
	}

	seen = make(map[string]bool)
	for _, pc := range phoneCountries {
		if seen[pc.Name] {
			t.Errorf("Duplicate Name found: %s", pc.Name)
		}
		seen[pc.Name] = true
	}
}

func TestGetSpecificCountries(t *testing.T) {
	phoneCountries := Get()

	testCases := []struct {
		countryName string
		expected    int
	}{
		{"United States", 2}, // includes US and 'US Minor Outlying Islands'
		{"United Kingdom", 1},
		{"Canada", 1},
		{"Australia", 1},
		{"Brazil", 1},
		{"New Zealand", 1},
		{"Aruba", 2},              // Aruba has two call codes
		{"Jamaica", 2},            // Jamaica has two call codes
		{"Dominican Republic", 3}, // Dominican Republic has three call codes
	}

	for _, tc := range testCases {
		count := 0
		for _, pc := range phoneCountries {
			if strings.Contains(pc.Name, tc.countryName) {
				count++
			}
		}
		if count != tc.expected {
			t.Errorf("Expected %d entries for %s, found %d", tc.expected, tc.countryName, count)
		}
	}
}
