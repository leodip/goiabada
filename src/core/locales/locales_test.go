package locales

import (
	"testing"
)

func TestGet(t *testing.T) {
	result := Get()

	// Test that Get() returns a non-nil slice
	if result == nil {
		t.Error("Get() returned nil")
	}

	// Test that Get() returns a non-empty slice
	if len(result) == 0 {
		t.Error("Get() returned an empty slice")
	}

	// Test for a few known locales
	knownLocales := map[string]string{
		"en":    "English",
		"es":    "Spanish",
		"fr":    "French",
		"zh-CN": "Chinese (China)",
	}

	for id, value := range knownLocales {
		found := false
		for _, locale := range result {
			if locale.Id == id && locale.Value == value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected locale {%s, %s} not found", id, value)
		}
	}
}

func TestUniqueIds(t *testing.T) {
	result := Get()
	idMap := make(map[string]bool)

	for _, locale := range result {
		if idMap[locale.Id] {
			t.Errorf("Duplicate Id found: %s", locale.Id)
		}
		idMap[locale.Id] = true
	}
}

func TestNonEmptyFields(t *testing.T) {
	result := Get()

	for _, locale := range result {
		if locale.Id == "" {
			t.Error("Found a Locale with empty Id")
		}
		if locale.Value == "" {
			t.Error("Found a Locale with empty Value")
		}
	}
}
