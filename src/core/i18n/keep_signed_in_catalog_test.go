package i18n

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The password page's Keep me signed in box and its note, in Goiabada's wording of WP29 Opinion
// 04/2012's "remember me (uses cookies)", translated in every built-in catalog (#743 decision 4).
func TestCatalog_KeepMeSignedInIsTranslatedEverywhere(t *testing.T) {
	en := loadCatalogFlat(t, "active.en.toml")
	want := map[string]string{
		"auth.pwd.keep_signed_in":      "Keep me signed in",
		"auth.pwd.keep_signed_in_note": "Uses a cookie to keep you signed in after you close the browser.",
	}
	for key, value := range want {
		assert.Equalf(t, value, en[key], "active.en.toml: %q", key)
	}

	for _, name := range catalogNames(t) {
		if name == "active.en.toml" {
			continue
		}
		translated := loadCatalogFlat(t, name)
		for key := range want {
			assert.NotEmptyf(t, translated[key], "%s: %q", name, key)
			assert.NotEqualf(t, en[key], translated[key], "%s: %q is still the English", name, key)
		}
	}
}
