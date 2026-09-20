package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestThreeStateSetting_String owns the total String decision 16 of #385 settled for this type. The
// in-range rows are stored values: a client's overridable columns carry them as these strings and
// the seeder writes "default", so they are pinned against literals rather than against the slice.
func TestThreeStateSetting_String(t *testing.T) {
	testCases := []struct {
		name    string
		setting ThreeStateSetting
		want    string
	}{
		{"on is the zero value", ThreeStateSettingOn, "on"},
		{"off", ThreeStateSettingOff, "off"},
		{"default, the top of the range", ThreeStateSettingDefault, "default"},
		{"one past the range", ThreeStateSetting(3), ""},
		{"far past the range", ThreeStateSetting(99), ""},
		{"negative", ThreeStateSetting(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.setting.String())
		})
	}
}

// TestThreeStateSettingFromString covers the parse in both directions.
func TestThreeStateSettingFromString(t *testing.T) {
	all := []ThreeStateSetting{ThreeStateSettingOn, ThreeStateSettingOff, ThreeStateSettingDefault}
	for _, setting := range all {
		t.Run(setting.String(), func(t *testing.T) {
			parsed, err := ThreeStateSettingFromString(setting.String())
			assert.NoError(t, err)
			assert.Equal(t, setting, parsed)
		})
	}

	t.Run("an unrecognized setting is refused", func(t *testing.T) {
		for _, raw := range []string{"", "inherit", "On", "1"} {
			parsed, err := ThreeStateSettingFromString(raw)
			assert.Error(t, err, "%q must not parse", raw)
			assert.Equal(t, ThreeStateSettingOn, parsed, "the refused value returns the zero setting")
		}
	})
}
