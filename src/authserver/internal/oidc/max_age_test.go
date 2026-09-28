package oidc

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseMaxAge owns the max_age parse table. Every row an authorization request can carry is
// here once: the other readers of max_age consult this function rather than repeating it (#243).
func TestParseMaxAge(t *testing.T) {
	accepted := []struct {
		name string
		raw  string
		want int64
	}{
		{"zero", "0", 0},
		{"an hour", "3600", 3600},
		{"leading zeros", "007", 7},
		{"the largest value a time.Duration holds in seconds", "9223372036", 9223372036},
		{"one second beyond it", "9223372037", 9223372037},
		{"the largest int64", "9223372036854775807", math.MaxInt64},
		{"one beyond int64 is held as the largest", "9223372036854775808", math.MaxInt64},
		{"22 digits is held as the largest", "9999999999999999999999", math.MaxInt64},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMaxAge(tc.raw)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}

	t.Run("empty is absent", func(t *testing.T) {
		got, err := ParseMaxAge("")
		assert.NoError(t, err)
		assert.Nil(t, got)
	})

	refused := []struct {
		name string
		raw  string
	}{
		{"negative", "-1"},
		{"explicit plus sign", "+5"},
		{"leading space", " 5"},
		{"trailing space", "5 "},
		{"letters", "abc"},
		{"decimal", "1.5"},
		{"exponent", "1e3"},
		{"a non-ASCII digit", "٣"},
		{"a space alone", " "},
	}
	for _, tc := range refused {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			got, err := ParseMaxAge(tc.raw)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}
