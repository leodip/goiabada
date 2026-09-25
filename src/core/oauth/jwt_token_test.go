package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetStringClaim(t *testing.T) {
	t.Run("Returns string value when claim is string", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{"test": "value"}}
		assert.Equal(t, "value", jwt.GetStringClaim("test"))
	})

	t.Run("Returns empty string when claim does not exist", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{}}
		assert.Equal(t, "", jwt.GetStringClaim("nonexistent"))
	})

	t.Run("Returns empty string when claim is int (regression test for panic)", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{"test": 123}}
		// Before the fix, this would panic with: interface conversion: interface {} is int, not string
		// After the fix, it returns empty string safely
		assert.NotPanics(t, func() {
			result := jwt.GetStringClaim("test")
			assert.Equal(t, "", result)
		})
	})

	t.Run("Returns empty string when claim is bool (regression test for panic)", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{"test": true}}
		assert.NotPanics(t, func() {
			result := jwt.GetStringClaim("test")
			assert.Equal(t, "", result)
		})
	})

	t.Run("Returns empty string when claim is object (regression test for panic)", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{"test": map[string]interface{}{"nested": "value"}}}
		assert.NotPanics(t, func() {
			result := jwt.GetStringClaim("test")
			assert.Equal(t, "", result)
		})
	})

	t.Run("Returns empty string when claim is array (regression test for panic)", func(t *testing.T) {
		jwt := JwtToken{Claims: map[string]interface{}{"test": []string{"a", "b"}}}
		assert.NotPanics(t, func() {
			result := jwt.GetStringClaim("test")
			assert.Equal(t, "", result)
		})
	})
}

func TestGetTimeClaim(t *testing.T) {
	now := time.Now().Unix()
	jwt := JwtToken{Claims: map[string]interface{}{"time": float64(now)}}
	assert.Equal(t, time.Unix(now, 0), jwt.GetTimeClaim("time"))
	assert.Equal(t, time.Time{}, jwt.GetTimeClaim("nonexistent"))
}

func TestGetBoolClaim(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"bool": true}}
	assert.Equal(t, true, *jwt.GetBoolClaim("bool"))
	assert.Nil(t, jwt.GetBoolClaim("nonexistent"))
}

func TestGetAddressClaim(t *testing.T) {
	address := map[string]interface{}{"street": "123 Main St", "city": "Anytown"}
	jwt := JwtToken{Claims: map[string]interface{}{"address": address}}
	expected := map[string]string{"street": "123 Main St", "city": "Anytown"}
	assert.Equal(t, expected, jwt.GetAddressClaim())
	assert.Empty(t, JwtToken{Claims: map[string]interface{}{}}.GetAddressClaim())
}

func TestHasScope(t *testing.T) {
	jwt := JwtToken{Claims: map[string]interface{}{"scope": "read write"}}
	assert.True(t, jwt.HasScope("read"))
	assert.True(t, jwt.HasScope("write"))
	assert.False(t, jwt.HasScope("delete"))
	assert.False(t, JwtToken{Claims: map[string]interface{}{}}.HasScope("read"))
}

// TestGetIntClaim pins the exact returned tuple for every input shape (#106 decision 15,
// finding 22).
//
// The tuple matters, not just the value. GetIntClaim reports only whether a PRESENT claim
// parsed, so absent and malformed both yield (0, false) and the accessor cannot tell them
// apart. That is deliberate: it keeps the generic accessor unsurprising, and the one caller
// that needs the distinction tests raw map presence first. If this ever changed to report
// true for an absent claim, the middleware would read a missing generation as valid.
//
// The float64 rows are the load-bearing ones. Claims arrive through encoding/json, so a
// JSON number is always float64; an implementation asserting to int would reject every
// well-formed token.
func TestGetIntClaim(t *testing.T) {
	const name = "auth_state_generation"

	tests := []struct {
		label     string
		claims    jwt.MapClaims
		wantValue int64
		wantOk    bool
	}{
		{"integral float64, the shape every real claim has", jwt.MapClaims{name: float64(7)}, 7, true},
		{"zero is a legitimate generation", jwt.MapClaims{name: float64(0)}, 0, true},
		{"large but unambiguously representable", jwt.MapClaims{name: float64(1 << 52)}, 1 << 52, true},
		{"exactly the safe maximum, 2^53-1", jwt.MapClaims{name: float64(1<<53 - 1)}, 1<<53 - 1, true},
		// The boundary row. 2^53 IS representable as a float64, so an implementation using
		// it as the limit accepts this. It is still unsafe: the JSON integer 2^53+1 parses
		// to the same float64, so a claim of 2^53 cannot be distinguished from one that was
		// larger. 2^53-1 above is the largest unambiguous value.
		{"2^53 exactly, representable but ambiguous after parsing", jwt.MapClaims{name: float64(1 << 53)}, 0, false},
		// Absent. Same tuple as malformed, which is why the middleware checks presence
		// itself. Keep this row: it is the one that would otherwise let a legacy token
		// with no claim be read as valid.
		{"absent claim", jwt.MapClaims{}, 0, false},
		{"explicit nil", jwt.MapClaims{name: nil}, 0, false},
		{"non-integral float64", jwt.MapClaims{name: float64(1.5)}, 0, false},
		{"negative", jwt.MapClaims{name: float64(-1)}, 0, false},
		{"beyond exact float64 integer range", jwt.MapClaims{name: float64(1<<53) + 2}, 0, false},
		{"string, even when it looks numeric", jwt.MapClaims{name: "7"}, 0, false},
		{"bool", jwt.MapClaims{name: true}, 0, false},
		{"json array", jwt.MapClaims{name: []interface{}{float64(7)}}, 0, false},
		// int rather than float64: unreachable from a parsed JWT, but pins that the
		// accessor asserts the type json actually produces rather than the one a Go
		// author would reach for.
		{"Go int, which a parsed token never contains", jwt.MapClaims{name: 7}, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			token := JwtToken{Claims: tc.claims}
			gotValue, gotOk := token.GetIntClaim(name)
			assert.Equal(t, tc.wantOk, gotOk, "ok flag")
			assert.Equal(t, tc.wantValue, gotValue, "value")
		})
	}
}
