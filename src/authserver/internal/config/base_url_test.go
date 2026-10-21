package config

// The base URL is held to the issuer's length limit before anything is seeded (#615), so an
// installation can never hold an issuer its own General settings page refuses on every save.
//
// It reads the environment and the flags and nothing else.

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseURLOf is an https URL exactly n characters long, padding the host label the way a long one
// is long, so a case can name the boundary it holds: the issuer limit is met at 60 and passed
// at 61.
func baseURLOf(n int) string {
	return "https://auth." + strings.Repeat("a", n-len("https://auth.")-len(".example.com")) + ".example.com"
}

func TestLoad_ABASURLongerThanTheIssuerAllowsIsRefused(t *testing.T) {
	// An astral character counts two in the length the save measures and four in bytes, so this
	// URL is exactly the limit the way the save counts it and past it in bytes: verified here, so
	// the literals cannot drift from the divergence the case exists for.
	astral := "https://auth." + strings.Repeat("a", 60-len("https://auth.")-len(".example.com")-4) +
		"\U0001F600\U0001F600.example.com"
	require.Equal(t, 60, inputvalidation.TextLength(astral))
	require.Len(t, astral, 64)

	tests := []struct {
		name  string
		value string   // GOIABADA_AUTHSERVER_BASEURL, always set, so the cases run on a known base
		args  []string // the flags Load parses over it
		want  string   // the refusal, or "" for a load
	}{
		{
			name:  "one character past the limit, from the variable",
			value: baseURLOf(61),
			want: `malformed configuration: GOIABADA_AUTHSERVER_BASEURL (--authserver-baseurl) is "` + baseURLOf(61) +
				`", longer than the issuer allows: at most 60 characters`,
		},
		{
			name:  "one past the limit, from the flag, which the variable does not rescue",
			value: "https://env.example.com",
			args:  []string{"-authserver-baseurl=" + baseURLOf(62)},
			want: `malformed configuration: GOIABADA_AUTHSERVER_BASEURL (--authserver-baseurl) is "` + baseURLOf(62) +
				`", longer than the issuer allows: at most 60 characters`,
		},
		{
			name:  "refused before migrate as well",
			value: baseURLOf(61),
			args:  []string{"migrate", "to"},
			want: `malformed configuration: GOIABADA_AUTHSERVER_BASEURL (--authserver-baseurl) is "` + baseURLOf(61) +
				`", longer than the issuer allows: at most 60 characters`,
		},
		{
			name:  "the limit itself loads",
			value: baseURLOf(60),
			want:  "",
		},
		{
			name:  "the limit is the save's unit, not bytes, so sixty code units of two astral characters load",
			value: astral,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, err := loadMatrixRefusing(t, map[string]string{"GOIABADA_AUTHSERVER_BASEURL": tt.value}, tt.args)

			if tt.want == "" {
				require.NoError(t, err)
				require.NotNil(t, c, "a load answers a configuration")
				assert.Equal(t, tt.value, c.AuthServer.BaseURL)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.want, err.Error())
			assert.Nil(t, c, "a refusal answers no configuration")
			assert.NotContains(t, err.Error(), "\n", "the refusal is one line on stderr")
		})
	}
}
