package config

// The server start refuses an admin console URL that is plain http on a host other than
// loopback (#590): the first start registers the console's redirect URIs from it, and a
// redirect URI like that receives nothing from this release on, so the console would be
// locked out with nothing at start to say why. `migrate` and `recover` read no console URL and
// are not refused, so a repair never waits on it.
//
// It reads the environment and the flags and nothing else.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminConsoleURLRefusal is the whole refusal Load answers for value, written out here rather
// than built the way config.go builds it.
func adminConsoleURLRefusal(value string) string {
	return `malformed configuration: GOIABADA_ADMINCONSOLE_BASEURL (--adminconsole-baseurl) is "` + value +
		`", plain http on a host other than 127.0.0.1, [::1] or localhost, where the admin console cannot sign in; ` +
		`nothing was changed. Move the console to https in this order: on the release that ran before this one, ` +
		`add the console's https URL, and that URL followed by /auth/callback, on the Redirect URIs tab of ` +
		`admin-console-client; serve the console over https and set GOIABADA_ADMINCONSOLE_BASEURL to that URL ` +
		`on both servers; then start this release`
}

func TestLoad_APlainHTTPAdminConsoleURLOffLoopbackIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string // the variable, when the case sets it
		args  []string          // the flags Load parses over it
		value string            // the console URL the parse leaves
		want  string            // the refusal, or "" for a load
	}{
		{
			name:  "plain http on a public host, from the variable",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://admin.example.com"},
			value: "http://admin.example.com",
			want:  adminConsoleURLRefusal("http://admin.example.com"),
		},
		{
			name:  "from the flag, which an https variable does not rescue",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "https://admin.example.com"},
			args:  []string{"-adminconsole-baseurl=http://admin.example.com:9091"},
			value: "http://admin.example.com:9091",
			want:  adminConsoleURLRefusal("http://admin.example.com:9091"),
		},
		{
			name:  "an uppercase scheme is still plain http",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "HTTP://admin.example.com"},
			value: "HTTP://admin.example.com",
			want:  adminConsoleURLRefusal("HTTP://admin.example.com"),
		},
		{
			name:  "a host that only starts with localhost is not loopback",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://localhost.attacker.com"},
			value: "http://localhost.attacker.com",
			want:  adminConsoleURLRefusal("http://localhost.attacker.com"),
		},
		{
			name:  "a private address is not loopback",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://192.168.1.50:9091"},
			value: "http://192.168.1.50:9091",
			want:  adminConsoleURLRefusal("http://192.168.1.50:9091"),
		},
		{
			name:  "refused under an unknown command, which the server start would otherwise answer",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://admin.example.com"},
			args:  []string{"migrat", "to", "44"},
			value: "http://admin.example.com",
			want:  adminConsoleURLRefusal("http://admin.example.com"),
		},
		{
			name:  "the default, http on localhost, loads",
			value: "http://localhost:9091",
		},
		{
			name:  "http on 127.0.0.1 loads",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://127.0.0.1:9091"},
			value: "http://127.0.0.1:9091",
		},
		{
			name:  "http on [::1] loads",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://[::1]:9091"},
			value: "http://[::1]:9091",
		},
		{
			name:  "http on LOCALHOST, the host folded, loads",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://LOCALHOST:9091"},
			value: "http://LOCALHOST:9091",
		},
		{
			name:  "https on a public host loads",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "https://admin.example.com"},
			value: "https://admin.example.com",
		},
		{
			name:  "https from the flag rescues a plain-http variable, the flag being the value the server reads",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://admin.example.com"},
			args:  []string{"-adminconsole-baseurl=https://admin.example.com"},
			value: "https://admin.example.com",
		},
		{
			name:  "migrate is not refused",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://admin.example.com"},
			args:  []string{"migrate", "to", "44"},
			value: "http://admin.example.com",
		},
		{
			name:  "migrate after a flag giving the console URL is not refused",
			args:  []string{"-adminconsole-baseurl=http://admin.example.com", "migrate", "version"},
			value: "http://admin.example.com",
		},
		{
			name:  "recover is not refused",
			env:   map[string]string{"GOIABADA_ADMINCONSOLE_BASEURL": "http://admin.example.com"},
			args:  []string{"recover", "--email", "admin@example.com"},
			value: "http://admin.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c, err := loadMatrixRefusing(t, tt.env, tt.args)

			if tt.want == "" {
				require.NoError(t, err)
				require.NotNil(t, c, "a load answers a configuration")
				assert.Equal(t, tt.value, c.AdminConsole.BaseURL)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.want, err.Error())
			assert.Nil(t, c, "a refusal answers no configuration")
			assert.NotContains(t, err.Error(), "\n", "the refusal is one line on stderr")
		})
	}
}
