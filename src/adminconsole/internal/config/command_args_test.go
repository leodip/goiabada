package config

import (
	"reflect"
	"testing"
)

// TestCommandArgs: what the flag parse leaves of a command line, found with the console's own
// flags and nothing else, under an environment Load refuses. A flag that takes a value takes the
// word after it, a boolean flag does not, and `--` ends the flags; a command line whose flags do
// not parse answers false (#808 decisions 3 and 5).
func TestCommandArgs(t *testing.T) {
	t.Setenv("TZ", "Not/AZone")
	t.Setenv("GOIABADA_ADMINCONSOLE_LISTEN_PORT_METRICS", "91x1")
	t.Setenv("GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS", "yes")
	t.Setenv("GOIABADA_ADMINCONSOLE_INTERNAL_CA_FILE", "/nonexistent/internal-ca.pem")

	cases := []struct {
		name string
		args []string
		want []string
		ok   bool
	}{
		{"nothing", nil, []string{}, true},
		{"flags alone", []string{"--adminconsole-log-level=debug", "--authserver-baseurl", "https://auth.example.com"}, []string{}, true},
		{"a word after a flag", []string{"--adminconsole-log-level=debug", "serve"}, []string{"serve"}, true},
		{"a command after a boolean flag", []string{"--adminconsole-metrics-enabled", "check-authserver"}, []string{"check-authserver"}, true},
		{"the word as a flag's value", []string{"--adminconsole-log-level", "healthcheck"}, []string{}, true},
		{"-- before the command", []string{"--", "healthcheck"}, []string{"healthcheck"}, true},
		{"a flag after a word", []string{"serve", "--adminconsole-log-level=debug"}, []string{"serve", "--adminconsole-log-level=debug"}, true},
		{"the trusted proxy flag", []string{"--adminconsole-trusted-proxies", "10.0.0.0/8", "serve"}, []string{"serve"}, true},
		{"an unknown flag", []string{"--no-such-flag", "serve"}, nil, false},
		{"a malformed flag value", []string{"--adminconsole-listen-port-http=90x1", "serve"}, nil, false},
		{"an auth server flag this binary refuses", []string{"--db-type=mysql", "serve"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CommandArgs(tc.args)
			if ok != tc.ok {
				t.Fatalf("CommandArgs(%q) ok = %v, want %v", tc.args, ok, tc.ok)
			}
			if tc.ok && (len(got) != 0 || len(tc.want) != 0) && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("CommandArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
