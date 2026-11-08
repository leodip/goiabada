package config

import (
	"reflect"
	"testing"
)

// TestCommandArgs: what the flag parse leaves of a command line, found with the server's own flags
// and nothing else, under an environment Load refuses. A flag that takes a value takes the word
// after it, a boolean flag does not, and `--` ends the flags; a command line whose flags do not
// parse answers false (#808 decision 3).
func TestCommandArgs(t *testing.T) {
	t.Setenv("TZ", "Not/AZone")
	t.Setenv("GOIABADA_AUTHSERVER_LISTEN_PORT_METRICS", "91x0")
	t.Setenv("GOIABADA_AUTHSERVER_LOG_LEVEL", "not-a-level")
	t.Setenv("GOIABADA_DB_TLS_CA_FILE", "/nonexistent/db-ca.pem")
	t.Setenv("GOIABADA_ADMINCONSOLE_BASEURL", "http://console.example.com")

	cases := []struct {
		name string
		args []string
		want []string
		ok   bool
	}{
		{"nothing", nil, []string{}, true},
		{"flags alone", []string{"--authserver-log-level=debug", "--db-type", "mysql"}, []string{}, true},
		{"a command after a flag", []string{"--authserver-log-level=debug", "healthcheck"}, []string{"healthcheck"}, true},
		{"a command after a boolean flag", []string{"--authserver-log-sql", "healthcheck"}, []string{"healthcheck"}, true},
		{"the word as a flag's value", []string{"--authserver-log-level", "healthcheck"}, []string{}, true},
		{"-- before the command", []string{"--", "healthcheck"}, []string{"healthcheck"}, true},
		{"migrate and its own arguments", []string{"--db-type=sqlite", "migrate", "--db-type=mysql", "to", "44"},
			[]string{"migrate", "--db-type=mysql", "to", "44"}, true},
		{"the trusted proxy flag", []string{"--authserver-trusted-proxies", "10.0.0.0/8", "recover"}, []string{"recover"}, true},
		{"an unknown flag", []string{"--no-such-flag", "healthcheck"}, nil, false},
		{"a malformed flag value", []string{"--authserver-listen-port-http=90x0", "healthcheck"}, nil, false},
		{"a console flag this binary refuses", []string{"--adminconsole-log-level=debug", "healthcheck"}, nil, false},
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
