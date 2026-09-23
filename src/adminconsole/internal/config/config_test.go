package config

import (
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"multiple with spaces", " 10.0.0.0/8 , 192.168.0.1 ,203.0.113.0/24", []string{"10.0.0.0/8", "192.168.0.1", "203.0.113.0/24"}},
		{"empty segments dropped", "10.0.0.1,, ,10.0.0.2", []string{"10.0.0.1", "10.0.0.2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitCSV(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCSV(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestGetEnvAsStringSlice(t *testing.T) {
	const key = "GOIABADA_TEST_TRUSTED_PROXIES"

	t.Run("unset returns nil", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getEnvAsStringSlice(key); got != nil {
			t.Errorf("getEnvAsStringSlice with empty env = %#v, want nil", got)
		}
	})

	t.Run("comma-separated parsed and trimmed", func(t *testing.T) {
		t.Setenv(key, " 10.0.0.0/8 , 172.16.0.0/12 ")
		want := []string{"10.0.0.0/8", "172.16.0.0/12"}
		if got := getEnvAsStringSlice(key); !reflect.DeepEqual(got, want) {
			t.Errorf("getEnvAsStringSlice = %#v, want %#v", got, want)
		}
	})
}

func TestGetEnv(t *testing.T) {
	const key = "GOIABADA_TEST_GETENV"

	// Both sides are trimmed, which is the rule a quoted value in a compose file or an env
	// file meets: GOIABADA_ADMINCONSOLE_LOG_LEVEL=" debug " is the same level as
	// GOIABADA_ADMINCONSOLE_LOG_LEVEL=debug.
	tests := []struct {
		name string
		// set is false for the unset case, which is what the default is for.
		set        bool
		value      string
		defaultVal string
		want       string
	}{
		{name: "unset returns the default", set: false, defaultVal: "info", want: "info"},
		{name: "unset returns the default trimmed", set: false, defaultVal: "  info  ", want: "info"},
		{name: "set returns the value", set: true, value: "debug", defaultVal: "info", want: "debug"},
		{name: "set returns the value trimmed", set: true, value: "  debug\t", defaultVal: "info", want: "debug"},
		// Present-and-empty is a value, not an absence: os.LookupEnv reports it as set, so
		// the default does not apply. An operator who writes GOIABADA_ADMINCONSOLE_LOG_FORMAT=
		// has chosen the empty string.
		{name: "set to empty is not the default", set: true, value: "", defaultVal: "info", want: ""},
		{name: "set to whitespace only is not the default", set: true, value: "   ", defaultVal: "info", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnv(key, tt.defaultVal); got != tt.want {
				t.Errorf("getEnv(%s=%q, %q) = %q, want %q", key, tt.value, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestGetEnvAsInt(t *testing.T) {
	const key = "GOIABADA_TEST_PORT"

	// Anything strconv.Atoi refuses falls back to the default rather than to zero, so a
	// mistyped port leaves the server on the port it was shipped with instead of on port 0.
	tests := []struct {
		name  string
		set   bool
		value string
		want  int
	}{
		{name: "unset returns the default", set: false, want: 9444},
		{name: "a number", set: true, value: "8444", want: 8444},
		{name: "a negative number", set: true, value: "-1", want: -1},
		{name: "whitespace is trimmed", set: true, value: "  8444  ", want: 8444},
		{name: "empty falls back", set: true, value: "", want: 9444},
		{name: "non-numeric falls back", set: true, value: "https", want: 9444},
		{name: "a decimal falls back", set: true, value: "8444.0", want: 9444},
		{name: "an overflowing number falls back", set: true, value: "99999999999999999999", want: 9444},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnvAsInt(key, 9444); got != tt.want {
				t.Errorf("getEnvAsInt(%s=%q, 9444) = %d, want %d", key, tt.value, got, tt.want)
			}
		})
	}
}

func TestGetEnvAsBool(t *testing.T) {
	const key = "GOIABADA_TEST_TRUST_PROXY_HEADERS"

	// getEnvAsBool can only ever express default-false: anything unparseable is false, which
	// is the safe answer for every setting that reaches it (each one turns something on).
	// Nothing this process loads has a default of true, which is why getEnvAsBoolDefault
	// (#293) stayed with the auth server, whose GOIABADA_DB_CREATE is the one such setting.
	tests := []struct {
		name  string
		set   bool
		value string
		want  bool
	}{
		{name: "unset is false", set: false, want: false},
		{name: `"true"`, set: true, value: "true", want: true},
		{name: `"1"`, set: true, value: "1", want: true},
		{name: `"T"`, set: true, value: "T", want: true},
		{name: `"false"`, set: true, value: "false", want: false},
		{name: "whitespace is trimmed", set: true, value: " true ", want: true},
		{name: "empty is false", set: true, value: "", want: false},
		// It reads as an affirmative and is not one, which is the case worth pinning: an
		// operator writing yes gets the setting off.
		{name: `"yes" is not parseable, so false`, set: true, value: "yes", want: false},
		{name: `"maybe" is not parseable, so false`, set: true, value: "maybe", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnvAsBool(key); got != tt.want {
				t.Errorf("getEnvAsBool(%s=%q) = %v, want %v", key, tt.value, got, tt.want)
			}
		})
	}
}

func TestIsCookieSecure(t *testing.T) {
	// Secure is derived solely from the base URL scheme (there is no override), and from this
	// process's own base URL: the auth server's cookies are decided in the auth server, which
	// is why there is no IsCookieSecure on the peer struct to test beside this one (#351).
	tests := []struct {
		name    string
		baseURL string
		want    bool
	}{
		{"http -> not secure (dev)", "http://localhost:9091", false},
		{"https -> secure", "https://admin.example.com", true},
		{"HTTPS uppercase -> secure", "HTTPS://ADMIN.EXAMPLE.COM", true},
		{"whitespace-padded https -> secure", "  https://admin.example.com  ", true},
		{"empty -> not secure", "", false},
		{"non-http scheme -> not secure", "ftp://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AdminConsoleConfig{BaseURL: tt.baseURL}
			if got := ac.IsCookieSecure(); got != tt.want {
				t.Errorf("AdminConsoleConfig.IsCookieSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeprecatedEnvVarsPresent(t *testing.T) {
	const a = "GOIABADA_TEST_DEPRECATED_A"
	const b = "GOIABADA_TEST_DEPRECATED_B"

	t.Run("none set -> empty", func(t *testing.T) {
		if got := deprecatedEnvVarsPresent(a, b); len(got) != 0 {
			t.Errorf("expected none present, got %#v", got)
		}
	})

	t.Run("one set -> only that one", func(t *testing.T) {
		t.Setenv(a, "true")
		got := deprecatedEnvVarsPresent(a, b)
		if len(got) != 1 || got[0] != a {
			t.Errorf("expected [%s], got %#v", a, got)
		}
	})

	t.Run("empty value still counts as present", func(t *testing.T) {
		t.Setenv(b, "")
		got := deprecatedEnvVarsPresent(a, b)
		if len(got) != 1 || got[0] != b {
			t.Errorf("expected [%s] (empty value is still set), got %#v", b, got)
		}
	})
}

// validAuthKey is 64 bytes as 128 hex characters (openssl rand -hex 64).
var validAuthKey = strings.Repeat("ab", 64)

// validEncKey is 32 bytes as 64 hex characters (openssl rand -hex 32).
var validEncKey = strings.Repeat("cd", 32)

// Session keys sign and encrypt the browser session cookie. A short or absent key must fail
// startup rather than silently weakening the cookie, so the validator is exercised across
// every rejection branch.
func TestValidateAdminConsoleSessionKeys(t *testing.T) {
	savedAuth := cfg.AdminConsole.SessionAuthenticationKey
	savedEnc := cfg.AdminConsole.SessionEncryptionKey
	savedPrevAuth := cfg.AdminConsole.SessionAuthenticationKeyPrevious
	savedPrevEnc := cfg.AdminConsole.SessionEncryptionKeyPrevious
	defer func() {
		cfg.AdminConsole.SessionAuthenticationKey = savedAuth
		cfg.AdminConsole.SessionEncryptionKey = savedEnc
		cfg.AdminConsole.SessionAuthenticationKeyPrevious = savedPrevAuth
		cfg.AdminConsole.SessionEncryptionKeyPrevious = savedPrevEnc
	}()

	tests := []struct {
		name        string
		authKey     string
		encKey      string
		prevAuthKey string
		prevEncKey  string
		wantErr     bool
		wantErrPart string
	}{
		{
			name:    "both keys valid",
			authKey: validAuthKey,
			encKey:  validEncKey,
		},
		{
			name:        "authentication key missing",
			authKey:     "",
			encKey:      validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY is required",
		},
		{
			name:        "encryption key missing",
			authKey:     validAuthKey,
			encKey:      "",
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY is required",
		},
		{
			name:        "authentication key not hex",
			authKey:     strings.Repeat("zz", 64),
			encKey:      validEncKey,
			wantErr:     true,
			wantErrPart: "must be hex-encoded",
		},
		{
			name:        "encryption key not hex",
			authKey:     validAuthKey,
			encKey:      strings.Repeat("zz", 32),
			wantErr:     true,
			wantErrPart: "must be hex-encoded",
		},
		{
			name:        "authentication key too short",
			authKey:     strings.Repeat("ab", 32),
			encKey:      validEncKey,
			wantErr:     true,
			wantErrPart: "must be 64 bytes",
		},
		{
			name:        "encryption key too short",
			authKey:     validAuthKey,
			encKey:      strings.Repeat("cd", 16),
			wantErr:     true,
			wantErrPart: "must be 32 bytes",
		},
		{
			name:        "encryption key too long",
			authKey:     validAuthKey,
			encKey:      strings.Repeat("cd", 33),
			wantErr:     true,
			wantErrPart: "must be 32 bytes",
		},
		{
			// The ordinary state: no rotation in progress, so there is no previous pair to
			// validate. Named rather than left implicit, because every case above it now
			// relies on the previous pair being absent.
			name:    "previous pair absent",
			authKey: validAuthKey,
			encKey:  validEncKey,
		},
		{
			name:        "previous pair valid",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			prevEncKey:  validEncKey,
		},
		{
			// Half a previous pair opens nothing, so it is refused rather than read as no
			// rotation. An operator who mistyped one variable name would otherwise be told
			// the rotation is in place while every session it was meant to keep alive is
			// turned away.
			name:        "previous authentication key set alone",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS is required",
		},
		{
			name:        "previous encryption key set alone",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS is required",
		},
		{
			name:        "previous authentication key not hex",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: strings.Repeat("zz", 64),
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS must be hex-encoded",
		},
		{
			name:        "previous encryption key not hex",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			prevEncKey:  strings.Repeat("zz", 32),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS must be hex-encoded",
		},
		{
			name:        "previous authentication key wrong length",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: strings.Repeat("ab", 32),
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY_PREVIOUS must be 64 bytes",
		},
		{
			name:        "previous encryption key wrong length",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			prevEncKey:  strings.Repeat("cd", 33),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY_PREVIOUS must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AdminConsole.SessionAuthenticationKey = tt.authKey
			cfg.AdminConsole.SessionEncryptionKey = tt.encKey
			cfg.AdminConsole.SessionAuthenticationKeyPrevious = tt.prevAuthKey
			cfg.AdminConsole.SessionEncryptionKeyPrevious = tt.prevEncKey

			err := ValidateAdminConsoleSessionKeys()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// setEnvOrUnset sets key to value, or removes it from the environment when value is nil.
// t.Setenv is what registers the restore, so the unset arm sets a placeholder first and then
// removes it: without that call the original value would not come back after the test.
func setEnvOrUnset(t *testing.T, key string, value *string) {
	t.Helper()
	t.Setenv(key, "placeholder-for-the-restore")
	if value == nil {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("could not unset %s: %v", key, err)
		}
		return
	}
	t.Setenv(key, *value)
}

func strPtr(s string) *string { return &s }

// The client id and the issuer stopped being admin console configuration in #285. A
// deployment upgrading from a release that had them keeps whatever it set, and a value that
// is silently ignored is the state the change exists to end: the wrong client id used to
// surface as a token failure naming a client the operator never configured, and a stale
// issuer locked the administrator out of the console entirely. Both are refusals at startup
// instead, so every arm of the decision is pinned here.
func TestValidateRemovedAdminConsoleVars(t *testing.T) {
	tests := []struct {
		name        string
		clientID    *string
		issuer      *string
		wantErr     bool
		wantErrPart string
	}{
		{
			name: "neither set",
		},
		{
			name:     "client id set to the constant",
			clientID: strPtr("admin-console-client"),
		},
		{
			name:     "client id set to the constant with surrounding whitespace",
			clientID: strPtr("  admin-console-client  "),
		},
		{
			name:        "client id set to another client",
			clientID:    strPtr("my-own-client"),
			wantErr:     true,
			wantErrPart: `GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID is set to "my-own-client"`,
		},
		{
			name:        "client id set empty",
			clientID:    strPtr(""),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID is set to \"\"",
		},
		{
			name:        "issuer set to a value",
			issuer:      strPtr("https://auth.example.com"),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_ISSUER is set",
		},
		{
			name:        "issuer set empty",
			issuer:      strPtr(""),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_ISSUER is set",
		},
		{
			// Both wrong at once reports the client id, which is the one that would
			// otherwise fail as an unrecognised client rather than as a lockout.
			name:        "both set wrongly reports the client id first",
			clientID:    strPtr("my-own-client"),
			issuer:      strPtr("https://auth.example.com"),
			wantErr:     true,
			wantErrPart: "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setEnvOrUnset(t, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID", tt.clientID)
			setEnvOrUnset(t, "GOIABADA_ADMINCONSOLE_ISSUER", tt.issuer)

			err := ValidateRemovedAdminConsoleVars()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected a refusal, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected refusal: %v", err)
			}
		})
	}
}

// The remedy is the whole point of the message: an operator meeting it has to know the value
// the admin console actually uses, not merely that theirs is wrong.
func TestValidateRemovedAdminConsoleVars_MessageCarriesTheRemedy(t *testing.T) {
	setEnvOrUnset(t, "GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID", strPtr("my-own-client"))
	setEnvOrUnset(t, "GOIABADA_ADMINCONSOLE_ISSUER", nil)

	err := ValidateRemovedAdminConsoleVars()
	if err == nil {
		t.Fatalf("expected a refusal, got nil")
	}
	if !strings.Contains(err.Error(), constants.AdminConsoleClientIdentifier) {
		t.Errorf("the refusal %q does not name the client the admin console authenticates as", err.Error())
	}
	if !strings.Contains(err.Error(), "Remove") {
		t.Errorf("the refusal %q does not say what to do about it", err.Error())
	}
}

// GetEffectiveBaseURL lets a deployment reach the auth server over an internal
// address (container network, service mesh) while still publishing a public URL.
func TestGetEffectiveBaseURL(t *testing.T) {
	tests := []struct {
		name            string
		baseURL         string
		internalBaseURL string
		want            string
	}{
		{
			name:    "no internal URL falls back to the public one",
			baseURL: "https://auth.example.com",
			want:    "https://auth.example.com",
		},
		{
			name:            "internal URL takes precedence",
			baseURL:         "https://auth.example.com",
			internalBaseURL: "http://authserver:9090",
			want:            "http://authserver:9090",
		},
		{
			name:            "empty internal URL falls back",
			baseURL:         "https://auth.example.com",
			internalBaseURL: "",
			want:            "https://auth.example.com",
		},
		{
			name:            "a whitespace-only internal URL falls back",
			baseURL:         "https://auth.example.com",
			internalBaseURL: "   ",
			want:            "https://auth.example.com",
		},
		{
			name: "both empty",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AuthServerConfig{
				BaseURL:         tt.baseURL,
				InternalBaseURL: tt.internalBaseURL,
			}

			if got := c.GetEffectiveBaseURL(); got != tt.want {
				t.Errorf("GetEffectiveBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Seam 2: the two log settings, from the environment and from the command line
// -----------------------------------------------------------------------------

// logEnvVars is every variable the cases below read, cleared before each one so
// a developer's own environment cannot decide what a default case observes.
var logEnvVars = []string{
	"GOIABADA_ADMINCONSOLE_LOG_LEVEL",
	"GOIABADA_ADMINCONSOLE_LOG_FORMAT",
}

// logSettings is compared whole against a positional literal in the `want:` of every case, so
// every field is read by that comparison and none of them by selector.
//
//nolint:unused // read whole by comparison, never by selector
type logSettings struct {
	adminLevel  string
	adminFormat string
}

// unsetEnv removes key for the duration of the test and puts it back after.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	previous, exists := os.LookupEnv(key)
	if !exists {
		return
	}
	t.Cleanup(func() { _ = os.Setenv(key, previous) })
	_ = os.Unsetenv(key)
}

// TestLoadFrom_TrustedProxies is the consumer half of the trusted-proxy parse:
// the table of what an entry means is ParseTrustedProxies' own, in core. Here it
// is only that the list loadFrom reads reaches it, and that a refusal names the
// setting an operator has to fix (#425).
func TestLoadFrom_TrustedProxies(t *testing.T) {
	const key = "GOIABADA_ADMINCONSOLE_TRUSTED_PROXIES"
	tests := []struct {
		name       string
		value      *string
		wantRanges []string
		wantErr    []string
	}{
		{name: "unset: no ranges and no error", value: nil},
		{name: "a valid list", value: ptr(" 10.0.0.0/8 , 192.168.1.5 "), wantRanges: []string{"10.0.0.0/8", "192.168.1.5/32"}},
		{
			name:    "every entry malformed",
			value:   ptr("not-an-ip,10.0.0.0/33"),
			wantErr: []string{key, "--adminconsole-trusted-proxies", `"not-an-ip"`, `"10.0.0.0/33"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetEnv(t, key)
			if tt.value != nil {
				t.Setenv(key, *tt.value)
			}
			saved := cfg
			t.Cleanup(func() { cfg = saved })

			fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			loadFrom(fs, nil)

			ranges, err := cfg.AdminConsole.TrustedProxyRanges()
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("TrustedProxyRanges() = %v, want an error", ranges)
				}
				if ranges != nil {
					t.Errorf("TrustedProxyRanges() ranges = %v, want nil beside the error", ranges)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not name %s", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("TrustedProxyRanges() error = %v", err)
			}
			got := make([]string, 0, len(ranges))
			for _, r := range ranges {
				got = append(got, r.String())
			}
			if len(tt.wantRanges) == 0 {
				if ranges != nil {
					t.Errorf("TrustedProxyRanges() = %v, want nil", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.wantRanges) {
				t.Errorf("TrustedProxyRanges() = %v, want %v", got, tt.wantRanges)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// loadLogSettings drives loadFrom with its own flag set, which is the whole
// reason that seam exists: the flags are registered on the set handed in, so
// each case gets a fresh registration instead of panicking on the second.
func loadLogSettings(t *testing.T, env map[string]string, args []string) logSettings {
	t.Helper()

	for _, key := range logEnvVars {
		unsetEnv(t, key)
	}
	for key, value := range env {
		t.Setenv(key, value)
	}

	saved := cfg
	t.Cleanup(func() { cfg = saved })

	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	loadFrom(fs, args)

	return logSettings{
		adminLevel:  cfg.AdminConsole.LogLevel,
		adminFormat: cfg.AdminConsole.LogFormat,
	}
}

func TestLoadFrom_LogSettings(t *testing.T) {
	// Every flag case sets its variable to a value the flag does not use, so a
	// pass cannot come from the environment having supplied the same answer.
	tests := []struct {
		name string
		env  map[string]string
		args []string
		want logSettings
	}{
		{
			name: "nothing set at all",
			want: logSettings{"info", "text"},
		},
		{
			name: "the level, from the environment",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_LEVEL": "debug"},
			want: logSettings{"debug", "text"},
		},
		{
			name: "the format, from the environment",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_FORMAT": "json"},
			want: logSettings{"info", "json"},
		},
		{
			name: "the level, from the command line",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_LEVEL": "debug"},
			args: []string{"--adminconsole-log-level=warn"},
			want: logSettings{"warn", "text"},
		},
		{
			name: "the format, from the command line",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_FORMAT": "text"},
			args: []string{"--adminconsole-log-format=json"},
			want: logSettings{"info", "json"},
		},
		{
			name: "both at once, each with its own value",
			env: map[string]string{
				"GOIABADA_ADMINCONSOLE_LOG_LEVEL":  "debug",
				"GOIABADA_ADMINCONSOLE_LOG_FORMAT": "json",
			},
			want: logSettings{"debug", "json"},
		},
		{
			name: "an unrecognised value is carried through unchanged",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_LEVEL": "verbose"},
			// Nothing here validates: logging.Install refuses at startup, so the
			// value is checked once, where it is used, and the server names it in
			// the failure rather than silently falling back to info.
			want: logSettings{"verbose", "text"},
		},
		{
			name: "a variable set to the empty string is not the default",
			env:  map[string]string{"GOIABADA_ADMINCONSOLE_LOG_FORMAT": ""},
			want: logSettings{"info", ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := loadLogSettings(t, test.env, test.args)

			if got != test.want {
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}
