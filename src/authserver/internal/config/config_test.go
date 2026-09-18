package config

import (
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestValidateAESEncryptionKey(t *testing.T) {
	saved := cfg.AESEncryptionKey
	defer func() { cfg.AESEncryptionKey = saved }()

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid 32-byte hex", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", false},
		{"empty", "", true},
		{"not hex", "zzzz", true},
		{"too short (16 bytes)", "00112233445566778899aabbccddeeff", true},
		{"too long (33 bytes)", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AESEncryptionKey = tt.key
			err := ValidateAESEncryptionKey()
			if tt.wantErr && err == nil {
				t.Errorf("ValidateAESEncryptionKey(%q): expected error, got nil", tt.key)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateAESEncryptionKey(%q): unexpected error: %v", tt.key, err)
			}
			if !tt.wantErr {
				if got := GetAESEncryptionKey(); len(got) != 32 {
					t.Errorf("GetAESEncryptionKey() length = %d, want 32", len(got))
				}
			}
		})
	}
}

func TestValidateAESEncryptionKey_Previous(t *testing.T) {
	savedCur := cfg.AESEncryptionKey
	savedPrev := cfg.AESEncryptionKeyPrevious
	defer func() {
		cfg.AESEncryptionKey = savedCur
		cfg.AESEncryptionKeyPrevious = savedPrev
	}()

	cfg.AESEncryptionKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	tests := []struct {
		name    string
		prev    string
		wantErr bool
	}{
		{"absent is fine", "", false},
		{"valid previous", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", false},
		{"previous not hex", "zzzz", true},
		{"previous wrong length", "00112233445566778899aabbccddeeff", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AESEncryptionKeyPrevious = tt.prev
			err := ValidateAESEncryptionKey()
			if tt.wantErr && err == nil {
				t.Errorf("expected error for previous=%q, got nil", tt.prev)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for previous=%q: %v", tt.prev, err)
			}
			if !tt.wantErr && tt.prev != "" && len(GetAESEncryptionKeyPrevious()) != 32 {
				t.Errorf("GetAESEncryptionKeyPrevious() length = %d, want 32", len(GetAESEncryptionKeyPrevious()))
			}
		})
	}
}

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

func TestGetEnvAsBoolDefault(t *testing.T) {
	const key = "GOIABADA_TEST_DB_CREATE"

	// Every case is run against both defaults, so the default is observed rather than assumed:
	// a case that only ever ran with defaultVal=false could not tell the fallback apart from
	// a parsed false.
	tests := []struct {
		name string
		// set is false for the unset case, which is the one the helper exists for.
		set          bool
		value        string
		wantTrueDef  bool
		wantFalseDef bool
	}{
		{name: "unset returns the default", set: false, wantTrueDef: true, wantFalseDef: false},
		{name: `"true"`, set: true, value: "true", wantTrueDef: true, wantFalseDef: true},
		{name: `"1"`, set: true, value: "1", wantTrueDef: true, wantFalseDef: true},
		{name: `"T"`, set: true, value: "T", wantTrueDef: true, wantFalseDef: true},
		{name: `"TRUE"`, set: true, value: "TRUE", wantTrueDef: true, wantFalseDef: true},
		{name: `"false"`, set: true, value: "false", wantTrueDef: false, wantFalseDef: false},
		{name: `"0"`, set: true, value: "0", wantTrueDef: false, wantFalseDef: false},
		{name: `"f"`, set: true, value: "f", wantTrueDef: false, wantFalseDef: false},
		{name: "whitespace is trimmed", set: true, value: " false ", wantTrueDef: false, wantFalseDef: false},
		// strconv.ParseBool rejects all four, so each falls back to the default. Keep the
		// "no" case: it reads as false and is not, and against defaultVal=true it returns true.
		{name: `"yes" is not parseable`, set: true, value: "yes", wantTrueDef: true, wantFalseDef: false},
		{name: `"no" is not parseable`, set: true, value: "no", wantTrueDef: true, wantFalseDef: false},
		{name: "empty is not parseable", set: true, value: "", wantTrueDef: true, wantFalseDef: false},
		{name: `"maybe" is not parseable`, set: true, value: "maybe", wantTrueDef: true, wantFalseDef: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv cannot unset, but it registers the restore, so setting then
			// unsetting leaves the variable absent for this subtest only.
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnvAsBoolDefault(key, true); got != tt.wantTrueDef {
				t.Errorf("getEnvAsBoolDefault(%s=%q, true) = %v, want %v", key, tt.value, got, tt.wantTrueDef)
			}
			if got := getEnvAsBoolDefault(key, false); got != tt.wantFalseDef {
				t.Errorf("getEnvAsBoolDefault(%s=%q, false) = %v, want %v", key, tt.value, got, tt.wantFalseDef)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	const key = "GOIABADA_TEST_GETENV"

	// Both sides are trimmed, which is the rule a quoted value in a compose file or an env
	// file meets: GOIABADA_DB_HOST=" db " is the same host as GOIABADA_DB_HOST=db.
	tests := []struct {
		name string
		// set is false for the unset case, which is what the default is for.
		set        bool
		value      string
		defaultVal string
		want       string
	}{
		{name: "unset returns the default", set: false, defaultVal: "sqlite", want: "sqlite"},
		{name: "unset returns the default trimmed", set: false, defaultVal: "  sqlite  ", want: "sqlite"},
		{name: "set returns the value", set: true, value: "mysql", defaultVal: "sqlite", want: "mysql"},
		{name: "set returns the value trimmed", set: true, value: "  mysql\t", defaultVal: "sqlite", want: "mysql"},
		// Present-and-empty is a value, not an absence: os.LookupEnv reports it as set, so
		// the default does not apply. An operator who writes GOIABADA_AUTHSERVER_LOG_FORMAT=
		// has chosen the empty string.
		{name: "set to empty is not the default", set: true, value: "", defaultVal: "sqlite", want: ""},
		{name: "set to whitespace only is not the default", set: true, value: "   ", defaultVal: "sqlite", want: ""},
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
		{name: "unset returns the default", set: false, want: 9443},
		{name: "a number", set: true, value: "8443", want: 8443},
		{name: "a negative number", set: true, value: "-1", want: -1},
		{name: "whitespace is trimmed", set: true, value: "  8443  ", want: 8443},
		{name: "empty falls back", set: true, value: "", want: 9443},
		{name: "non-numeric falls back", set: true, value: "https", want: 9443},
		{name: "a decimal falls back", set: true, value: "8443.0", want: 9443},
		{name: "an overflowing number falls back", set: true, value: "99999999999999999999", want: 9443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnvAsInt(key, 9443); got != tt.want {
				t.Errorf("getEnvAsInt(%s=%q, 9443) = %d, want %d", key, tt.value, got, tt.want)
			}
		})
	}
}

func TestGetEnvAsInt64(t *testing.T) {
	const key = "GOIABADA_TEST_MAX_SIZE"
	const defaultVal = int64(3 * 1024 * 1024)

	tests := []struct {
		name  string
		set   bool
		value string
		want  int64
	}{
		{name: "unset returns the default", set: false, want: defaultVal},
		{name: "a number", set: true, value: "5242880", want: 5242880},
		// The reason this one is int64 rather than int: a size beyond the 32-bit range.
		{name: "a number beyond 32 bits", set: true, value: "4294967296", want: 4294967296},
		{name: "whitespace is trimmed", set: true, value: " 5242880 ", want: 5242880},
		{name: "empty falls back", set: true, value: "", want: defaultVal},
		{name: "non-numeric falls back", set: true, value: "3MB", want: defaultVal},
		{name: "an overflowing number falls back", set: true, value: "99999999999999999999", want: defaultVal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if !tt.set {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv(%s) = %v", key, err)
				}
			}
			if got := getEnvAsInt64(key, defaultVal); got != tt.want {
				t.Errorf("getEnvAsInt64(%s=%q, %d) = %d, want %d", key, tt.value, defaultVal, got, tt.want)
			}
		})
	}
}

func TestGetEnvAsBool(t *testing.T) {
	const key = "GOIABADA_TEST_TRUST_PROXY_HEADERS"

	// getEnvAsBool can only ever express default-false: anything unparseable is false, which
	// is the safe answer for every setting that reaches it (each one turns something on).
	// A setting whose default is true goes through getEnvAsBoolDefault instead (#293).
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
	// Secure is derived solely from the base URL scheme (there is no override).
	tests := []struct {
		name    string
		baseURL string
		want    bool
	}{
		{"http -> not secure (dev)", "http://localhost:9090", false},
		{"https -> secure", "https://auth.example.com", true},
		{"HTTPS uppercase -> secure", "HTTPS://AUTH.EXAMPLE.COM", true},
		{"whitespace-padded https -> secure", "  https://auth.example.com  ", true},
		{"empty -> not secure", "", false},
		{"non-http scheme -> not secure", "ftp://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := &AuthServerConfig{BaseURL: tt.baseURL}
			if got := as.IsCookieSecure(); got != tt.want {
				t.Errorf("AuthServerConfig.IsCookieSecure() = %v, want %v", got, tt.want)
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

// Session keys sign and encrypt the browser session cookie. A short or absent
// key must fail startup rather than silently weakening the cookie, so both
// validators are exercised across every rejection branch.
func TestValidateAuthServerSessionKeys(t *testing.T) {
	savedAuth := cfg.AuthServer.SessionAuthenticationKey
	savedEnc := cfg.AuthServer.SessionEncryptionKey
	savedPrevAuth := cfg.AuthServer.SessionAuthenticationKeyPrevious
	savedPrevEnc := cfg.AuthServer.SessionEncryptionKeyPrevious
	defer func() {
		cfg.AuthServer.SessionAuthenticationKey = savedAuth
		cfg.AuthServer.SessionEncryptionKey = savedEnc
		cfg.AuthServer.SessionAuthenticationKeyPrevious = savedPrevAuth
		cfg.AuthServer.SessionEncryptionKeyPrevious = savedPrevEnc
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
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY is required",
		},
		{
			name:        "encryption key missing",
			authKey:     validAuthKey,
			encKey:      "",
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY is required",
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
			name:        "authentication key too long",
			authKey:     strings.Repeat("ab", 65),
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
			name:        "odd number of hex characters",
			authKey:     strings.Repeat("ab", 63) + "a",
			encKey:      validEncKey,
			wantErr:     true,
			wantErrPart: "must be hex-encoded",
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
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS is required",
		},
		{
			name:        "previous encryption key set alone",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS is required",
		},
		{
			name:        "previous authentication key not hex",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: strings.Repeat("zz", 64),
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS must be hex-encoded",
		},
		{
			name:        "previous encryption key not hex",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			prevEncKey:  strings.Repeat("zz", 32),
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS must be hex-encoded",
		},
		{
			name:        "previous authentication key wrong length",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: strings.Repeat("ab", 32),
			prevEncKey:  validEncKey,
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS must be 64 bytes",
		},
		{
			name:        "previous encryption key wrong length",
			authKey:     validAuthKey,
			encKey:      validEncKey,
			prevAuthKey: validAuthKey,
			prevEncKey:  strings.Repeat("cd", 33),
			wantErr:     true,
			wantErrPart: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AuthServer.SessionAuthenticationKey = tt.authKey
			cfg.AuthServer.SessionEncryptionKey = tt.encKey
			cfg.AuthServer.SessionAuthenticationKeyPrevious = tt.prevAuthKey
			cfg.AuthServer.SessionEncryptionKeyPrevious = tt.prevEncKey

			err := ValidateAuthServerSessionKeys()

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

func TestSimpleAccessors(t *testing.T) {
	savedEmail := cfg.AdminEmail
	savedPassword := cfg.AdminPassword
	savedAppName := cfg.AppName
	defer func() {
		cfg.AdminEmail = savedEmail
		cfg.AdminPassword = savedPassword
		cfg.AppName = savedAppName
	}()

	cfg.AdminEmail = "admin@example.com"
	cfg.AdminPassword = "s3cret"
	cfg.AppName = "Goiabada Test"

	if got := GetAdminEmail(); got != "admin@example.com" {
		t.Errorf("GetAdminEmail() = %q", got)
	}
	if got := GetAdminPassword(); got != "s3cret" {
		t.Errorf("GetAdminPassword() = %q", got)
	}
	if got := GetAppName(); got != "Goiabada Test" {
		t.Errorf("GetAppName() = %q", got)
	}
}

// -----------------------------------------------------------------------------
// The log settings, from the environment and from the command line
// -----------------------------------------------------------------------------
//
// The general matrix in load_matrix_test.go already covers the default, the environment value and
// the flag for both of these. What stays here are the two rows it cannot express: a value nothing
// validates, and a variable set to the empty string. The admin console's half of this table went
// with the admin console (#351).

// logEnvVars is every variable the cases below read, cleared before each one so
// a developer's own environment cannot decide what a default case observes.
var logEnvVars = []string{
	"GOIABADA_AUTHSERVER_LOG_LEVEL",
	"GOIABADA_AUTHSERVER_LOG_FORMAT",
}

// logSettings is compared whole against a positional literal in the `want:` of every case, so
// every field is read by that comparison and none of them by selector.
//
//nolint:unused // read whole by comparison, never by selector
type logSettings struct {
	authLevel  string
	authFormat string
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
		authLevel:  cfg.AuthServer.LogLevel,
		authFormat: cfg.AuthServer.LogFormat,
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
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_LEVEL": "debug"},
			want: logSettings{"debug", "text"},
		},
		{
			name: "the format, from the environment",
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_FORMAT": "json"},
			want: logSettings{"info", "json"},
		},
		{
			name: "the level, from the command line",
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_LEVEL": "debug"},
			args: []string{"--authserver-log-level=warn"},
			want: logSettings{"warn", "text"},
		},
		{
			name: "the format, from the command line",
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_FORMAT": "text"},
			args: []string{"--authserver-log-format=json"},
			want: logSettings{"info", "json"},
		},
		{
			name: "both at once, each with its own value",
			env: map[string]string{
				"GOIABADA_AUTHSERVER_LOG_LEVEL":  "debug",
				"GOIABADA_AUTHSERVER_LOG_FORMAT": "json",
			},
			want: logSettings{"debug", "json"},
		},
		{
			name: "an unrecognised value is carried through unchanged",
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_LEVEL": "verbose"},
			// Nothing here validates: logging.Install refuses at startup, so the
			// value is checked once, where it is used, and the server names it in
			// the failure rather than silently falling back to info.
			want: logSettings{"verbose", "text"},
		},
		{
			name: "a variable set to the empty string is not the default",
			env:  map[string]string{"GOIABADA_AUTHSERVER_LOG_FORMAT": ""},
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
