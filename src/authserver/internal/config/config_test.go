package config

import (
	"bytes"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

const (
	testDataKeyHex         = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testPreviousDataKeyHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// TestDataKeys holds the current key's rule, with the messages ValidateAESEncryptionKey wrote
// word for word: an operator reading the refusal meets the text it always said. A refusal answers
// no key at all (#434).
func TestDataKeys(t *testing.T) {
	const hint = ". Generate with: openssl rand -hex 32"
	tests := []struct {
		name    string
		key     string
		wantErr string // the whole message, or "" for acceptance
	}{
		{"valid 32-byte hex", testDataKeyHex, ""},
		{"surrounding whitespace is trimmed", "  " + testDataKeyHex + "\t", ""},
		{"empty", "", "GOIABADA_AES_ENCRYPTION_KEY is required" + hint},
		{"whitespace only", "   ", "GOIABADA_AES_ENCRYPTION_KEY is required" + hint},
		{"not hex", "zzzz", "GOIABADA_AES_ENCRYPTION_KEY must be hex-encoded (error: encoding/hex: invalid byte: U+007A 'z')" + hint},
		{"too short (16 bytes)", "00112233445566778899aabbccddeeff",
			"GOIABADA_AES_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got 16 bytes" + hint},
		{"too long (33 bytes)", testDataKeyHex + "00",
			"GOIABADA_AES_ENCRYPTION_KEY must be 32 bytes (64 hex chars), got 33 bytes" + hint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{AESEncryptionKey: tt.key}
			current, previous, err := c.DataKeys()

			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("DataKeys() error = %v, want %q", err, tt.wantErr)
				}
				if current != nil || previous != nil {
					t.Errorf("DataKeys() refused and still answered keys %x, %x", current, previous)
				}
				return
			}
			if err != nil {
				t.Fatalf("DataKeys() = %v, want no error", err)
			}
			want, _ := hex.DecodeString(testDataKeyHex)
			if !bytes.Equal(current, want) {
				t.Errorf("DataKeys() current = %x, want %x", current, want)
			}
			if previous != nil {
				t.Errorf("DataKeys() previous = %x with none configured, want nil", previous)
			}
		})
	}
}

// TestDataKeys_Previous is the rotation key's half: optional, and held to the same rule when it is
// set, with the messages it always had, which carry no generate hint because the previous key is
// the one an operator already has.
func TestDataKeys_Previous(t *testing.T) {
	tests := []struct {
		name    string
		prev    string
		wantErr string
	}{
		{"absent is fine", "", ""},
		{"whitespace only is absent", "  ", ""},
		{"valid previous", testPreviousDataKeyHex, ""},
		{"previous not hex", "zzzz",
			"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS must be hex-encoded (error: encoding/hex: invalid byte: U+007A 'z')"},
		{"previous wrong length", "00112233445566778899aabbccddeeff",
			"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS must be 32 bytes (64 hex chars), got 16 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{AESEncryptionKey: testDataKeyHex, AESEncryptionKeyPrevious: tt.prev}
			current, previous, err := c.DataKeys()

			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("DataKeys() error = %v, want %q", err, tt.wantErr)
				}
				if current != nil || previous != nil {
					t.Errorf("DataKeys() refused and still answered keys %x, %x", current, previous)
				}
				return
			}
			if err != nil {
				t.Fatalf("DataKeys() = %v, want no error", err)
			}
			wantCurrent, _ := hex.DecodeString(testDataKeyHex)
			if !bytes.Equal(current, wantCurrent) {
				t.Errorf("DataKeys() current = %x, want %x", current, wantCurrent)
			}
			var wantPrevious []byte
			if strings.TrimSpace(tt.prev) != "" {
				wantPrevious, _ = hex.DecodeString(tt.prev)
			}
			if !bytes.Equal(previous, wantPrevious) || (wantPrevious == nil) != (previous == nil) {
				t.Errorf("DataKeys() previous = %#v, want %#v", previous, wantPrevious)
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

// assertRecorded holds a helper call to having recorded exactly the one problem want, or none
// when want is empty.
func assertRecorded(t *testing.T, malformed malformedValues, want string) {
	t.Helper()
	if want == "" {
		if len(malformed) != 0 {
			t.Errorf("recorded %q, want nothing", malformed)
		}
		return
	}
	if len(malformed) != 1 || malformed[0] != want {
		t.Errorf("recorded %q, want exactly [%q]", malformed, want)
	}
}

// setOrUnset sets key to value, or leaves it absent when set is false. t.Setenv cannot unset, but
// it registers the restore, so setting then unsetting leaves the variable absent for this subtest
// only.
func setOrUnset(t *testing.T, key string, set bool, value string) {
	t.Helper()
	t.Setenv(key, value)
	if !set {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("os.Unsetenv(%s) = %v", key, err)
		}
	}
}

func TestGetEnvAsBoolDefault(t *testing.T) {
	const key = "GOIABADA_TEST_DB_CREATE"

	// Every case is run against both defaults, so the default is observed rather than assumed:
	// a case that only ever ran with defaultVal=false could not tell the fallback apart from
	// a parsed false.
	//
	// Keep the refusal rows: they reverse the earlier position, that anything strconv.ParseBool
	// refuses falls back to the default, on purpose. "no" reads as false and against a true
	// default it was true, so GOIABADA_DB_CREATE=no created the database it said not to (#434).
	tests := []struct {
		name string
		// set is false for the unset case, which is the one the helper exists for.
		set          bool
		value        string
		wantTrueDef  bool
		wantFalseDef bool
		refusal      string // the one recorded problem, or "" for none
	}{
		{name: "unset returns the default", set: false, wantTrueDef: true, wantFalseDef: false},
		{name: "empty returns the default", set: true, value: "", wantTrueDef: true, wantFalseDef: false},
		{name: "whitespace only returns the default", set: true, value: "  ", wantTrueDef: true, wantFalseDef: false},
		{name: `"true"`, set: true, value: "true", wantTrueDef: true, wantFalseDef: true},
		{name: `"1"`, set: true, value: "1", wantTrueDef: true, wantFalseDef: true},
		{name: `"T"`, set: true, value: "T", wantTrueDef: true, wantFalseDef: true},
		{name: `"TRUE"`, set: true, value: "TRUE", wantTrueDef: true, wantFalseDef: true},
		{name: `"false"`, set: true, value: "false", wantTrueDef: false, wantFalseDef: false},
		{name: `"0"`, set: true, value: "0", wantTrueDef: false, wantFalseDef: false},
		{name: `"f"`, set: true, value: "f", wantTrueDef: false, wantFalseDef: false},
		{name: "whitespace is trimmed", set: true, value: " false ", wantTrueDef: false, wantFalseDef: false},
		{name: `"yes" is refused`, set: true, value: "yes", wantTrueDef: true, wantFalseDef: false,
			refusal: key + ` is "yes", not a boolean (true or false)`},
		{name: `"no" is refused`, set: true, value: "no", wantTrueDef: true, wantFalseDef: false,
			refusal: key + ` is "no", not a boolean (true or false)`},
		{name: `"on" is refused`, set: true, value: "on", wantTrueDef: true, wantFalseDef: false,
			refusal: key + ` is "on", not a boolean (true or false)`},
		{name: `"maybe" is refused`, set: true, value: "maybe", wantTrueDef: true, wantFalseDef: false,
			refusal: key + ` is "maybe", not a boolean (true or false)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnset(t, key, tt.set, tt.value)

			var malformed malformedValues
			if got := getEnvAsBoolDefault(key, true, &malformed); got != tt.wantTrueDef {
				t.Errorf("getEnvAsBoolDefault(%s=%q, true) = %v, want %v", key, tt.value, got, tt.wantTrueDef)
			}
			assertRecorded(t, malformed, tt.refusal)

			malformed = nil
			if got := getEnvAsBoolDefault(key, false, &malformed); got != tt.wantFalseDef {
				t.Errorf("getEnvAsBoolDefault(%s=%q, false) = %v, want %v", key, tt.value, got, tt.wantFalseDef)
			}
			assertRecorded(t, malformed, tt.refusal)
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

	// Unset or empty after the trim is the default, and records nothing: every Compose file the
	// setup wizard writes gives the https port empty to mean no https listener. Anything else strconv.Atoi
	// refuses is recorded as malformed.
	//
	// Keep the refusal rows: they reverse the earlier position, that a mistyped port falls back to
	// the port the server shipped with, on purpose. That fallback started a deployment on a port
	// its operator never chose and said nothing (#434).
	tests := []struct {
		name    string
		set     bool
		value   string
		want    int
		refusal string // the one recorded problem, or "" for none
	}{
		{name: "unset returns the default", set: false, want: 9443},
		{name: "empty returns the default", set: true, value: "", want: 9443},
		{name: "whitespace only returns the default", set: true, value: "   ", want: 9443},
		{name: "a number", set: true, value: "8443", want: 8443},
		{name: "a negative number", set: true, value: "-1", want: -1},
		{name: "whitespace is trimmed", set: true, value: "  8443  ", want: 8443},
		{name: "non-numeric is refused", set: true, value: "https", want: 9443,
			refusal: key + ` is "https", not an integer`},
		{name: "a decimal is refused", set: true, value: "9090.0", want: 9443,
			refusal: key + ` is "9090.0", not an integer`},
		{name: "a hexadecimal number is refused", set: true, value: "0x10", want: 9443,
			refusal: key + ` is "0x10", not an integer`},
		{name: "an overflowing number is refused", set: true, value: "99999999999999999999", want: 9443,
			refusal: key + ` is "99999999999999999999", not an integer`},
		{name: "the refusal quotes the trimmed value", set: true, value: " 80 80 ", want: 9443,
			refusal: key + ` is "80 80", not an integer`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnset(t, key, tt.set, tt.value)

			var malformed malformedValues
			if got := getEnvAsInt(key, 9443, &malformed); got != tt.want {
				t.Errorf("getEnvAsInt(%s=%q, 9443) = %d, want %d", key, tt.value, got, tt.want)
			}
			assertRecorded(t, malformed, tt.refusal)
		})
	}
}

func TestGetEnvAsInt64(t *testing.T) {
	const key = "GOIABADA_TEST_MAX_SIZE"
	const defaultVal = int64(3 * 1024 * 1024)

	// Keep the refusal rows, for getEnvAsInt's reason: a size written as 3MB used to be the
	// default size, silently (#434).
	tests := []struct {
		name    string
		set     bool
		value   string
		want    int64
		refusal string
	}{
		{name: "unset returns the default", set: false, want: defaultVal},
		{name: "empty returns the default", set: true, value: "", want: defaultVal},
		{name: "a number", set: true, value: "5242880", want: 5242880},
		// The reason this one is int64 rather than int: a size beyond the 32-bit range.
		{name: "a number beyond 32 bits", set: true, value: "4294967296", want: 4294967296},
		{name: "whitespace is trimmed", set: true, value: " 5242880 ", want: 5242880},
		{name: "non-numeric is refused", set: true, value: "3MB", want: defaultVal,
			refusal: key + ` is "3MB", not an integer`},
		{name: "a hexadecimal number is refused", set: true, value: "0x10", want: defaultVal,
			refusal: key + ` is "0x10", not an integer`},
		{name: "an overflowing number is refused", set: true, value: "99999999999999999999", want: defaultVal,
			refusal: key + ` is "99999999999999999999", not an integer`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnset(t, key, tt.set, tt.value)

			var malformed malformedValues
			if got := getEnvAsInt64(key, defaultVal, &malformed); got != tt.want {
				t.Errorf("getEnvAsInt64(%s=%q, %d) = %d, want %d", key, tt.value, defaultVal, got, tt.want)
			}
			assertRecorded(t, malformed, tt.refusal)
		})
	}
}

func TestGetEnvAsBool(t *testing.T) {
	const key = "GOIABADA_TEST_TRUST_PROXY_HEADERS"

	// getEnvAsBool's default is false; a setting whose default is true goes through
	// getEnvAsBoolDefault instead (#293). Unset or empty is that default; anything
	// strconv.ParseBool refuses is recorded as malformed.
	//
	// Keep the refusal rows: they reverse the earlier position, that anything unparseable is
	// false, on purpose. yes reads as an affirmative and is not one, so an operator writing it got
	// the setting off and nothing said so (#434).
	tests := []struct {
		name    string
		set     bool
		value   string
		want    bool
		refusal string
	}{
		{name: "unset is false", set: false, want: false},
		{name: "empty is false", set: true, value: "", want: false},
		{name: "whitespace only is false", set: true, value: "  ", want: false},
		{name: `"true"`, set: true, value: "true", want: true},
		{name: `"1"`, set: true, value: "1", want: true},
		{name: `"T"`, set: true, value: "T", want: true},
		{name: `"false"`, set: true, value: "false", want: false},
		{name: "whitespace is trimmed", set: true, value: " true ", want: true},
		{name: `"yes" is refused`, set: true, value: "yes", want: false,
			refusal: key + ` is "yes", not a boolean (true or false)`},
		{name: `"on" is refused`, set: true, value: "on", want: false,
			refusal: key + ` is "on", not a boolean (true or false)`},
		{name: `"maybe" is refused`, set: true, value: "maybe", want: false,
			refusal: key + ` is "maybe", not a boolean (true or false)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOrUnset(t, key, tt.set, tt.value)

			var malformed malformedValues
			if got := getEnvAsBool(key, &malformed); got != tt.want {
				t.Errorf("getEnvAsBool(%s=%q) = %v, want %v", key, tt.value, got, tt.want)
			}
			assertRecorded(t, malformed, tt.refusal)
		})
	}
}

func TestMalformedValues_Err(t *testing.T) {
	var none malformedValues
	if err := none.err(); err != nil {
		t.Errorf("err() with nothing recorded = %v, want nil", err)
	}

	two := malformedValues{`A is "x", not an integer`, `B is "y", not a boolean (true or false)`}
	want := `malformed configuration: A is "x", not an integer; B is "y", not a boolean (true or false)`
	if err := two.err(); err == nil || err.Error() != want {
		t.Errorf("err() = %v, want %q", err, want)
	}

	// A value carrying a newline is quoted, so the refusal stays the one line main writes.
	var newline malformedValues
	newline.add("C", "80\n80", "an integer")
	if err := newline.err(); err == nil || strings.Contains(err.Error(), "\n") {
		t.Errorf("err() = %q, want one line", err)
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

// Deliberately thin: the session-key rule and its exhaustive table are
// core/sessionstore's (TestParseKeys). What this owns is that SessionKeys hands
// ParseKeys this binary's four variable names, each in its own slot, so one
// accept per shape and one refusal per name.
func TestAuthServerConfig_SessionKeys(t *testing.T) {
	previousAuthKey := strings.Repeat("12", 64)
	previousEncKey := strings.Repeat("34", 32)

	tests := []struct {
		name         string
		config       AuthServerConfig
		wantPrevious bool
		wantErr      string
	}{
		{
			name:   "the current pair alone gives no previous pair",
			config: AuthServerConfig{SessionAuthenticationKey: validAuthKey, SessionEncryptionKey: validEncKey},
		},
		{
			name: "both pairs",
			config: AuthServerConfig{
				SessionAuthenticationKey:         validAuthKey,
				SessionEncryptionKey:             validEncKey,
				SessionAuthenticationKeyPrevious: previousAuthKey,
				SessionEncryptionKeyPrevious:     previousEncKey,
			},
			wantPrevious: true,
		},
		{
			name:    "the authentication key missing",
			config:  AuthServerConfig{SessionEncryptionKey: validEncKey},
			wantErr: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY is required",
		},
		{
			name:    "the encryption key missing",
			config:  AuthServerConfig{SessionAuthenticationKey: validAuthKey},
			wantErr: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY is required",
		},
		{
			name: "the previous encryption key alone",
			config: AuthServerConfig{
				SessionAuthenticationKey:     validAuthKey,
				SessionEncryptionKey:         validEncKey,
				SessionEncryptionKeyPrevious: previousEncKey,
			},
			wantErr: "GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY_PREVIOUS is required when GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS is set: both halves of the previous pair are needed to open a session sealed under it",
		},
		{
			name: "the previous encryption key at 33 bytes",
			config: AuthServerConfig{
				SessionAuthenticationKey:         validAuthKey,
				SessionEncryptionKey:             validEncKey,
				SessionAuthenticationKeyPrevious: previousAuthKey,
				SessionEncryptionKeyPrevious:     strings.Repeat("34", 33),
			},
			wantErr: "GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY_PREVIOUS must be 32 bytes (64 hex chars), got 33 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current, previous, err := tt.config.SessionKeys()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				if err.Error() != tt.wantErr {
					t.Errorf("error\n got %q\nwant %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hex.EncodeToString(current.AuthenticationKey) != validAuthKey ||
				hex.EncodeToString(current.EncryptionKey) != validEncKey {
				t.Errorf("the current pair did not decode from the two current variables")
			}
			if !tt.wantPrevious {
				if previous != nil {
					t.Errorf("expected no previous pair, got %+v", previous)
				}
				return
			}
			if previous == nil {
				t.Fatalf("expected a previous pair, got nil")
			}
			if hex.EncodeToString(previous.AuthenticationKey) != previousAuthKey ||
				hex.EncodeToString(previous.EncryptionKey) != previousEncKey {
				t.Errorf("the previous pair did not decode from the two previous variables")
			}
		})
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

// TestLoad_TrustedProxies is the consumer half of the trusted-proxy parse:
// the table of what an entry means is ParseTrustedProxies' own, in core. Here it
// is only that the list Load reads reaches it, and that a refusal names the
// setting an operator has to fix (#425).
func TestLoad_TrustedProxies(t *testing.T) {
	const key = "GOIABADA_AUTHSERVER_TRUSTED_PROXIES"
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
			wantErr: []string{key, "--authserver-trusted-proxies", `"not-an-ip"`, `"10.0.0.0/33"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetEnv(t, key)
			if tt.value != nil {
				t.Setenv(key, *tt.value)
			}
			fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			c, err := Load(fs, nil)
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}

			ranges, err := c.AuthServer.TrustedProxyRanges()
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

// loadLogSettings drives Load with its own flag set: the flags are registered on the set handed
// in, so each case gets a fresh registration instead of panicking on the second.
func loadLogSettings(t *testing.T, env map[string]string, args []string) logSettings {
	t.Helper()

	for _, key := range logEnvVars {
		unsetEnv(t, key)
	}
	for key, value := range env {
		t.Setenv(key, value)
	}

	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c, err := Load(fs, args)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}

	return logSettings{
		authLevel:  c.AuthServer.LogLevel,
		authFormat: c.AuthServer.LogFormat,
	}
}

func TestLoad_LogSettings(t *testing.T) {
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
