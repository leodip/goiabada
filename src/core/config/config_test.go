package config

import (
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

// Session keys sign and encrypt the browser session cookie. A short or absent
// key must fail startup rather than silently weakening the cookie, so both
// validators are exercised across every rejection branch.
func TestValidateAuthServerSessionKeys(t *testing.T) {
	savedAuth := cfg.AuthServer.SessionAuthenticationKey
	savedEnc := cfg.AuthServer.SessionEncryptionKey
	defer func() {
		cfg.AuthServer.SessionAuthenticationKey = savedAuth
		cfg.AuthServer.SessionEncryptionKey = savedEnc
	}()

	tests := []struct {
		name        string
		authKey     string
		encKey      string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AuthServer.SessionAuthenticationKey = tt.authKey
			cfg.AuthServer.SessionEncryptionKey = tt.encKey

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

func TestValidateAdminConsoleSessionKeys(t *testing.T) {
	savedAuth := cfg.AdminConsole.SessionAuthenticationKey
	savedEnc := cfg.AdminConsole.SessionEncryptionKey
	defer func() {
		cfg.AdminConsole.SessionAuthenticationKey = savedAuth
		cfg.AdminConsole.SessionEncryptionKey = savedEnc
	}()

	tests := []struct {
		name        string
		authKey     string
		encKey      string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.AdminConsole.SessionAuthenticationKey = tt.authKey
			cfg.AdminConsole.SessionEncryptionKey = tt.encKey

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

// The two validators must be independent: admin console keys being wrong must
// not make the auth server's keys look wrong, and vice versa.
func TestSessionKeyValidatorsAreIndependent(t *testing.T) {
	savedAuthServerAuth := cfg.AuthServer.SessionAuthenticationKey
	savedAuthServerEnc := cfg.AuthServer.SessionEncryptionKey
	savedAdminAuth := cfg.AdminConsole.SessionAuthenticationKey
	savedAdminEnc := cfg.AdminConsole.SessionEncryptionKey
	defer func() {
		cfg.AuthServer.SessionAuthenticationKey = savedAuthServerAuth
		cfg.AuthServer.SessionEncryptionKey = savedAuthServerEnc
		cfg.AdminConsole.SessionAuthenticationKey = savedAdminAuth
		cfg.AdminConsole.SessionEncryptionKey = savedAdminEnc
	}()

	cfg.AuthServer.SessionAuthenticationKey = validAuthKey
	cfg.AuthServer.SessionEncryptionKey = validEncKey
	cfg.AdminConsole.SessionAuthenticationKey = ""
	cfg.AdminConsole.SessionEncryptionKey = ""

	if err := ValidateAuthServerSessionKeys(); err != nil {
		t.Errorf("auth server keys should be valid regardless of admin console keys: %v", err)
	}
	if err := ValidateAdminConsoleSessionKeys(); err == nil {
		t.Error("admin console keys should be reported as missing")
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
