package config

import (
	"reflect"
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
