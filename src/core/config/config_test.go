package config

import (
	"reflect"
	"testing"
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
