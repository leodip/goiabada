package config

import (
	"strings"
	"testing"
)

// TestLoad_TheSMTPEHLOName is #718 decision 9 at the load: the name the auth server introduces
// itself to the SMTP relay by is a domain under RFC 1123 section 2.1's label rules (RFC 5321
// section 4.1.2) or an RFC 5321 section 4.1.3 address literal, [IPv4] or [IPv6:address] without a
// zone, landed in the case typed. Anything else stops the start on the malformed-configuration line:
// a bare IP address with the line saying to write it in brackets, and a general address literal,
// since no tag but IPv6 is registered.
func TestLoad_TheSMTPEHLOName(t *testing.T) {
	const (
		key     = "GOIABADA_AUTHSERVER_SMTP_EHLO_NAME"
		setting = key + " (--authserver-smtp-ehlo-name) is "
		notOne  = ", not a domain such as mail.example.com or an address literal such as [192.0.2.10] or [IPv6:2001:db8::10]"
	)
	label63 := strings.Repeat("a", 62) + "1"
	// Four labels of 63 and three dots: RFC 1123 section 2.1's 255 exactly.
	name255 := strings.Join([]string{label63, label63, label63, label63}, ".")
	// Three of 63, one of 62 and one of 1, with four dots: one past it, every label valid.
	name256 := strings.Join([]string{label63, label63, label63, label63[:62], "b"}, ".")

	tests := []struct {
		name    string
		env     string
		args    []string
		want    string
		refusal string
	}{
		{name: "unset is empty", want: ""},
		{name: "a domain", env: "mail.example.com", want: "mail.example.com"},
		{name: "a domain in the case typed", env: "Mail-1.Example.COM", want: "Mail-1.Example.COM"},
		{name: "a domain of one label", env: "relay", want: "relay"},
		{name: "a label starting with a digit", env: "1mail.example.com", want: "1mail.example.com"},
		{name: "a last label of letters and digits", env: "mail.example.c0m", want: "mail.example.c0m"},
		{name: "a label of 63", env: label63 + ".example.com", want: label63 + ".example.com"},
		{name: "a name of 255", env: name255, want: name255},
		{name: "spaces around it are trimmed", env: "  mail.example.com ", want: "mail.example.com"},
		{name: "from the flag", args: []string{"-authserver-smtp-ehlo-name=mail.example.org"}, want: "mail.example.org"},
		{name: "an IPv4 literal", env: "[192.0.2.10]", want: "[192.0.2.10]"},
		{name: "an IPv4 literal at its bounds", env: "[0.0.0.0]", want: "[0.0.0.0]"},
		{name: "an IPv4 literal of 255s", env: "[255.255.255.255]", want: "[255.255.255.255]"},
		{name: "an IPv6 literal", env: "[IPv6:2001:db8::10]", want: "[IPv6:2001:db8::10]"},
		{name: "an IPv6 literal in the case typed", env: "[ipv6:2001:DB8::10]", want: "[ipv6:2001:DB8::10]"},
		{name: "an IPv6 literal written in full", env: "[IPv6:2001:db8:0:0:0:0:0:10]", want: "[IPv6:2001:db8:0:0:0:0:0:10]"},
		{name: "an IPv6 literal with six groups beside ::", env: "[IPv6:1:2:3:4:5:6::]", want: "[IPv6:1:2:3:4:5:6::]"},
		{name: "an IPv6 literal ending in IPv4", env: "[IPv6:::ffff:192.0.2.10]", want: "[IPv6:::ffff:192.0.2.10]"},

		{name: "a bare IPv4 address", env: "192.0.2.10",
			refusal: setting + `"192.0.2.10", an IP address: write it in brackets, as [192.0.2.10]`},
		{name: "a bare IPv6 address", env: "2001:db8::10",
			refusal: setting + `"2001:db8::10", an IP address: write it in brackets, as [IPv6:2001:db8::10]`},
		{name: "a bare IP address from the flag", args: []string{"-authserver-smtp-ehlo-name=192.0.2.10"},
			refusal: setting + `"192.0.2.10", an IP address: write it in brackets, as [192.0.2.10]`},
		{name: "a general address literal", env: "[x400:c=gb]",
			refusal: setting + `"[x400:c=gb]", a general address literal: no tag but IPv6 is registered, so write [192.0.2.10] or [IPv6:2001:db8::10]`},
		{name: "an IPv6 literal with a zone", env: "[IPv6:fe80::1%eth0]", refusal: setting + `"[IPv6:fe80::1%eth0]"` + notOne},
		{name: "an IPv6 literal holding IPv4 alone", env: "[IPv6:192.0.2.10]", refusal: setting + `"[IPv6:192.0.2.10]"` + notOne},
		{name: "an IPv6 literal with seven groups beside ::", env: "[IPv6:1:2:3:4:5:6:7::]", refusal: setting + `"[IPv6:1:2:3:4:5:6:7::]"` + notOne},
		{name: "an IPv6 literal of seven groups", env: "[IPv6:1:2:3:4:5:6:7]", refusal: setting + `"[IPv6:1:2:3:4:5:6:7]"` + notOne},
		{name: "an IPv6 address bracketed without its tag", env: "[2001:db8::10]",
			refusal: setting + `"[2001:db8::10]", an IPv6 address without its tag: write it as [IPv6:2001:db8::10]`},
		{name: "an IPv4 literal past 255", env: "[256.0.0.1]", refusal: setting + `"[256.0.0.1]"` + notOne},
		{name: "an IPv4 literal of three parts", env: "[192.0.2]", refusal: setting + `"[192.0.2]"` + notOne},
		{name: "an IPv4 literal of four-digit part", env: "[1920.0.2.1]", refusal: setting + `"[1920.0.2.1]"` + notOne},
		{name: "an empty literal", env: "[]", refusal: setting + `"[]"` + notOne},
		{name: "an unclosed literal", env: "[192.0.2.10", refusal: setting + `"[192.0.2.10"` + notOne},
		{name: "a label starting with a hyphen", env: "-mail.example.com", refusal: setting + `"-mail.example.com"` + notOne},
		{name: "a label ending with a hyphen", env: "mail-.example.com", refusal: setting + `"mail-.example.com"` + notOne},
		{name: "an empty label", env: "mail..example.com", refusal: setting + `"mail..example.com"` + notOne},
		{name: "a trailing dot", env: "mail.example.com.", refusal: setting + `"mail.example.com."` + notOne},
		{name: "a leading dot", env: ".example.com", refusal: setting + `".example.com"` + notOne},
		{name: "a last label of digits", env: "mail.example.123", refusal: setting + `"mail.example.123"` + notOne},
		{name: "an underscore", env: "mail_relay.example.com", refusal: setting + `"mail_relay.example.com"` + notOne},
		{name: "a space", env: "mail example.com", refusal: setting + `"mail example.com"` + notOne},
		{name: "a non-ASCII label", env: "correio.exemplo.com.bré", refusal: setting + `"correio.exemplo.com.bré"` + notOne},
		{name: "a label of 64", env: label63 + "b.example.com", refusal: setting + `"` + label63 + `b.example.com"` + notOne},
		{name: "a name of 256", env: name256, refusal: setting + `"` + name256 + `"` + notOne},
		{name: "refused before migrate as well", env: "192.0.2.10", args: []string{"migrate"},
			refusal: setting + `"192.0.2.10", an IP address: write it in brackets, as [192.0.2.10]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{}
			if tt.env != "" {
				env[key] = tt.env
			}
			_, c, err := loadMatrixRefusing(t, env, tt.args)

			if tt.refusal != "" {
				want := "malformed configuration: " + tt.refusal
				if err == nil || err.Error() != want {
					t.Errorf("Load() = %v, want %q", err, want)
				}
				if c != nil {
					t.Errorf("Load() refused and still answered a configuration: %#v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v, want no error", err)
			}
			if c.AuthServer.SMTPEHLOName != tt.want {
				t.Errorf("SMTPEHLOName = %q, want %q", c.AuthServer.SMTPEHLOName, tt.want)
			}
		})
	}
}

// TestLoad_ARefusedEHLONameSharesTheLine holds the EHLO name to the one malformed-configuration
// line, beside any other value refused in the same start.
func TestLoad_ARefusedEHLONameSharesTheLine(t *testing.T) {
	_, _, err := loadMatrixRefusing(t, map[string]string{
		"GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP": "90x",
		"GOIABADA_AUTHSERVER_SMTP_EHLO_NAME":   "2001:db8::10",
	}, nil)

	want := `malformed configuration: GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP is "90x", not an integer; ` +
		`GOIABADA_AUTHSERVER_SMTP_EHLO_NAME (--authserver-smtp-ehlo-name) is "2001:db8::10", an IP address: write it in brackets, as [IPv6:2001:db8::10]`
	if err == nil || err.Error() != want {
		t.Errorf("Load() = %v, want %q", err, want)
	}
}
