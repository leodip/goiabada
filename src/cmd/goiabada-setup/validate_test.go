package main

import (
	"strings"
	"testing"
)

// hostOf is the URL's host alone: the scheme, a port, a path and a trailing slash each reached the
// Ingress host while it was the URL with its scheme trimmed (#430).
func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://auth.example.com":                "auth.example.com",
		"https://auth.example.com/":               "auth.example.com",
		"https://auth.example.com:8443":           "auth.example.com",
		"https://auth.example.com:8443/base/path": "auth.example.com",
		"http://auth.example.com":                 "auth.example.com",
		"https://10.0.0.5:8443/x":                 "10.0.0.5",
		"https://[::1]:9090":                      "::1",
	}
	for url, want := range cases {
		if got := hostOf(url); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", url, got, want)
		}
	}
}

// The default admin console URL and email are the auth host's parent with admin in front, and
// there are none for a host without a parent. The last two labels defaulted
// https://auth.example.co.uk to https://admin.co.uk (#430).
func TestDefaultAdminURLAndEmail(t *testing.T) {
	cases := []struct{ auth, admin, email string }{
		{"https://auth.example.com", "https://admin.example.com", "admin@example.com"},
		{"https://auth.acme.io", "https://admin.acme.io", "admin@acme.io"},
		{"https://example.com", "https://admin.example.com", "admin@example.com"},
		{"https://auth.example.co.uk", "https://admin.example.co.uk", "admin@example.co.uk"},
		{"https://auth.eu.acme.com", "https://admin.eu.acme.com", "admin@eu.acme.com"},
		{"https://auth.example.com:8443/x", "https://admin.example.com", "admin@example.com"},
		{"https://10.0.0.5", "", ""},
		{"https://[::1]:9090", "", ""},
		{"https://localhost", "", ""},
	}
	for _, tc := range cases {
		admin, derived := defaultAdminURL(tc.auth)
		if admin != tc.admin || derived != (tc.admin != "") {
			t.Errorf("defaultAdminURL(%q) = %q, %v; want %q, %v", tc.auth, admin, derived, tc.admin, tc.admin != "")
		}
		if email := defaultAdminEmailFor(tc.auth); email != tc.email {
			t.Errorf("defaultAdminEmailFor(%q) = %q, want %q", tc.auth, email, tc.email)
		}
	}
}

// The mismatch warning compares parents, so the pair the sibling rule derives never warns, and a
// host without a parent is compared as itself.
func TestSiteOf_TheMismatchComparison(t *testing.T) {
	cases := []struct {
		auth, admin string
		differ      bool
	}{
		{"https://auth.example.com", "https://admin.example.com", false},
		{"https://auth.example.co.uk", "https://admin.example.co.uk", false},
		{"https://auth.example.co.uk", "https://admin.other.co.uk", true},
		{"https://auth.acme.io", "https://console.acme.io", false},
		{"https://auth.acme.io", "https://admin.acme.com", true},
		{"https://example.com", "https://admin.example.com", false},
		{"https://10.0.0.5", "https://10.0.0.5:8443", false},
		{"https://10.0.0.5", "https://10.0.0.6", true},
		{"https://localhost:9090", "https://admin.example.com", true},
	}
	for _, tc := range cases {
		if differ := siteOf(tc.auth) != siteOf(tc.admin); differ != tc.differ {
			t.Errorf("%s against %s: differ = %v (%q, %q), want %v", tc.auth, tc.admin, differ, siteOf(tc.auth), siteOf(tc.admin), tc.differ)
		}
	}
}

// A Kubernetes host is a precise Gateway API Hostname: lowercase RFC 1123 labels of 1 to 63
// characters, at most 253 in all, and never an IP address (#430).
func TestValidateListenerHostname(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Repeat(label63+".", 3) + strings.Repeat("b", 61)
	for _, host := range []string{
		"auth.example.com", "a.b", "goiabada", "auth-1.example.com", "1auth.example.com",
		label63 + ".example.com", name253,
	} {
		if err := validateListenerHostname(host); err != nil {
			t.Errorf("validateListenerHostname(%q) = %v, want accepted", host, err)
		}
	}
	for host, want := range map[string]string{
		"10.0.0.5":                     "is an IP address",
		"::1":                          "is an IP address",
		"Auth.example.com":             "has 'A'",
		"auth.EXAMPLE.com":             "has 'E'",
		"auth_1.example.com":           "has '_'",
		"auth..example.com":            "a label of 0 characters",
		"":                             "a label of 0 characters",
		label63 + "a.example.com":      "a label of 64 characters",
		name253 + "b":                  "too long",
		"-auth.example.com":            "starting or ending with '-'",
		"auth-.example.com":            "starting or ending with '-'",
		"auth.example.com.":            "a label of 0 characters",
		"*.example.com":                "has '*'",
		"auth.example.com:8443":        "has ':'",
		"auth.example.com/admin/path1": "has '/'",
	} {
		err := validateListenerHostname(host)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("validateListenerHostname(%q) = %v, want an error containing %q", host, err, want)
		}
	}
}

// validateURL refuses what url.Parse reads differently from the host it checked, so hostOf is
// always the host validated: userinfo moved the host to evil.com, and a port nothing can dial or a
// broken escape does not parse at all (#430).
func TestValidateURL(t *testing.T) {
	for _, url := range []string{
		"https://auth.example.com", "https://auth.example.com/", "https://auth.example.com:8443/base/path",
		"http://localhost:9090", "https://10.0.0.5", "https://Auth.Example.com",
	} {
		if err := validateURL(url); err != nil {
			t.Errorf("validateURL(%q) = %v, want accepted", url, err)
		}
	}
	for url, want := range map[string]string{
		"https://auth.example.com:x@evil.com/":   "cannot carry a user name or password",
		"https://auth.example.com:x:y@evil.com/": "cannot carry a user name or password",
		"https://auth.example.com:abc":           "cannot be parsed",
		"https://auth.example.com/%zz":           "cannot be parsed",
		"auth.example.com":                       "must start with http:// or https://",
		"https://auth_example.com":               "invalid character '_'",
		"https://[::1]:9090":                     "invalid character '['",
		"":                                       "cannot be empty",
	} {
		err := validateURL(url)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("validateURL(%q) = %v, want an error containing %q", url, err, want)
		}
	}
}

// The database host is what GOIABADA_DB_HOST accepts: a hostname, or an IP literal, IPv6 bare or
// bracketed. Anything else is still refused by the hostname rule (#430).
func TestValidateDatabaseHost(t *testing.T) {
	for _, host := range []string{
		"db.example.com", "localhost", "postgres-service", "10.0.0.5",
		"::1", "[::1]", "2001:db8::5", "[2001:db8::5]", "::ffff:10.0.0.5",
	} {
		if err := validateDatabaseHost(host); err != nil {
			t.Errorf("validateDatabaseHost(%q) = %v, want accepted", host, err)
		}
	}
	for _, host := range []string{
		"", "[::1", "::1]", "[[::1]]", "::g", "[db.example.com]", "db_example", "db example.com",
		"fe80::1%eth0", "-db.example.com", "db.example.com.",
	} {
		if err := validateDatabaseHost(host); err == nil {
			t.Errorf("validateDatabaseHost(%q) accepted, want refused", host)
		}
	}
}
