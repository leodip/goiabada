package main

import (
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
)

// checkWritable refuses a value no generated file can carry: one that is not valid UTF-8, which a
// YAML stream cannot hold (YAML 1.2.2, section 5.1), and one holding NUL, which no process
// environment can. Every other value is written exactly as given, through quote.go (#430).
func checkWritable(value string) error {
	if !utf8.ValidString(value) {
		return errs.New("it is not valid UTF-8")
	}
	if strings.ContainsRune(value, 0) {
		return errs.New("it contains a NUL character")
	}
	return nil
}

func validateURL(urlStr string) error {
	if urlStr == "" {
		return errs.Errorf("URL cannot be empty")
	}
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return errs.Errorf("URL must start with http:// or https://")
	}
	hostname := strings.TrimPrefix(urlStr, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	if err := validateHostname(hostname); err != nil {
		return err
	}
	// hostOf reads the host with url.Parse, and these two refusals make it the host validated
	// above: https://auth.example.com:x@evil.com/ passed as auth.example.com while every URL
	// parser reads evil.com, and https://auth.example.com:abc carried a port nothing can dial
	// (#430).
	u, err := url.Parse(urlStr)
	if err != nil {
		return errs.New("URL cannot be parsed")
	}
	if u.User != nil {
		return errs.New("URL cannot carry a user name or password")
	}
	return nil
}

// hostOf is the host of a URL validateURL accepted, without its port, path or trailing slash:
// what a Kubernetes host and a certificate name, and so the default admin URL too, are about.
// Trimming the scheme alone put https://auth.example.com/ and :8443 into the Ingress (#430).
// clusterInternalHost reports whether host is a name only a Kubernetes cluster's DNS answers: a
// Service's short name, which has no dot, or a name under svc, such as
// postgres.db.svc.cluster.local. An IP address never is.
func clusterInternalHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || net.ParseIP(h) != nil {
		return false
	}
	return !strings.Contains(h, ".") || strings.HasSuffix(h, ".svc") || strings.Contains(h, ".svc.") ||
		strings.HasSuffix(h, ".cluster.local")
}

func hostOf(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "" // unreachable for a URL validateURL accepted, which refuses one url.Parse does not
	}
	return u.Hostname()
}

// parentDomain is the domain a host sits in: the host minus its first label when it has three or
// more, and the host itself when it has two. An IP literal or a single-label host has none. Taking
// the last two labels made https://auth.example.co.uk default the admin console to
// https://admin.co.uk; the parent keeps the admin console a sibling of the auth server (#430).
func parentDomain(host string) (string, bool) {
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}
	labels := strings.Split(host, ".")
	switch len(labels) {
	case 1:
		return "", false
	case 2:
		return host, true
	default:
		return strings.Join(labels[1:], "."), true
	}
}

// defaultAdminURL is the admin console URL offered for an auth server URL, https://admin. plus
// the auth host's parent, and false when the host has no parent to offer one from.
func defaultAdminURL(authServerURL string) (string, bool) {
	parent, ok := parentDomain(hostOf(authServerURL))
	if !ok {
		return "", false
	}
	return "https://admin." + parent, true
}

// defaultAdminEmailFor is the admin email offered for an auth server URL, admin@ plus the auth
// host's parent, and "" when it has none.
func defaultAdminEmailFor(authServerURL string) string {
	parent, ok := parentDomain(hostOf(authServerURL))
	if !ok {
		return ""
	}
	return "admin@" + parent
}

// siteOf is what the domain-mismatch warning compares for a URL: its host's parent, or the host
// itself when it has none, so two different IP addresses still differ.
func siteOf(urlStr string) string {
	host := hostOf(urlStr)
	if parent, ok := parentDomain(host); ok {
		return parent
	}
	return host
}

// validateListenerHostname holds a Kubernetes host to what a Gateway listener's hostname may be,
// a precise Hostname of Gateway API v1.6.1 (apis/v1/shared_types.go): "the RFC 1123 definition of
// a hostname" except that "IPs are not allowed", every label "lower case alphanumeric characters
// or '-'", starting and ending with an alphanumeric, at most 253 characters. The API server
// refuses any other, so the manifest would not apply (#430).
func validateListenerHostname(host string) error {
	if net.ParseIP(host) != nil {
		return errs.Errorf("%s is an IP address, and a Kubernetes host must be a domain name", host)
	}
	if len(host) > 253 {
		return errs.Errorf("host %s is too long for Kubernetes (max 253 characters)", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return errs.Errorf("host %s has a label of %d characters, and Kubernetes needs 1 to 63", host, len(label))
		}
		for _, c := range label {
			if !isASCIILowerAlphaNum(c) && c != '-' {
				return errs.Errorf("host %s has '%c', and a Kubernetes host is lowercase a-z, 0-9 and '-'", host, c)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errs.Errorf("host %s has a label starting or ending with '-'", host)
		}
	}
	return nil
}

// isASCIIAlphaNum reports whether c is an ASCII letter or digit.
func isASCIIAlphaNum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isASCIILowerAlphaNum reports whether c is a lowercase ASCII letter or digit.
func isASCIILowerAlphaNum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// validateDatabaseHost accepts what the auth server's GOIABADA_DB_HOST does: a hostname, or an IP
// literal, an IPv6 one bare or in brackets, since the server and the connection check both join it
// to the port through hostport.Join. validateHostname alone refused every IPv6 host (#430).
func validateDatabaseHost(host string) error {
	if net.ParseIP(hostport.Unbracket(host)) != nil {
		return nil
	}
	return validateHostname(host)
}

func validateHostname(hostname string) error {
	if hostname == "" {
		return errs.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 253 {
		return errs.Errorf("hostname too long (max 253 characters)")
	}
	for i, c := range hostname {
		if !isASCIIAlphaNum(c) && c != '-' && c != '.' {
			return errs.Errorf("invalid character '%c' at position %d (only a-z, 0-9, '-', '.' allowed)", c, i)
		}
	}
	if hostname[0] == '-' || hostname[0] == '.' {
		return errs.Errorf("hostname cannot start with '%c'", hostname[0])
	}
	if hostname[len(hostname)-1] == '-' || hostname[len(hostname)-1] == '.' {
		return errs.Errorf("hostname cannot end with '%c'", hostname[len(hostname)-1])
	}
	return nil
}

func validateEmail(email string) error {
	if email == "" {
		return errs.Errorf("email cannot be empty")
	}
	atIndex := strings.Index(email, "@")
	if atIndex == -1 {
		return errs.Errorf("email must contain '@'")
	}
	if atIndex == 0 {
		return errs.Errorf("email must have text before '@'")
	}
	if atIndex == len(email)-1 {
		return errs.Errorf("email must have text after '@'")
	}
	if strings.Count(email, "@") > 1 {
		return errs.Errorf("email must contain only one '@'")
	}
	domain := email[atIndex+1:]
	if !strings.Contains(domain, ".") {
		return errs.Errorf("email domain must contain '.'")
	}
	return nil
}

func validatePort(port string) error {
	if port == "" {
		return errs.Errorf("port cannot be empty")
	}
	portNum := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return errs.Errorf("port must be a number")
		}
		portNum = portNum*10 + int(c-'0')
	}
	if portNum < 1 || portNum > 65535 {
		return errs.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateNamespace(ns string) error {
	if ns == "" {
		return errs.Errorf("namespace cannot be empty")
	}
	if len(ns) > 63 {
		return errs.Errorf("namespace too long (max 63 characters)")
	}
	for i, c := range ns {
		if !isASCIILowerAlphaNum(c) && c != '-' {
			return errs.Errorf("invalid character '%c' at position %d (only lowercase a-z, 0-9, '-' allowed)", c, i)
		}
	}
	if ns[0] >= '0' && ns[0] <= '9' {
		return errs.Errorf("namespace must start with a letter")
	}
	if ns[0] == '-' {
		return errs.Errorf("namespace cannot start with '-'")
	}
	if ns[len(ns)-1] == '-' {
		return errs.Errorf("namespace cannot end with '-'")
	}
	return nil
}

func validateDatabaseName(name string) error {
	if name == "" {
		return errs.Errorf("database name cannot be empty")
	}
	if len(name) > 63 {
		return errs.Errorf("database name too long (max 63 characters)")
	}
	for i, c := range name {
		if !isASCIIAlphaNum(c) && c != '_' {
			return errs.Errorf("invalid character '%c' at position %d (only a-z, A-Z, 0-9, '_' allowed)", c, i)
		}
	}
	if name[0] >= '0' && name[0] <= '9' {
		return errs.Errorf("database name must start with a letter")
	}
	return nil
}

// checkPasswordStrength names the character classes a chosen admin password lacks, which the
// operator may accept. Its length is not judged here: adminpassword.Check refuses one the first
// start would not seed before this is asked (#500).
func checkPasswordStrength(password string) []string {
	var issues []string
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper {
		issues = append(issues, "no uppercase letter")
	}
	if !hasLower {
		issues = append(issues, "no lowercase letter")
	}
	if !hasDigit {
		issues = append(issues, "no digit")
	}
	if !hasSpecial {
		issues = append(issues, "no special character")
	}
	return issues
}
