package main

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
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
	return validateHostname(hostname)
}

// isASCIIAlphaNum reports whether c is an ASCII letter or digit.
func isASCIIAlphaNum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isASCIILowerAlphaNum reports whether c is a lowercase ASCII letter or digit.
func isASCIILowerAlphaNum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
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

func checkPasswordStrength(password string) []string {
	var issues []string
	if len(password) < 8 {
		issues = append(issues, "less than 8 characters")
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range password {
		if unicode.IsUpper(c) {
			hasUpper = true
		} else if unicode.IsLower(c) {
			hasLower = true
		} else if unicode.IsDigit(c) {
			hasDigit = true
		} else {
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

func extractDomainFromURL(urlStr string) string {
	hostname := strings.TrimPrefix(urlStr, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}
