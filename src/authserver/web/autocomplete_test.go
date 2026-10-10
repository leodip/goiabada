package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// inputTag is one input element, which may span lines.
var inputTag = regexp.MustCompile(`(?s)<input\b[^>]*>`)

// autocompleteAttr and nameAttr read one attribute of an input element. The attribute must follow
// whitespace: a \b boundary also matched data-autocomplete and data-name, which a browser ignores.
var (
	autocompleteAttr = regexp.MustCompile(`\sautocomplete="([^"]*)"`)
	nameAttr         = regexp.MustCompile(`\sname="([^"]*)"`)
)

// passwordFieldTokens are the autofill tokens a password field may carry (HTML Standard, 4.10.18.7,
// "Autofill"): current-password where the user types the password they have, new-password where
// they choose one, or where a saved login must never be filled in, and off for a read-only value.
var passwordFieldTokens = map[string]bool{"current-password": true, "new-password": true, "off": true}

// Every password field names what it holds, so a password manager neither guesses nor fills a saved
// login where it does not belong: with none, the admin console's email settings had the
// administrator's own saved password filled into the SMTP password (#542). The fields whose token
// matters most are pinned by name.
func TestTemplates_EveryPasswordFieldNamesItsAutocomplete(t *testing.T) {
	pinned := map[string]map[string]string{
		"template/auth_pwd.html":                  {"email": "username", "password": "current-password"},
		"template/account_register.html":          {"email": "username", "password": "new-password", "passwordConfirmation": "new-password"},
		"template/reset_password.html":            {"password": "new-password", "passwordConfirmation": "new-password"},
		"template/auth_otp.html":                  {"otp": "one-time-code"},
		"template/auth_otp_enrollment.html":       {"otp": "one-time-code"},
		"template/forgot_password.html":           {"email": "email"},
		"template/account_activate_password.html": {"password": "new-password", "passwordConfirmation": "new-password"},
	}
	checked := 0
	seen := map[string]bool{}
	err := fs.WalkDir(templateFS, "template", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		content, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		for _, tag := range inputTag.FindAllString(string(content), -1) {
			name := ""
			if m := nameAttr.FindStringSubmatch(tag); m != nil {
				name = m[1]
			}
			token := ""
			if m := autocompleteAttr.FindStringSubmatch(tag); m != nil {
				token = m[1]
			}
			if strings.Contains(tag, `type="password"`) {
				checked++
				if !passwordFieldTokens[token] {
					t.Errorf("%s: password field %q has autocomplete %q, want current-password, new-password or off", path, name, token)
				}
			}
			if want, ok := pinned[path][name]; ok {
				seen[path+" "+name] = true
				if token != want {
					t.Errorf("%s: field %q has autocomplete %q, want %q", path, name, token, want)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no password field was read")
	}
	// A pinned field that is gone, renamed or moved would otherwise pass unchecked.
	for path, fields := range pinned {
		for name := range fields {
			if !seen[path+" "+name] {
				t.Errorf("%s: no input named %q, which this test pins", path, name)
			}
		}
	}
}

// The matchers read the attributes a browser reads, and not a data- attribute that ends in the same
// name.
func TestAutocompleteMatchers_ReadOnlyTheRealAttributes(t *testing.T) {
	if m := autocompleteAttr.FindStringSubmatch(`<input type="password" data-autocomplete="new-password" name="password">`); m != nil {
		t.Errorf("data-autocomplete read as autocomplete: %v", m)
	}
	if m := nameAttr.FindStringSubmatch(`<input type="password" data-name="password">`); m != nil {
		t.Errorf("data-name read as name: %v", m)
	}
	m := autocompleteAttr.FindStringSubmatch("<input\n\ttype=\"password\"\n\tautocomplete=\"new-password\">")
	if m == nil || m[1] != "new-password" {
		t.Errorf("an attribute on its own line was not read: %v", m)
	}
}
