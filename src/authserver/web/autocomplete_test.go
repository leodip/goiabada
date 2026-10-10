package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// inputTag is one input element, which may span lines.
var inputTag = regexp.MustCompile(`(?s)<input\b[^>]*>`)

// autocompleteAttr and nameAttr read one attribute of an input element.
var (
	autocompleteAttr = regexp.MustCompile(`\bautocomplete="([^"]*)"`)
	nameAttr         = regexp.MustCompile(`\bname="([^"]*)"`)
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
		"template/auth_pwd.html":            {"email": "username", "password": "current-password"},
		"template/account_register.html":    {"email": "username", "password": "new-password", "passwordConfirmation": "new-password"},
		"template/reset_password.html":      {"password": "new-password", "passwordConfirmation": "new-password"},
		"template/auth_otp.html":            {"otp": "one-time-code"},
		"template/auth_otp_enrollment.html": {"otp": "one-time-code"},
	}
	checked := 0
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
			if want, ok := pinned[path][name]; ok && token != want {
				t.Errorf("%s: field %q has autocomplete %q, want %q", path, name, token, want)
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
}
