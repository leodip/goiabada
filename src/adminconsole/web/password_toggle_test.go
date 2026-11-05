package web

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// passwordFieldKinds names, for each console template and each password field's id in it, the
// kind of password the field holds (#722 decision 8): its show/hide button is named from
// adminconsole.password_toggle.show_<kind> and hide_<kind>. The OTP page draws a field with id
// password in each of two branches, and the recovery codes' field beside them.
var passwordFieldKinds = map[string]map[string]string{
	"template/account_change_password.html": {
		"currentPassword":         "current_password",
		"newPassword":             "new_password",
		"newPasswordConfirmation": "new_password_confirmation",
	},
	"template/account_email.html":                {"currentPassword": "current_password"},
	"template/account_delete.html":               {"password": "password"},
	"template/account_otp.html":                  {"password": "password", "recovery-codes-password": "password"},
	"template/admin_users_new.html":              {"password": "password"},
	"template/admin_users_authentication.html":   {"newPassword": "new_password"},
	"template/admin_settings_email.html":         {"password": "password"},
	"template/admin_settings_turnstile.html":     {"turnstileSecretKey": "secret_key"},
	"template/admin_clients_authentication.html": {"clientSecret": "client_secret"},
}

// passwordFieldCount is how many password fields each template draws.
var passwordFieldCount = map[string]int{
	"template/account_change_password.html":      3,
	"template/account_email.html":                1,
	"template/account_delete.html":               1,
	"template/account_otp.html":                  3,
	"template/admin_users_new.html":              1,
	"template/admin_users_authentication.html":   1,
	"template/admin_settings_email.html":         1,
	"template/admin_settings_turnstile.html":     1,
	"template/admin_clients_authentication.html": 1,
}

// passwordToggleWords are the message IDs of the words a field's button shows: the generic Show and
// Hide, except on the client secret, whose button keeps its own (#722 decision 8).
func passwordToggleWords(kind string) (show, hide string) {
	if kind == "client_secret" {
		return "adminconsole.admin_clients.authentication.reveal_link", "adminconsole.admin_clients.authentication.hide_link"
	}
	return "adminconsole.password_toggle.show", "adminconsole.password_toggle.hide"
}

var (
	idAttr          = regexp.MustCompile(`\sid="([^"]*)"`)
	buttonElement   = regexp.MustCompile(`(?s)^<button\b([^>]*)>(.*?)</button>`)
	inputRowOpening = regexp.MustCompile(`<div class="input-row">\s*$`)
)

// hasBareAttr reports whether a tag's attributes carry the boolean attribute name.
func hasBareAttr(attrs, name string) bool {
	return regexp.MustCompile(`\s` + regexp.QuoteMeta(name) + `(\s|$|>|=)`).MatchString(attrs)
}

// translated is the attribute value or text a template writes for a message ID.
func translated(key string) string {
	return fmt.Sprintf(`{{ T $.ctx %q }}`, key)
}

// Every password field in the console is never spell-checked, capitalised or corrected once its
// button shows it as text (#722 decision 11; HTML Standard 6.8.5, 6.8.7 and 6.8.8), and sits in an
// input-row beside its show/hide button: a plain button, drawn hidden so it never shows without
// JavaScript, marked data-password-toggle for the script, naming its field in aria-controls, and
// named and worded from the message IDs of the field's kind, with the status words the script
// announces (#722 decisions 7 and 8).
func TestTemplates_EveryPasswordFieldHasItsShowHideButton(t *testing.T) {
	counted := map[string]int{}
	err := fs.WalkDir(templateFS, "template", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		content, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(content)
		for _, at := range inputTag.FindAllStringIndex(src, -1) {
			tag := src[at[0]:at[1]]
			if !strings.Contains(tag, `type="password"`) {
				continue
			}
			counted[path]++
			id := ""
			if m := idAttr.FindStringSubmatch(tag); m != nil {
				id = m[1]
			}
			where := fmt.Sprintf("%s: password field %q", path, id)
			for _, attr := range []string{`spellcheck="false"`, `autocapitalize="none"`, `autocorrect="off"`} {
				if !strings.Contains(tag, " "+attr) {
					t.Errorf("%s does not carry %s", where, attr)
				}
			}
			kind, ok := passwordFieldKinds[path][id]
			if !ok {
				t.Errorf("%s is not listed in passwordFieldKinds, so its button's name is not pinned", where)
				continue
			}
			if !inputRowOpening.MatchString(src[:at[0]]) {
				t.Errorf("%s does not open a <div class=\"input-row\">, where its button sits beside it", where)
			}
			button := buttonElement.FindStringSubmatch(strings.TrimLeft(src[at[1]:], " \t\r\n"))
			if button == nil {
				t.Errorf("%s is not followed by its show/hide button", where)
				continue
			}
			attrs, text := button[1], button[2]
			showWord, hideWord := passwordToggleWords(kind)
			for _, want := range []string{
				`type="button"`,
				`aria-controls="` + id + `"`,
				`aria-label="` + translated("adminconsole.password_toggle.show_"+kind) + `"`,
				`data-hide-name="` + translated("adminconsole.password_toggle.hide_"+kind) + `"`,
				`data-hide-label="` + translated(hideWord) + `"`,
				`data-shown-status="` + translated("adminconsole.password_toggle.shown") + `"`,
				`data-hidden-status="` + translated("adminconsole.password_toggle.hidden") + `"`,
			} {
				if !strings.Contains(attrs, " "+want) {
					t.Errorf("%s: its button <button%s> does not carry %s", where, attrs, want)
				}
			}
			for _, bare := range []string{"data-password-toggle", "hidden"} {
				if !hasBareAttr(attrs, bare) {
					t.Errorf("%s: its button <button%s> does not carry %s", where, attrs, bare)
				}
			}
			if strings.TrimSpace(text) != translated(showWord) {
				t.Errorf("%s: its button reads %q, want %s", where, text, translated(showWord))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range passwordFieldCount {
		if counted[path] != want {
			t.Errorf("%s: %d password fields, want %d", path, counted[path], want)
		}
	}
	for path, n := range counted {
		if _, ok := passwordFieldCount[path]; !ok {
			t.Errorf("%s: %d password fields that passwordFieldCount does not list", path, n)
		}
	}
}

// The buttons work wherever a password field is drawn: every template holding one is a page of the
// menu layout, the only layout drawing the "menu" block, which loads utils.js, where the behaviour
// is declared, and shell.js, which registers it on every button marked data-password-toggle.
func TestLayouts_LoadTheScriptThatRegistersPasswordToggles(t *testing.T) {
	layout, err := templateFS.ReadFile("template/layouts/menu_layout.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"/static/utils.js", "/static/shell.js"} {
		if !strings.Contains(string(layout), `<script src="{{ asset "`+script+`" }}" defer></script>`) {
			t.Errorf("menu_layout.html does not load %s", script)
		}
	}
	for path := range passwordFieldCount {
		page, readErr := templateFS.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !strings.Contains(string(page), `{{define "menu"}}`) {
			t.Errorf("%s is not a page of the menu layout, whose shell.js wires its show/hide buttons", path)
		}
	}
	shell, err := staticFS.ReadFile("static/shell.js")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^setUpPasswordToggles\(\);$`).Match(shell) {
		t.Error("shell.js does not call setUpPasswordToggles()")
	}
	if _, body, ok := functionBody(utilsJS(t), "setUpPasswordToggles"); !ok {
		t.Error("utils.js declares no setUpPasswordToggles")
	} else if !strings.Contains(body, `"button[data-password-toggle]"`) {
		t.Errorf("setUpPasswordToggles does not select button[data-password-toggle]: %s", body)
	}
}

// The client secret's page shows a generated secret through the shared behaviour, and reaches its
// Show button by id, so an operator's copy of the template from before the button carried
// data-password-toggle still gets a working button (#722, assumed: "an operator's old copy").
func TestClientAuthenticationJS_UsesTheSharedPasswordToggle(t *testing.T) {
	script, err := staticFS.ReadFile("static/pages/admin-clients-authentication.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(script)
	if !strings.Contains(src, `passwordToggle(showButton)`) {
		t.Error("admin-clients-authentication.js does not register its Show button with passwordToggle")
	}
	if strings.Contains(src, `secretField.type =`) {
		t.Error("admin-clients-authentication.js switches the secret's type itself, past the shared behaviour")
	}
}

// msRevealSelector is the one selector hiding Edge's own reveal control: on a password field whose
// show/hide button the script has shown, so a field has one control for the job, and Edge keeps its
// own where the button never shows, as with JavaScript off (#722 decision 11).
const msRevealSelector = ".input-row:has(> [data-password-toggle]:not([hidden])) > input::-ms-reveal"

var cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

// Edge draws its own reveal control in a password field, which beside the show/hide button would be
// two controls for one job. ui.css hides it only beside a shown button, in a rule of its own: a
// browser that does not know ::-ms-reveal drops the whole selector list holding it, so sharing a
// list would void the other selectors in every other browser.
func TestUICSS_HidesEdgesRevealControlBesideAShownButton(t *testing.T) {
	served, err := fs.ReadFile(staticFS, "static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("tailwindcss/ui.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct{ name, css string }{
		{"tailwindcss/ui.css", string(source)},
		{"static/main.css", string(served)},
	} {
		t.Run(file.name, func(t *testing.T) {
			css := cssComment.ReplaceAllString(file.css, "")
			if n := strings.Count(css, "::-ms-reveal"); n != 1 {
				t.Fatalf("%s: ::-ms-reveal appears %d times, want once, in %s", file.name, n, msRevealSelector)
			}
			rule := cssRule(t, file.name, css, msRevealSelector)
			if got := declarations(rule, "display"); len(got) != 1 || got[0] != "none" {
				t.Errorf("%s: %s's display is %q, want only none", file.name, msRevealSelector, got)
			}
			at := strings.Index(css, msRevealSelector)
			if at <= 0 {
				t.Fatalf("%s: %s is not in the file", file.name, msRevealSelector)
			}
			before := strings.TrimSpace(css[:at])
			if last := before[len(before)-1]; last != '{' && last != '}' {
				t.Errorf("%s: %s shares a selector list (it follows %q), so a browser without ::-ms-reveal drops the list",
					file.name, msRevealSelector, last)
			}
		})
	}
}
