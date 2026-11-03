package web

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// passwordFieldKinds names, for each auth server template and each password field's id in it, the
// kind of password the field holds (#722 decision 8): its show/hide button is named from
// common.password_toggle.show_<kind> and hide_<kind>.
var passwordFieldKinds = map[string]map[string]string{
	"template/auth_pwd.html": {"password": "password"},
	"template/account_register.html": {
		"password":             "password",
		"passwordConfirmation": "password_confirmation",
	},
	"template/reset_password.html": {
		"password":             "password",
		"passwordConfirmation": "password_confirmation",
	},
	"template/account_activate_password.html": {
		"password":             "password",
		"passwordConfirmation": "password_confirmation",
	},
}

// passwordFieldCount is how many password fields each template draws.
var passwordFieldCount = map[string]int{
	"template/auth_pwd.html":                  1,
	"template/account_register.html":          2,
	"template/reset_password.html":            2,
	"template/account_activate_password.html": 2,
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

// Every password field on the auth server's pages is never spell-checked, capitalised or corrected
// once its button shows it as text (#722 decision 11; HTML Standard 6.8.5, 6.8.7 and 6.8.8), and
// sits in an input-row beside its show/hide button: a plain button, drawn hidden so it never shows
// without JavaScript, marked data-password-toggle for the script, naming its field in
// aria-controls, and named and worded from the common.password_toggle.* IDs of the field's kind,
// with the status words the script announces (#722 decisions 7 and 8).
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
			for _, want := range []string{
				`type="button"`,
				`aria-controls="` + id + `"`,
				`aria-label="` + translated("common.password_toggle.show_"+kind) + `"`,
				`data-hide-name="` + translated("common.password_toggle.hide_"+kind) + `"`,
				`data-hide-label="` + translated("common.password_toggle.hide") + `"`,
				`data-shown-status="` + translated("common.password_toggle.shown") + `"`,
				`data-hidden-status="` + translated("common.password_toggle.hidden") + `"`,
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
			if strings.Contains(attrs, "aria-pressed") {
				t.Errorf("%s: its button <button%s> carries aria-pressed, though its name changes with the state", where, attrs)
			}
			if strings.TrimSpace(text) != translated("common.password_toggle.show") {
				t.Errorf("%s: its button reads %q, want %s", where, text, translated("common.password_toggle.show"))
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

// The buttons work wherever a password field is drawn: the sign-in, registration, reset and
// activation pages are drawn in the auth layout (handler_auth_pwd.go, handler_account_register.go,
// handler_reset_password.go, handler_account_activate.go), and every page in the layout without the
// client's section; both load utils.js, which registers the behaviour on every button marked
// data-password-toggle when it loads.
func TestLayouts_LoadTheScriptThatRegistersPasswordToggles(t *testing.T) {
	templates := servedFiles(t, templateFS, "template", ".html")
	for _, layout := range []string{"template/layouts/auth_layout.html", "template/layouts/no_menu_layout.html"} {
		if !strings.Contains(templates[layout], `<script src="{{ asset "/static/utils.js" }}" defer></script>`) {
			t.Errorf("%s does not load /static/utils.js, where the show/hide buttons are wired", layout)
		}
	}

	scripts := servedFiles(t, staticFS, "static", ".js")
	var registration string
	declared := false
	for _, d := range jsDecls(scripts["static/utils.js"]) {
		switch {
		case d.name == "passwordToggle":
			declared = true
		case d.name == "" && strings.Contains(d.body, `"button[data-password-toggle]"`):
			registration = d.body
		}
	}
	if !declared {
		t.Error("static/utils.js declares no passwordToggle")
	}
	if registration == "" {
		t.Fatal("static/utils.js registers nothing on button[data-password-toggle] when it loads")
	}
	if !callRe("passwordToggle").MatchString(registration) {
		t.Errorf("static/utils.js: the button[data-password-toggle] registration does not call passwordToggle:\n%s", registration)
	}
}

// msRevealSelector is the one selector hiding Edge's own reveal control: on a password field whose
// show/hide button the script has shown, so a field has one control for the job, and Edge keeps its
// own where the button never shows, as with JavaScript off (#722 decision 11).
const msRevealSelector = ".input-row:has(> [data-password-toggle]:not([hidden])) > input::-ms-reveal"

// msRevealRule is that selector's rule as the served main.css writes it, alone in its selector
// list: a browser that does not know ::-ms-reveal drops the whole list holding it.
var msRevealRule = regexp.MustCompile(`(?:^|[{}])\s*` + regexp.QuoteMeta(msRevealSelector) + `\s*\{\s*display:\s*none;?\s*\}`)

// The auth server's pages are served their own main.css, which must hide Edge's reveal control
// beside a shown button as the console's does, in a rule of its own.
func TestMainCSS_HidesEdgesRevealControlBesideAShownButton(t *testing.T) {
	css, err := fs.ReadFile(staticFS, "static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(css), "::-ms-reveal"); n != 1 {
		t.Errorf("static/main.css: ::-ms-reveal appears %d times, want once, in %s", n, msRevealSelector)
	}
	if !msRevealRule.Match(css) {
		t.Errorf("static/main.css has no rule of its own %s { display: none }", msRevealSelector)
	}
}
