package web

import (
	"regexp"
	"strings"
	"testing"
)

// formTag is one form element's opening tag, which may span lines.
var formTag = regexp.MustCompile(`(?s)<form\b[^>]*>`)

// submitOnceMarker is the attribute a form that must be sent once carries: utils.js registers a
// submit listener on every form carrying it, which lets the first submission through and refuses
// every later one. submitOnceHandler is the inline handler that did the same before the pages moved
// their scripts out of the templates (#617), which a form not yet moved still carries.
const (
	submitOnceMarker  = "data-submit-once"
	submitOnceHandler = `onsubmit="return submitOnce(this)"`
)

// The password form and the two code forms, the verification and the enrolment, send one submission
// however often they are submitted: a double click or a repeated Enter. Each step's rotation of the
// browser session now lands only while the session it loaded is still there, so a second submission
// arriving after the first rotated it away meets the "no longer active" page rather than going
// through, and before #579 it landed on the account page with its sign-in lost (#579 decision 3).
//
// This is lexical, as static_lint_test.go's guards are, since this module has no JavaScript runner:
// each form carries the marker or the handler, the layout it is rendered in loads the script
// declaring and registering it, and the declaration does what it is for.
// TestUtilsJS_EveryFunctionIsReachedFromATemplate holds the declaration to these callers.
func TestTemplates_CredentialFormsSubmitOnce(t *testing.T) {
	templates := servedFiles(t, templateFS, "template", ".html")
	scripts := servedFiles(t, staticFS, "static", ".js")

	for _, path := range []string{"template/auth_pwd.html", "template/auth_otp.html", "template/auth_otp_enrollment.html"} {
		src, ok := templates[path]
		if !ok {
			t.Errorf("%s: not served, so the form this test pins is gone", path)
			continue
		}
		forms := formTag.FindAllString(src, -1)
		if len(forms) != 1 {
			t.Errorf("%s: %d forms, want the one credential form", path, len(forms))
			continue
		}
		if !strings.Contains(forms[0], submitOnceMarker) && !strings.Contains(forms[0], submitOnceHandler) {
			t.Errorf("%s: the form %s carries neither %s nor %s, so a double click sends it twice",
				path, forms[0], submitOnceMarker, submitOnceHandler)
		}
	}

	// The three pages are rendered in the auth layout (handler_auth_pwd.go, handler_auth_otp.go).
	if !strings.Contains(templates["template/layouts/auth_layout.html"], `<script src="{{ asset "/static/utils.js" }}" defer></script>`) {
		t.Error("template/layouts/auth_layout.html does not load /static/utils.js, where submitOnce is declared")
	}

	var body, registration string
	for _, d := range jsDecls(scripts["static/utils.js"]) {
		switch {
		case d.name == "submitOnce":
			body = d.body
		case d.name == "" && strings.Contains(d.body, `"form[`+submitOnceMarker+`]"`):
			registration = d.body
		}
	}
	if body == "" {
		t.Fatal("static/utils.js declares no submitOnce")
	}
	// A second submission is refused, by returning false from the handler, and the first disables
	// the form's buttons, which is also what stops a repeated Enter: implicit submission does not
	// submit through a disabled default button (HTML Standard, 4.10.21.2, "Implicit submission").
	for _, want := range []string{"return false", ".disabled = true", "return true"} {
		if !strings.Contains(body, want) {
			t.Errorf("static/utils.js: submitOnce does not contain %q:\n%s", want, body)
		}
	}
	// And the marker is registered: a submission submitOnce refuses is prevented.
	if registration == "" {
		t.Fatalf("static/utils.js registers no listener on form[%s]", submitOnceMarker)
	}
	for _, want := range []string{`addEventListener("submit"`, "submitOnce(form)", "event.preventDefault()"} {
		if !strings.Contains(registration, want) {
			t.Errorf("static/utils.js: the form[%s] registration does not contain %q:\n%s", submitOnceMarker, want, registration)
		}
	}
}
