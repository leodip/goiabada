// Package emailtemplate holds the auth server's emails as email templates (#818): each email's
// built-in definition, which says the placeholders it offers and holds its text in the six built-in
// languages, and the format that text is written in, a subject and a body in a small Markdown set
// with placeholders such as {{name}} and {{link}}, which format.go renders and checks.
//
// The email layout, the frame drawn around a body in its brand, stays a template the render package
// draws; this package writes what sits inside it.
package emailtemplate

import (
	"strings"
	"time"

	"golang.org/x/text/language"
)

// The placeholders an email can offer (#818 decisions 3 and 4). A name is lowercase with
// underscores.
const (
	// AppName is the app name of the settings.
	AppName = "app_name"
	// Name is the recipient's name, never empty (RecipientName).
	Name = "name"
	// Link is the email's action link: on its own the URL drawn as a link to itself, or the whole
	// destination of a link.
	Link = "link"
	// Button is the brand's button to the link, alone on its line, labelled with the button label.
	Button = "button"
	// Code is the verification code: the boxed code alone in its paragraph, else the code as text.
	Code = "code"
	// Expiry is the link's or the code's lifetime with its unit, in the email's language.
	Expiry = "expiry"
	// CodesLeft is how many unused recovery codes are left, a number.
	CodesLeft = "codes_left"
)

// Placeholder is one placeholder an email offers, and whether its body cannot do without it.
type Placeholder struct {
	Name     string
	Required bool
}

// InSubject reports whether the placeholder may be written in the subject, which takes text values
// only, never the link or the button.
func (p Placeholder) InSubject() bool {
	return p.Name != Link && p.Name != Button
}

// Text is one language of an email: its subject, its button's label, empty for an email without a
// button, and its body.
type Text struct {
	Subject     string
	ButtonLabel string
	Body        string
}

// Email is an email's built-in definition: its identifier, used in API paths, stored rows and audit
// entries, the placeholders it offers, and its text in each of the six built-in languages.
type Email struct {
	ID           string
	Placeholders []Placeholder
	BuiltIn      map[string]Text
}

// HasButton reports whether the email offers the button, and so has a button label.
func (e *Email) HasButton() bool {
	_, ok := e.placeholder(Button)
	return ok
}

func (e *Email) placeholder(name string) (Placeholder, bool) {
	for _, p := range e.Placeholders {
		if p.Name == name {
			return p, true
		}
	}
	return Placeholder{}, false
}

// Values are what an email's placeholders read when it is sent. The renderer that draws the email
// sets AppName; Expiry is written in the email's language when it is rendered.
type Values struct {
	AppName string
	Name    string
	Link    string
	Code    string
	Expiry  time.Duration
	// CodesLeft is how many unused recovery codes are left, which {{codes_left}} writes as a number.
	CodesLeft int
}

// Message is an email ready to send: its subject and the HTML document it is sent as, whose
// plain-text part the sender works out.
type Message struct {
	Subject string
	HTML    string
}

// Languages are the six built-in languages every email is written in, as the catalogs built into
// Goiabada are tagged, English first.
var Languages = []string{"en", "de", "es", "fr", "it", "pt-BR"}

// languageTags are Languages parsed, in the same order, for the matcher.
var languageTags = func() []language.Tag {
	tags := make([]language.Tag, len(Languages))
	for i, l := range Languages {
		tags[i] = language.MustParse(l)
	}
	return tags
}()

// Language answers the built-in language an email to a recipient reading locale is written in, as an
// email's copy was chosen before its text moved here (#531): locale is matched against the six
// languages followed by English, so a regional variant reads its language's text (fr-CA reads fr)
// and a language with none, one an operator added through an override catalog among them, reads
// English. The answer is always one of Languages, by the index the matcher answers rather than the
// tag it prints, which can come back region-extended.
func Language(locale string) string {
	parsed, _, err := language.ParseAcceptLanguage(locale)
	if err != nil || len(parsed) == 0 {
		return Languages[0]
	}
	_, index, _ := language.NewMatcher(languageTags).Match(append(parsed, language.English)...)
	return Languages[index]
}

// RecipientName is what {{name}} reads for a recipient (#818 decision 15): their full name, or, for
// one with none, the address the email is sent to, so no email reads "Hello ,".
func RecipientName(fullName, address string) string {
	if strings.TrimSpace(fullName) == "" {
		return address
	}
	return fullName
}

// builtIns are every email's built-in definition.
var builtIns = []*Email{
	PasswordResetLink, ActivationLink, Welcome, RegistrationExistingAccount, NewUserSetup, VerificationCode, TestEmail,
	EmailAddressChanged, PasswordChanged, PasswordChangedByAdministrator, PasswordReset,
	OTPEnabled, OTPDisabled, OTPDisabledByAdministrator, OTPLockout, RecoveryCodeUsed, RecoveryCodesReplaced,
	AccountDeleted, AccountDeletedByAdministrator,
}

// BuiltIns answers every email's built-in definition. The slice is the caller's own.
func BuiltIns() []*Email {
	return append([]*Email(nil), builtIns...)
}
