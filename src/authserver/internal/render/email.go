package render

import (
	"bytes"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// emailLayout is the layout an email is drawn in, the frame around its body.
const emailLayout = "layouts/email_layout.html"

// emailContent fills the layout's three blocks for an email sent from its definition: its subject
// as its title, which a mail client rarely shows and so says nothing the subject does not, nothing
// in the head, and the body the format rendered.
const emailContent = `{{define "title"}}{{.emailSubject}}{{end}}{{define "head"}}{{end}}{{define "body"}}{{.emailBody}}{{end}}`

// RenderEmail renders email, sent from its built-in definition (#818), as the message a recipient
// receives: in the built-in language that matches the language r's context carries
// (i18n.WithRecipientLanguage for an email to a user), in the brand of the page it was sent from as
// RequestPageBrand reads it, and with values, whose app name is the settings'. The body is drawn
// inside the email layout, which writes the frame inline from emailFrame as a template email's is,
// and the layout marks the email with the language its text is written in.
func (h *Renderer) RenderEmail(r *http.Request, email *emailtemplate.Email, values emailtemplate.Values) (emailtemplate.Message, error) {
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return emailtemplate.Message{}, reqctx.ErrNoSettings
	}
	lang := emailtemplate.Language(i18n.LocaleTag(r.Context()))
	text, ok := email.BuiltIn[lang]
	if !ok {
		return emailtemplate.Message{}, errs.Errorf("the email %s has no built-in text in %s", email.ID, lang)
	}
	values.AppName = settings.AppName

	frame := emailFrameOf(r.Context(), settings.AppName, RequestPageBrand(r.Context(), h.brands), h.baseURL)
	rendered, err := email.Render(lang, text, values, emailLookOf(frame))
	if err != nil {
		return emailtemplate.Message{}, errs.Wrap(err, "unable to render the email "+email.ID)
	}

	templ, err := template.New(filepath.Base(emailLayout)).Funcs(templateFuncMap).ParseFS(h.templateFS, emailLayout)
	if err != nil {
		return emailtemplate.Message{}, errs.Wrap(err, "unable to parse the email layout")
	}
	if templ, err = templ.Parse(emailContent); err != nil {
		return emailtemplate.Message{}, errs.Wrap(err, "unable to parse the email's content")
	}
	var buf bytes.Buffer
	err = templ.ExecuteTemplate(&buf, filepath.Base(emailLayout), map[string]interface{}{
		"ctx":          r.Context(),
		"appName":      settings.AppName,
		"emailLang":    lang,
		"emailFrame":   frame,
		"emailSubject": rendered.Subject,
		"emailBody":    rendered.Body,
	})
	if err != nil {
		return emailtemplate.Message{}, errs.Wrap(err, "unable to execute the email layout")
	}
	return emailtemplate.Message{Subject: rendered.Subject, HTML: buf.String()}, nil
}

// emailLookOf is what a body takes from the frame it is drawn in: the brand's color for its links
// and its button, the button's label color, corner and font, and the boxed code's colors, corner and
// monospace font.
func emailLookOf(frame EmailFrame) emailtemplate.Look {
	return emailtemplate.Look{
		Link: frame.Link, OnBrand: frame.OnBrand, ControlRadius: frame.ControlRadius,
		FontFamily: frame.FontFamily,
		Subtle:     frame.Subtle, Line: frame.Line, BoxRadius: frame.BoxRadius, Ink: frame.Ink,
		CodeFamily: frame.CodeFamily,
	}
}
