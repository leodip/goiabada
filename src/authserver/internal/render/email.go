package render

import (
	"bytes"
	"context"
	"database/sql"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// EmailTemplateReader is what an email reads its administrator's edit from (#818 decision 7).
// data.Database satisfies it.
type EmailTemplateReader interface {
	GetEmailTemplate(ctx context.Context, tx *sql.Tx, emailTemplate string, language string) (*record.EmailTemplate, error)
}

// WithEmailTemplates returns a copy of h whose emails are sent with the edits edits reads, each in
// its recipient's language. A renderer without one sends every email with its built-in text.
func (h *Renderer) WithEmailTemplates(edits EmailTemplateReader) *Renderer {
	withEdits := *h
	withEdits.edits = edits
	return &withEdits
}

// emailLayout is the layout an email is drawn in, the frame around its body.
const emailLayout = "layouts/email_layout.html"

// emailContent fills the layout's three blocks for an email sent from its definition: its subject
// as its title, which a mail client rarely shows and so says nothing the subject does not, nothing
// in the head, and the body the format rendered.
const emailContent = `{{define "title"}}{{.emailSubject}}{{end}}{{define "head"}}{{end}}{{define "body"}}{{.emailBody}}{{end}}`

// RenderEmail renders email, sent from its built-in definition (#818), as the message a recipient
// receives: in the built-in language that matches the language r's context carries
// (i18n.WithRecipientLanguage for an email to a user), with the text textToSend answers for it, in
// the brand of the page it was sent from as RequestPageBrand reads it, and with values, whose app
// name is the settings'. The body is drawn inside the email layout, which writes the frame inline
// from emailFrame, and the layout marks the email with the language its text is written in. The
// whole email is in that language, its frame and footer as well as its text: the frame and footer
// are drawn from the recipient's catalog when it is written in that language, so an operator's
// fr-CA wording reaches an email in French, and from the language's own catalog when it is not, so
// a recipient reading a language with no built-in text, one an operator added through an override
// catalog, gets all of it in English.
func (h *Renderer) RenderEmail(r *http.Request, email *emailtemplate.Email, values emailtemplate.Values) (emailtemplate.Message, error) {
	lang := emailtemplate.Language(i18n.LocaleTag(r.Context()))
	if _, ok := email.BuiltIn[lang]; !ok {
		return emailtemplate.Message{}, errs.Errorf("the email %s has no built-in text in %s", email.ID, lang)
	}
	ctx := r.Context()
	if !emailtemplate.SameLanguage(i18n.CatalogTag(ctx), lang) {
		// lang is one of the six built-in catalogs' tags, so the recipient's language is exactly it.
		ctx = i18n.WithRecipientLanguage(ctx, lang, "")
	}
	return h.drawEmail(ctx, email, lang, h.textToSend(ctx, email, lang), values, RequestPageBrand(ctx, h.brands))
}

// RenderEmailSample renders email in lang with text, as given and unchecked, the way RenderEmail
// draws an email sent with it: the email template preview and its test send (#818 decisions 11 and
// 12), whose text nobody may have saved. It is drawn in brand, or in the default brand when brand is
// nil, whatever page r is from, and values, whose app name is the settings', are the caller's sample
// values. The whole email is in lang, its frame and footer as well as its text, as a recipient
// reading lang gets it, whatever language the caller reads; r's own context is left in the caller's.
func (h *Renderer) RenderEmailSample(r *http.Request, email *emailtemplate.Email, lang string, text emailtemplate.Text,
	values emailtemplate.Values, brand *record.Brand) (emailtemplate.Message, error) {
	if _, ok := email.BuiltIn[lang]; !ok {
		return emailtemplate.Message{}, errs.Errorf("the email %s has no built-in text in %s", email.ID, lang)
	}
	// lang is one of the six built-in catalogs' tags, so the recipient's language is exactly it, and
	// it replaces the caller's page language as an email to a user replaces the sender's.
	ctx := i18n.WithRecipientLanguage(r.Context(), lang, "")
	page := DefaultPageBrand(ctx, h.brands)
	if brand != nil {
		page = PageBrand{}
		if h.brands != nil {
			page = pageBrandOf(ctx, h.brands, brand)
		}
	}
	return h.drawEmail(ctx, email, lang, text, values, page)
}

// drawEmail draws email in lang with text and values, whose app name is the settings', inside the
// email layout, which writes the frame inline from brand's look, and marks the email with the
// language its text is written in.
func (h *Renderer) drawEmail(ctx context.Context, email *emailtemplate.Email, lang string, text emailtemplate.Text,
	values emailtemplate.Values, brand PageBrand) (emailtemplate.Message, error) {
	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		return emailtemplate.Message{}, reqctx.ErrNoSettings
	}
	values.AppName = settings.AppName

	frame := emailFrameOf(ctx, settings.AppName, brand, h.baseURL)
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
		"ctx":          ctx,
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

// textToSend answers the text email is sent with in lang: its administrator's edit in lang laid over
// the built-in text (#818 decision 7), read at each send with no cache, so a save applies to the next
// email. It is the built-in text of lang, all of it, when there is no edit, when the edit breaks a
// rule a save would refuse it for today (decision 8), and when the edit cannot be read (decision 16):
// a reset link or a security notice in the built-in wording is better than one that does not arrive.
// The two last are logged, naming the email and the language and never the text.
func (h *Renderer) textToSend(ctx context.Context, email *emailtemplate.Email, lang string) emailtemplate.Text {
	if h.edits == nil {
		return email.BuiltIn[lang]
	}
	edit, err := h.edits.GetEmailTemplate(ctx, nil, email.ID, lang)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read the email template edit, so the email is sent with the built-in text",
			"email_template", email.ID, "language", lang, "error", err)
		return email.BuiltIn[lang]
	}
	text, problems := email.TextToSend(lang, edit)
	if len(problems) > 0 {
		slog.WarnContext(ctx, "the email template edit is invalid, so the email is sent with the built-in text",
			"email_template", email.ID, "language", lang, "problems", problems.Broken())
	}
	return text
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
