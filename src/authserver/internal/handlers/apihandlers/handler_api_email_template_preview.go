package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
)

// The admin API's preview and test send of an email template (#818 decisions 11 and 12): one
// language of one email drawn with a text nobody may have saved, as a recipient would get it, with
// sample values the server fixes, in the brand the request chooses or the default brand. A text a
// save would refuse is refused by both with the same answer. The preview stores and sends nothing,
// and takes any scope that reads settings; the test send sends text nobody has saved to an address
// someone typed, so it takes the scope a save takes, authserver:manage.

// emailTemplateBrandReader is what a preview and a test send read the brand they are drawn in from.
type emailTemplateBrandReader interface {
	GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error)
}

// emailTemplateSampleRenderer draws an email in a language with a text nobody may have saved, in a
// brand, or in the default brand for a nil one. render.Renderer satisfies it.
type emailTemplateSampleRenderer interface {
	RenderEmailSample(r *http.Request, email *emailtemplate.Email, lang string, text emailtemplate.Text,
		values emailtemplate.Values, brand *record.Brand) (emailtemplate.Message, error)
}

// The sample values a preview and a test send are drawn with (#818 decision 11): a sample name, a
// code in the verification code's shape, a number of codes left, and a link under a domain that
// never resolves (RFC 6761 section 6.4), so it leads nowhere. The app name is the settings', and
// the expiry the email's real lifetime.
const (
	emailTemplateSampleName      = "Jane Doe"
	emailTemplateSampleCode      = "ABCD1234"
	emailTemplateSampleLink      = "https://example.invalid/sample-link"
	emailTemplateSampleCodesLeft = 3
)

// emailTemplateLifetimes are the real lifetimes of the links and the code the emails that offer
// {{expiry}} carry, the ones their senders give, so a sample says what the email will.
var emailTemplateLifetimes = map[string]time.Duration{
	emailtemplate.PasswordResetLink.ID: emaillinks.ResetLinkLifetime,
	emailtemplate.ActivationLink.ID:    emaillinks.ActivationCodeLifetime,
	emailtemplate.NewUserSetup.ID:      emaillinks.SetupLinkLifetime,
	emailtemplate.VerificationCode.ID:  emailVerificationCodeLifetime,
}

// emailTemplateSampleValues are the values email's preview and test send are drawn with.
func emailTemplateSampleValues(email *emailtemplate.Email) emailtemplate.Values {
	return emailtemplate.Values{
		Name:      emailTemplateSampleName,
		Link:      emailTemplateSampleLink,
		Code:      emailTemplateSampleCode,
		Expiry:    emailTemplateLifetimes[email.ID],
		CodesLeft: emailTemplateSampleCodesLeft,
	}
}

// emailTemplateSample is what a preview and a test send draw: one language of an email, a text a
// save accepts, and the brand chosen, nil for the default brand.
type emailTemplateSample struct {
	email *emailtemplate.Email
	lang  string
	text  emailtemplate.Text
	brand *record.Brand
}

// checkEmailTemplateSample checks a text sent to be previewed or tested in lang of email as a save
// does, and reads the brand brandId names, answering the request with a 400 when the text breaks a
// rule or the brand is not there.
func checkEmailTemplateSample(w http.ResponseWriter, r *http.Request, database emailTemplateBrandReader,
	email *emailtemplate.Email, lang string, subject, buttonLabel, body string, brandId *int64) (*emailTemplateSample, bool) {
	text := emailtemplate.Text{Subject: subject, ButtonLabel: buttonLabel, Body: normalizeLineBreaks(body)}
	if problems := email.Check(text); len(problems) > 0 {
		writeValidationError(w, r, emailTemplateRefusalAt(email, problems[0]))
		return nil, false
	}
	sample := &emailTemplateSample{email: email, lang: lang, text: text}
	if brandId != nil {
		brand, err := database.GetBrandById(r.Context(), nil, *brandId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting the brand of an email template sample"),
				"brand_id", *brandId)
			return nil, false
		}
		if brand == nil {
			writeValidationError(w, r, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeEmailTemplateBrandNotFound, nil), "brandId"))
			return nil, false
		}
		sample.brand = brand
	}
	return sample, true
}

// render draws the sample with the sample values.
func (s *emailTemplateSample) render(r *http.Request, renderer emailTemplateSampleRenderer) (emailtemplate.Message, error) {
	message, err := renderer.RenderEmailSample(r, s.email, s.lang, s.text, emailTemplateSampleValues(s.email), s.brand)
	if err != nil {
		return emailtemplate.Message{}, errs.Wrap(err, "unable to render the email template sample")
	}
	return message, nil
}

// HandleEmailTemplatePreviewPost answers the subject, the HTML and the plain-text part the server
// would send for the text in the request, in the language the path names, with the sample values
// and in the chosen brand. It stores nothing and sends nothing.
func HandleEmailTemplatePreviewPost(database emailTemplateBrandReader, renderer emailTemplateSampleRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, lang, ok := emailTemplateLanguageFromPath(w, r)
		if !ok {
			return
		}
		var req api.PreviewEmailTemplateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		sample, ok := checkEmailTemplateSample(w, r, database, email, lang, req.Subject, req.ButtonLabel, req.Body, req.BrandId)
		if !ok {
			return
		}
		message, err := sample.render(r, renderer)
		if err != nil {
			writeInternalServerError(w, r, err, "email_template", email.ID, "language", lang)
			return
		}
		// The plain-text part the sender would send beside the HTML, worked out the same way.
		text, err := emaildelivery.PlainText(message.HTML)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "unable to work out the plain text of the email template sample"),
				"email_template", email.ID, "language", lang)
			return
		}
		writeJSON(w, r, http.StatusOK, api.PreviewEmailTemplateResponse{Subject: message.Subject, Html: message.HTML, Text: text})
	}
}

// HandleEmailTemplateSendTestPost sends the text in the request to the address it types, as a
// recipient would get it: in the language the path names, in the chosen brand, with the preview's
// sample values, and with nothing in its subject marking it as a test. It is refused as the SMTP
// test is while SMTP is off, answers a failed send with the SMTP test's fixed messages, and is
// audited as the SMTP test is, as sent_test_email naming the email template and the language.
func HandleEmailTemplateSendTestPost(
	database emailTemplateBrandReader,
	emailValidator EmailValidator,
	emailSender EmailSender,
	renderer emailTemplateSampleRenderer,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, lang, ok := emailTemplateLanguageFromPath(w, r)
		if !ok {
			return
		}
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SMTPEnabled {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSMTPNotEnabled, nil), "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		var req api.SendTestEmailTemplateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.To) == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsEmailDestinationRequired, nil))
			return
		}
		if err := emailValidator.ValidateEmailAddress(req.To); err != nil {
			writeValidationError(w, r, err)
			return
		}
		sample, ok := checkEmailTemplateSample(w, r, database, email, lang, req.Subject, req.ButtonLabel, req.Body, req.BrandId)
		if !ok {
			return
		}
		// Text nobody has saved, sent to an address someone typed, is reserved as a save is (#818
		// decision 12).
		if !settingsCeilingAllows(w, r, auditLogger) {
			return
		}

		message, err := sample.render(r, renderer)
		if err != nil {
			writeInternalServerError(w, r, err, "email_template", email.ID, "language", lang)
			return
		}
		input := &emaildelivery.SendEmailInput{To: req.To, Subject: message.Subject, HtmlBody: message.HTML}
		// As for the SMTP test, a failure answers the fixed message of its kind and the error, which
		// carries addresses and the server's own replies, goes to the log (#410 decision 5).
		result, err := emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
		if err != nil {
			slog.WarnContext(r.Context(), "unable to send the email template test", "email_template", email.ID,
				"language", lang, "error", err)
			writeLocalizedError(w, r, sendFailureMessage(err), "SEND_FAILED", http.StatusBadRequest)
			return
		}

		auditLogger.Log(r.Context(), audit.EventSentTestEmail, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"email_digest":   hashutil.HashString(strings.ToLower(strings.TrimSpace(req.To))),
			"email_template": email.ID,
			"language":       lang,
		})
		writeJSON(w, r, http.StatusOK, api.SendTestEmailResponse{Success: true, Encrypted: result.Encrypted})
	}
}
