package adminsettingshandlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// The email template editor's preview and Send test email (#818 decisions 11 and 12). Both take the
// text in the form, saved or not, which the admin API draws as a recipient would get it, with the
// sample values it fixes, in the language being edited and the brand chosen for the preview.
//
// The preview is two requests from email-template-preview.js. The first, JSON, answers the subject
// and the plain-text part, or the refusal a save would give, which the editor shows where the
// preview is, keeping the last good preview. Only then does the page load the frame through the
// second: the one console route that answers a document the console may frame, the email's HTML
// under a policy of its own (emailFramePolicy). Its HTML is the auth server's, never the browser's:
// the route draws it from the text, as the JSON preview does, so the console serves no markup a
// request carries. It is a POST, which the console's origin check refuses from any other site, so it
// answers only a signed-in administrator's own request.

// BrandOption is one brand the preview can be drawn in.
type BrandOption struct {
	Id   int64
	Name string
}

// emailTemplateEditorReader is what the editor is drawn from: the email, and the brands its preview
// can be drawn in.
type emailTemplateEditorReader interface {
	emailTemplateReader
	GetAllBrands(ctx context.Context, accessToken string) ([]api.BrandResponse, error)
}

// emailTemplatePreviewer draws a text of one language of an email with the sample values.
type emailTemplatePreviewer interface {
	PreviewEmailTemplate(ctx context.Context, accessToken string, email, language string,
		request *api.PreviewEmailTemplateRequest) (*api.PreviewEmailTemplateResponse, error)
}

// emailTemplateTestSender sends a text of one language of an email to an address.
type emailTemplateTestSender interface {
	SendTestEmailTemplate(ctx context.Context, accessToken string, email, language string,
		request *api.SendTestEmailTemplateRequest) (*api.SendTestEmailResponse, error)
}

// emailTemplateSample is the text in the editor's form and the brand chosen for its preview, as the
// preview and the test send take them; BrandId is nil for the default brand.
type emailTemplateSample struct {
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
	BrandId     *int64 `json:"brandId"`
}

// trimmed is the sample as a save sends its text: the subject and the button label are one line
// each and sent trimmed, and the body as typed, its line breaks normalized by the auth server. An
// email without a button has no label field, so the editor sends an empty one.
func (s emailTemplateSample) trimmed() emailTemplateSample {
	s.Subject = strings.TrimSpace(s.Subject)
	s.ButtonLabel = strings.TrimSpace(s.ButtonLabel)
	return s
}

func (s emailTemplateSample) previewRequest() *api.PreviewEmailTemplateRequest {
	s = s.trimmed()
	return &api.PreviewEmailTemplateRequest{Subject: s.Subject, ButtonLabel: s.ButtonLabel, Body: s.Body, BrandId: s.BrandId}
}

// emailTemplatePreviewAnswer is what the editor shows beside the frame.
type emailTemplatePreviewAnswer struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// emailTemplateJSONAccessToken answers the bearer the request carries, answering the request as
// JSON when it carries none, which is a wiring defect: these routes are mounted under RequiresScope.
func emailTemplateJSONAccessToken(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) (string, bool) {
	jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
	if !ok {
		httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
		return "", false
	}
	return jwtInfo.TokenResponse.AccessToken, true
}

// decodeEmailTemplateJSON reads the request's JSON body into into, answering a body that does not
// decode.
func decodeEmailTemplateJSON(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, into any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(body, into) != nil {
		render.JSONBadRequestBody(httpHelper, w, r)
		return false
	}
	return true
}

// HandleEmailTemplatePreviewPost answers the subject and the plain-text part of the email the text
// in the request draws, in the language the address names and the brand chosen, or, as JSON, the
// refusal a save would give it.
func HandleEmailTemplatePreviewPost(httpHelper HttpHelper, apiClient emailTemplatePreviewer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sample emailTemplateSample
		if !decodeEmailTemplateJSON(httpHelper, w, r, &sample) {
			return
		}
		token, ok := emailTemplateJSONAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		preview, err := apiClient.PreviewEmailTemplate(r.Context(), token, r.PathValue("email"), r.PathValue("language"),
			sample.previewRequest())
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		httpHelper.EncodeJSON(w, r, emailTemplatePreviewAnswer{Subject: preview.Subject, Text: preview.Text})
	}
}

// emailFramePolicy is the framed route's Content-Security-Policy, which replaces the console's on
// its answers alone (#818 decision 11). default-src 'none' loads nothing, and the email draws with
// two exceptions: its style attributes, the only styling an email has, which every console page
// refuses, and its images from the auth server, assetOrigins, where the brand's logo is. A form and
// a base address do nothing, frame-ancestors 'self' lets the console alone frame it, and sandbox runs
// it sandboxed however it is opened, as the editor's frame does: no script runs, and with
// <base target="_blank"> (emailFrameBase) its links open a window the sandbox refuses, so they go
// nowhere.
func emailFramePolicy(assetOrigins []string) string {
	images := "img-src"
	if len(assetOrigins) == 0 {
		images += " 'none'"
	}
	for _, origin := range assetOrigins {
		images += " " + origin
	}
	return "default-src 'none'; style-src-attr 'unsafe-inline'; " + images +
		"; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox"
}

// emailFrameBase opens every link of the framed email in a new window, which its sandbox refuses: a
// link in the frame would otherwise load its page in the frame itself, which a sandbox allows.
const emailFrameBase = `<base target="_blank">`

// withEmailFrameBase answers html with emailFrameBase first in its head, or first of all when it has
// none. The HTML is the auth server's email layout, whose head is the first of its tags to hold one.
func withEmailFrameBase(html string) string {
	if at := strings.Index(html, "<head>"); at >= 0 {
		at += len("<head>")
		return html[:at] + emailFrameBase + html[at:]
	}
	return emailFrameBase + html
}

// setEmailFrameHeaders replaces the console's framing and policy headers with the framed route's,
// before anything is written, so its refusals carry them too.
func setEmailFrameHeaders(h http.Header, assetOrigins []string) {
	h.Set("Content-Security-Policy", emailFramePolicy(assetOrigins))
	h.Set("X-Frame-Options", "SAMEORIGIN")
}

// HandleEmailTemplatePreviewFramePost answers the email the text in the form draws, in the language
// the address names and the brand chosen, as an HTML document of its own, which the editor's
// sandboxed frame shows. A text the API refuses, which the JSON preview has already said beside
// the frame, answers its status with nothing to draw.
func HandleEmailTemplatePreviewFramePost(httpHelper HttpHelper, apiClient emailTemplatePreviewer, assetOrigins []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setEmailFrameHeaders(w.Header(), assetOrigins)
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		sample := emailTemplateSample{
			Subject:     r.PostFormValue("subject"),
			ButtonLabel: r.PostFormValue("buttonLabel"),
			Body:        r.PostFormValue("body"),
		}
		if id, err := strconv.ParseInt(r.PostFormValue("brandId"), 10, 64); err == nil {
			sample.BrandId = &id
		}

		preview, err := apiClient.PreviewEmailTemplate(r.Context(), token, r.PathValue("email"), r.PathValue("language"),
			sample.previewRequest())
		if err != nil {
			// The refusals a form is drawn again for, a text a save refuses among them, answer their
			// own status; the classifier answers the rest as it answers any page.
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(string) {
				status := http.StatusBadRequest
				var apiErr *apiclient.APIError
				if errors.As(err, &apiErr) {
					status = apiErr.StatusCode
				}
				w.WriteHeader(status)
			})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // G705: the auth server's email renderer drew this HTML from the text, escaping every value, and the frame policy above runs no script in it
		_, _ = io.WriteString(w, withEmailFrameBase(preview.Html))
	}
}

// emailTemplateTestInput is what Send test email sends: the address typed, and the text and the
// brand the preview is drawn with.
type emailTemplateTestInput struct {
	To string `json:"to"`
	emailTemplateSample
}

// emailTemplateTestAnswer is the sentence the editor says beside Send test email.
type emailTemplateTestAnswer struct {
	Message string `json:"message"`
}

// HandleEmailTemplateSendTestPost sends the text in the request to the address it types, as a
// recipient would get it, in the language the address names and the brand chosen for the preview,
// and answers the sentence saying where it went, and that it went unencrypted when it did, as the
// SMTP test says; a refusal is answered as JSON with the API's sentence.
func HandleEmailTemplateSendTestPost(httpHelper HttpHelper, apiClient emailTemplateTestSender) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input emailTemplateTestInput
		if !decodeEmailTemplateJSON(httpHelper, w, r, &input) {
			return
		}
		token, ok := emailTemplateJSONAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		to := strings.TrimSpace(input.To)
		sample := input.trimmed()
		answer, err := apiClient.SendTestEmailTemplate(r.Context(), token, r.PathValue("email"), r.PathValue("language"),
			&api.SendTestEmailTemplateRequest{To: to, Subject: sample.Subject, ButtonLabel: sample.ButtonLabel,
				Body: sample.Body, BrandId: sample.BrandId})
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		message := i18n.T(r.Context(), "adminconsole.admin_settings.email_sendtest.sent_successfully",
			map[string]any{"address": to})
		if !answer.Encrypted {
			message += " " + i18n.T(r.Context(), "adminconsole.admin_settings.email_sendtest.sent_unencrypted")
		}
		httpHelper.EncodeJSON(w, r, emailTemplateTestAnswer{Message: message})
	}
}

// bindEmailTemplatePreview adds what the preview and Send test email are drawn from to bind: every
// brand, in the auth server's order, and the default brand's name, which the selector's first
// choice names; whether SMTP is on, without which the test send is disabled; and the signed-in
// administrator's own address, which the test send's address starts at. It answers false, having
// answered the page that says why, when the brands cannot be read.
func bindEmailTemplatePreview(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient emailTemplateEditorReader,
	token string, bind map[string]interface{}) bool {
	brands, err := apiClient.GetAllBrands(r.Context(), token)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return false
	}
	options := make([]BrandOption, 0, len(brands))
	defaultName := ""
	for _, brand := range brands {
		options = append(options, BrandOption{Id: brand.Id, Name: brand.Name})
		if brand.IsDefault {
			defaultName = brand.Name
		}
	}
	bind["brands"] = options
	bind["defaultBrandName"] = defaultName

	smtpEnabled := false
	if settings, ok := reqctx.SettingsFrom(r.Context()); ok {
		smtpEnabled = settings.SMTPEnabled
	}
	bind["smtpEnabled"] = smtpEnabled

	testAddress := ""
	if jwtInfo, ok := reqctx.JwtInfoFrom(r.Context()); ok && jwtInfo.IdToken != nil {
		testAddress = jwtInfo.IdToken.StringClaim("email")
	}
	bind["testAddress"] = testAddress
	return true
}
