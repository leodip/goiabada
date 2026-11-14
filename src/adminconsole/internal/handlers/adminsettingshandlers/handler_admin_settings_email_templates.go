package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/language"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The Email templates tab under Admin, Email (#818 decision 14): the list of every email in its
// groups, and the editor of one email in one language, which saves and resets that language through
// the admin API. What an email says is global; how it looks is its brand's.

const emailTemplatesPath = "/admin/settings/email/templates"

// The editor's two notices, left by a save and a reset for the page they redirect to.
const (
	flashEmailTemplateSaved = "emailTemplateSaved"
	flashEmailTemplateReset = "emailTemplateReset"
)

// emailTemplateGroups are the list's groups, in order, and the emails each holds, in order, by
// identifier. Each email's name and the sentence saying when it is sent are the console's, in its
// catalogs, under adminconsole.email_templates.email.<identifier>.
var emailTemplateGroups = []struct {
	key    string
	emails []string
}{
	{"registration", []string{"activation_link", "welcome", "registration_existing_account"}},
	{"password", []string{"password_reset_link", "password_reset", "password_changed", "password_changed_by_administrator"}},
	{"verification", []string{"verification_code"}},
	{"two_factor", []string{"otp_enabled", "otp_disabled", "otp_disabled_by_administrator", "otp_lockout",
		"recovery_code_used", "recovery_codes_replaced"}},
	{"account", []string{"new_user_setup", "email_address_changed", "account_deleted", "account_deleted_by_administrator"}},
	{"test", []string{"test"}},
}

// knownEmailTemplate reports whether the console names the email, which every email the auth server
// it ships with lists is.
func knownEmailTemplate(id string) bool {
	for _, group := range emailTemplateGroups {
		for _, email := range group.emails {
			if email == id {
				return true
			}
		}
	}
	return false
}

// EmailTemplateGroup is one group of the list: its key, which names its heading, and its emails.
type EmailTemplateGroup struct {
	Key    string
	Emails []EmailTemplateRow
}

// EmailTemplateRow is one email of the list: its identifier, whether the console names it, and its
// languages that are edited, invalid ones included, in the API's order.
type EmailTemplateRow struct {
	Id        string
	Known     bool
	Languages []EmailTemplateLanguage
}

// EmailTemplateLanguage is one language of an email: its tag, its English name, which the template
// labels it with as the Page language select does (LocaleLabel), and its status.
type EmailTemplateLanguage struct {
	Tag     string
	Name    string
	Status  string
	Current bool
}

// Edited reports whether the language holds an edit that is sent.
func (l EmailTemplateLanguage) Edited() bool { return l.Status == api.EmailTemplateStatusEdited }

// Invalid reports whether the language holds an edit that breaks a rule of this release, so the
// built-in text is sent instead.
func (l EmailTemplateLanguage) Invalid() bool { return l.Status == api.EmailTemplateStatusInvalid }

// EmailTemplatePlaceholder is one placeholder the email offers: its name, as written in a text, and
// whether the body cannot do without it and whether the subject may use it.
type EmailTemplatePlaceholder struct {
	Name      string
	Written   string
	Required  bool
	InSubject bool
}

// EmailTemplateText is one language's text as the editor's form holds it. The editor's script reads
// the text as saved in this shape, to tell an unsaved change.
type EmailTemplateText struct {
	Subject     string `json:"subject"`
	ButtonLabel string `json:"buttonLabel"`
	Body        string `json:"body"`
}

func languageName(tag string) string {
	if l, ok := locales.ByID(tag); ok {
		return l.Name
	}
	return tag
}

// emailTemplatesLister is what the list needs: every email with its languages' status.
type emailTemplatesLister interface {
	GetEmailTemplates(ctx context.Context, accessToken string) ([]api.EmailTemplateSummaryResponse, error)
}

// HandleEmailTemplatesGet draws the list of every email, in the console's groups, with its edited
// and invalid languages marked.
func HandleEmailTemplatesGet(httpHelper HttpHelper, apiClient emailTemplatesLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		summaries, err := apiClient.GetEmailTemplates(r.Context(), token)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		rows := map[string]EmailTemplateRow{}
		var unknown []EmailTemplateRow
		for _, summary := range summaries {
			row := EmailTemplateRow{Id: summary.Id, Known: knownEmailTemplate(summary.Id), Languages: []EmailTemplateLanguage{}}
			for _, l := range summary.Languages {
				if l.Status == api.EmailTemplateStatusEdited || l.Status == api.EmailTemplateStatusInvalid {
					row.Languages = append(row.Languages, EmailTemplateLanguage{Tag: l.Language, Name: languageName(l.Language), Status: l.Status})
				}
			}
			rows[summary.Id] = row
			if !row.Known {
				unknown = append(unknown, row)
			}
		}

		groups := make([]EmailTemplateGroup, 0, len(emailTemplateGroups))
		for _, g := range emailTemplateGroups {
			group := EmailTemplateGroup{Key: g.key}
			for _, id := range g.emails {
				if row, ok := rows[id]; ok {
					group.Emails = append(group.Emails, row)
				}
			}
			// An email the console does not name, from an auth server newer than it, is listed by its
			// identifier with the account notices rather than left out.
			if g.key == "account" {
				group.Emails = append(group.Emails, unknown...)
			}
			if len(group.Emails) > 0 {
				groups = append(groups, group)
			}
		}

		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_templates.html",
			map[string]interface{}{"groups": groups}); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// emailTemplateReader reads one email with its six languages.
type emailTemplateReader interface {
	GetEmailTemplate(ctx context.Context, accessToken string, email string) (*api.EmailTemplateResponse, error)
}

// editorLanguage is the built-in language the editor opens in for a console read in catalogTag, as
// an email's language is matched against the languages its text is written in: a regional variant
// opens its language (fr-CA opens fr), and a language with none, one an operator added among them,
// opens English, which the API lists first.
func editorLanguage(catalogTag string, languages []api.EmailTemplateLanguageResponse) string {
	if len(languages) == 0 {
		return ""
	}
	tags := make([]language.Tag, len(languages))
	for i, l := range languages {
		tags[i] = language.Make(l.Language)
	}
	parsed, err := language.Parse(catalogTag)
	if err != nil {
		return languages[0].Language
	}
	_, index, _ := language.NewMatcher(tags).Match(parsed, language.English)
	return languages[index].Language
}

// HandleEmailTemplateOpenGet opens an email's editor, from the list, in the language that matches
// the one the administrator reads the console in (#818 decision 14).
func HandleEmailTemplateOpenGet(httpHelper HttpHelper, apiClient emailTemplateReader, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		email, err := apiClient.GetEmailTemplate(r.Context(), token, r.PathValue("email"))
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		tag := editorLanguage(i18n.CatalogTag(r.Context()), email.Languages)
		if tag == "" {
			httpHelper.NotFound(w, r)
			return
		}
		//nolint:gosec // G710: the configured base URL and a fixed path around two segments, each path-escaped
		http.Redirect(w, r, baseURL+emailTemplatePagePath(email.Id, tag), http.StatusFound)
	}
}

func emailTemplatePagePath(email, tag string) string {
	return emailTemplatesPath + "/" + url.PathEscape(email) + "/" + url.PathEscape(tag)
}

// loadEmailTemplateLanguage reads the email the path names and the language of it the path names,
// answering the request when it cannot: the 404 page for an email or a language that is not there,
// the language matched exactly as the API lists it.
func loadEmailTemplateLanguage(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient emailTemplateReader,
	token string) (*api.EmailTemplateResponse, *api.EmailTemplateLanguageResponse, bool) {
	email, err := apiClient.GetEmailTemplate(r.Context(), token, r.PathValue("email"))
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return nil, nil, false
	}
	tag := r.PathValue("language")
	for i := range email.Languages {
		if email.Languages[i].Language == tag {
			return email, &email.Languages[i], true
		}
	}
	httpHelper.NotFound(w, r)
	return nil, nil, false
}

// editorText is a language's text as the form holds it.
func editorText(text api.EmailTemplateTextResponse) EmailTemplateText {
	form := EmailTemplateText{Subject: text.Subject, Body: text.Body}
	if text.ButtonLabel != nil {
		form.ButtonLabel = *text.ButtonLabel
	}
	return form
}

// renderEmailTemplate draws the editor of lang with form in its fields and extra beside them, the
// notices or the refusal. The editor's text as saved goes with it, which leaving the page would
// discard the form for, and what the preview and Send test email are drawn from.
func renderEmailTemplate(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient emailTemplateEditorReader,
	token string, email *api.EmailTemplateResponse, lang *api.EmailTemplateLanguageResponse, form EmailTemplateText,
	extra map[string]interface{}) {

	languages := make([]EmailTemplateLanguage, 0, len(email.Languages))
	for _, l := range email.Languages {
		languages = append(languages, EmailTemplateLanguage{Tag: l.Language, Name: languageName(l.Language), Status: l.Status,
			Current: l.Language == lang.Language})
	}
	placeholders := make([]EmailTemplatePlaceholder, 0, len(email.Placeholders))
	for _, p := range email.Placeholders {
		placeholders = append(placeholders, EmailTemplatePlaceholder{Name: p.Name, Written: "{{" + p.Name + "}}",
			Required: p.Required, InSubject: p.InSubject})
	}
	problemIn := map[string]bool{}
	if lang.Status == api.EmailTemplateStatusInvalid {
		for _, p := range lang.Problems {
			problemIn[p.Field] = true
		}
	}

	bind := map[string]interface{}{
		"email":        email.Id,
		"known":        knownEmailTemplate(email.Id),
		"language":     lang.Language,
		"languages":    languages,
		"hasButton":    email.HasButton,
		"placeholders": placeholders,
		"form":         form,
		"saved":        editorText(lang.EditorText),
		"edited":       lang.Status != api.EmailTemplateStatusDefault,
		"invalid":      lang.Status == api.EmailTemplateStatusInvalid,
		"problems":     lang.Problems,
		"problemIn":    problemIn,
		"pagePath":     emailTemplatePagePath(email.Id, lang.Language),
		"savedNotice":  false,
		"resetNotice":  false,
	}
	for k, v := range extra {
		bind[k] = v
	}
	if !bindEmailTemplatePreview(httpHelper, w, r, apiClient, token, bind) {
		return
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_email_template.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleEmailTemplateGet draws the editor of one email in one language, with the editor's text in
// the form, which for an invalid edit is the edit as stored, beside a warning saying what is wrong
// and that the built-in text is being sent.
func HandleEmailTemplateGet(httpHelper HttpHelper, httpSession sessionstore.Store, apiClient emailTemplateEditorReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		email, lang, ok := loadEmailTemplateLanguage(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		_, saved := sess.TakeFlash(r.URL.Path, flashEmailTemplateSaved)
		_, reset := sess.TakeFlash(r.URL.Path, flashEmailTemplateReset)
		if saved || reset {
			if err := httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		renderEmailTemplate(httpHelper, w, r, apiClient, token, email, lang, editorText(lang.EditorText),
			map[string]interface{}{"savedNotice": saved, "resetNotice": reset})
	}
}

// emailTemplateSaver is what a save needs: the email and the brands, which a refusal is drawn with,
// and the write.
type emailTemplateSaver interface {
	emailTemplateEditorReader
	SaveEmailTemplate(ctx context.Context, accessToken string, email, language string,
		request *api.SaveEmailTemplateRequest) (*api.EmailTemplateLanguageResponse, error)
}

// emailTemplateErrorField is the form field a refusal of the save names in its error_field, the
// request's own member names, which are the fields' ids; empty for one that names none.
func emailTemplateErrorField(err error) string {
	pointer := render.ErrorPointer(err)
	if len(pointer) != 1 {
		return ""
	}
	switch pointer[0] {
	case api.EmailTemplateFieldSubject, api.EmailTemplateFieldButtonLabel, api.EmailTemplateFieldBody:
		return pointer[0]
	}
	return ""
}

// HandleEmailTemplatePost saves the form as the language's whole text, which applies at once, and
// comes back to the editor saying so. The subject and the button label are one line each and sent
// trimmed; the body is sent as typed, its line breaks normalized by the auth server. An email
// without a button sends no label.
func HandleEmailTemplatePost(httpHelper HttpHelper, httpSession sessionstore.Store, apiClient emailTemplateSaver,
	baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		email, lang, ok := loadEmailTemplateLanguage(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}

		form := EmailTemplateText{
			Subject: strings.TrimSpace(r.PostFormValue("subject")),
			Body:    r.PostFormValue("body"),
		}
		if email.HasButton {
			form.ButtonLabel = strings.TrimSpace(r.PostFormValue("buttonLabel"))
		}

		_, err := apiClient.SaveEmailTemplate(r.Context(), token, email.Id, lang.Language, &api.SaveEmailTemplateRequest{
			Subject: form.Subject, ButtonLabel: form.ButtonLabel, Body: form.Body,
		})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderEmailTemplate(httpHelper, w, r, apiClient, token, email, lang, form, map[string]interface{}{
					"error":      message,
					"errorField": emailTemplateErrorField(err),
				})
			})
			return
		}

		pagePath := emailTemplatePagePath(email.Id, lang.Language)
		if !leaveEmailTemplateFlash(httpHelper, httpSession, w, r, pagePath, flashEmailTemplateSaved) {
			return
		}
		http.Redirect(w, r, baseURL+pagePath, http.StatusFound)
	}
}

// emailTemplateResetter is what a reset needs: the email and the brands, which a refusal is drawn
// with, and the write.
type emailTemplateResetter interface {
	emailTemplateEditorReader
	ResetEmailTemplate(ctx context.Context, accessToken string, email, language string) error
}

// HandleEmailTemplateResetPost removes the language's edit, so the email is sent with the built-in
// text, and comes back to the editor saying so. The page asks first.
func HandleEmailTemplateResetPost(httpHelper HttpHelper, httpSession sessionstore.Store, apiClient emailTemplateResetter,
	baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := emailTemplateAccessToken(httpHelper, w, r)
		if !ok {
			return
		}
		email, lang, ok := loadEmailTemplateLanguage(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}

		if err := apiClient.ResetEmailTemplate(r.Context(), token, email.Id, lang.Language); err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderEmailTemplate(httpHelper, w, r, apiClient, token, email, lang, editorText(lang.EditorText), map[string]interface{}{
					"error": message,
				})
			})
			return
		}

		pagePath := emailTemplatePagePath(email.Id, lang.Language)
		if !leaveEmailTemplateFlash(httpHelper, httpSession, w, r, pagePath, flashEmailTemplateReset) {
			return
		}
		http.Redirect(w, r, baseURL+pagePath, http.StatusFound)
	}
}

// leaveEmailTemplateFlash leaves the notice key for the editor at pagePath, which the write
// redirects to, answering the request when the session cannot be saved. The other notice, never
// shown, is dropped, so the page says only this write's.
func leaveEmailTemplateFlash(httpHelper HttpHelper, httpSession sessionstore.Store, w http.ResponseWriter, r *http.Request,
	pagePath, key string) bool {
	sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return false
	}
	sess.TakeFlash(pagePath, flashEmailTemplateSaved)
	sess.TakeFlash(pagePath, flashEmailTemplateReset)
	sess.SetFlash(pagePath, key, "true")
	if err := httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return false
	}
	return true
}

// emailTemplateAccessToken answers the bearer the request carries, answering the request when it
// carries none, which is a wiring defect: every one of these routes is mounted under RequiresScope.
func emailTemplateAccessToken(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) (string, bool) {
	jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
	if !ok {
		httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
		return "", false
	}
	return jwtInfo.TokenResponse.AccessToken, true
}
