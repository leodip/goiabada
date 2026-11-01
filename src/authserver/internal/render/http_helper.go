package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/requestid"
	"golang.org/x/text/language"
)

// Renderer renders pages from the template file system it was built over, and writes JSON.
type Renderer struct {
	templateFS fs.FS
	assets     *assetFingerprints
}

// New returns a Renderer over templateFS, which holds the layouts and pages, and staticFS, the
// static files the server serves under /static/, which the pages name through the asset template
// function.
func New(templateFS fs.FS, staticFS fs.FS) *Renderer {
	return &Renderer{templateFS: templateFS, assets: newAssetFingerprints(staticFS)}
}

// InternalServerError logs err once, with a stack and the request id the page shows, and renders
// the 500 page.
//
// errs.WithStack is applied here rather than at the 876 call sites, which is what lets every one of
// them pass err bare: it is the identity on anything this tree constructed, so the only value it
// changes is a bare error from the standard library or a dependency, which would otherwise log with
// no frames at all. The attributes are structured, and the stack rides inside the error attribute
// because slog's default handler formats an error value with %+v (#279 decisions 9 and 10).
func (h *Renderer) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	requestId := requestid.FromContext(r.Context())
	// No request_id attribute: the installed handler reads it off the context this call passes
	// it, so naming it here would write it twice (#320 decision 2). requestId is still read,
	// because the page below shows it to whoever hit the error.
	slog.ErrorContext(r.Context(), "internal server error", "error", errs.WithStack(err))

	// The status travels in the bind map rather than through an early WriteHeader. Committing it
	// first freezes the header map, so every header RenderTemplate sets afterwards is silently
	// dropped: this page has been shipping without the Content-Type the helper writes, and would
	// ship without the cache directives too. RenderTemplate writes the status from _httpStatus, and
	// the http.Error fallback below still writes 500 when the render fails, so the answer is 500
	// either way. It also makes this last-resort path obey the rule the form_post emitters state,
	// that a failed render leaves the response untouched for whoever renders the error (#247).
	err = h.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/error.html", map[string]interface{}{
		"requestId":   requestId,
		"_httpStatus": http.StatusInternalServerError,
	})
	if err != nil {
		// The last resort writes fixed catalog text and never the render error, which named
		// template files and internal state to whoever hit the page. The request id is the one
		// variable, and it is client-chosen: requestid.Middleware adopts an inbound X-Request-Id
		// verbatim, so it is escaped and clipped before it is echoed (#159, #414, #425).
		slog.ErrorContext(r.Context(), "unable to render the error page", "error", err)
		http.Error(w, i18n.T(r.Context(), "error.body")+" "+i18n.T(r.Context(), "error.request_id_label")+" "+
			logging.FieldForLog(requestId), http.StatusInternalServerError)
	}
}

// NotFound renders the 404 page, and logs nothing.
//
// The silence is the point. A URL whose id does not parse, whose id is absent, or that names an
// entity the API says is gone is a fact about the request, not a fault an operator has to
// investigate: answering it with the 500 page spent a stack, a log record and a request id on a
// stale bookmark, and told the administrator that the server had broken. RFC 9110 section 15.5.5:
// 404 "indicates that the origin server did not find a current representation for the target
// resource or is not willing to disclose that one exists" (#279).
//
// A render failure is a real server fault and falls through to InternalServerError, which owns
// every header as well as the status: RenderTemplate buffers the page before it touches the
// response, so nothing has been written when it returns an error.
func (h *Renderer) NotFound(w http.ResponseWriter, r *http.Request) {
	err := h.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/not_found.html", map[string]interface{}{
		"_httpStatus": http.StatusNotFound,
	})
	if err != nil {
		h.InternalServerError(w, r, err)
	}
}

func (h *Renderer) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	buf, err := h.RenderTemplateToBuffer(r, layoutName, templateName, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	// Every page built from a template is dynamic, per-user UI, and several of them carry a
	// credential: the password form, the OTP prompt, the enrolment page that shows the TOTP seed,
	// and the consent screen. RFC 6749 section 5.1 makes both header fields a MUST for any response
	// containing tokens, credentials, or other sensitive information, unqualified as to endpoint,
	// and RFC 9111 section 4.2.2 says an origin server that wants to prevent caching has to say so
	// explicitly: a 200 with no directives is heuristically cacheable and a cache may store it.
	// Writing the pair here rather than in a middleware covers every render site in both modules by
	// construction, and structurally cannot reach static assets, images, JWKS or discovery, which
	// must stay cacheable.
	//
	// The position matters as much as the values. It is after RenderTemplateToBuffer has returned
	// successfully, so a render that fails leaves the response completely untouched and the
	// caller's InternalServerError still owns every header as well as the status (#247).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if data != nil && data["_httpStatus"] != nil {
		httpStatus, ok := data["_httpStatus"].(int)
		if !ok {
			return errs.New("unable to cast _httpStatus to int")
		}
		w.WriteHeader(httpStatus)
	}

	_, err = buf.WriteTo(w)
	if err != nil {
		return errs.New("unable to write to response writer")
	}
	return nil
}

func (h *Renderer) RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {

	// The layout reads the settings straight off the request. It used to take them through a port,
	// because the renderer lived in core and core could not import the persistence models, and #385
	// moved it here. A render without them is refused rather than drawn with a blank app name; when
	// the refused render is the error page itself, InternalServerError answers in plain text (#433).
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return nil, reqctx.ErrNoSettings
	}
	// The layout's values are written into the caller's map rather than a copy, which the
	// admin console's twin relies on and its tests read back; a nil map is therefore allocated
	// here rather than panicking on the first write below. No caller passes nil today, so this
	// closes a latent panic, and the twin carries the same guard (#435).
	if data == nil {
		data = map[string]interface{}{}
	}
	data["appName"] = settings.AppName
	data["uiTheme"] = settings.UITheme
	data["urlPath"] = r.URL.Path
	data["smtpEnabled"] = settings.SMTPEnabled
	data["goiabadaVersion"] = buildinfo.Version + " (" + buildinfo.BuildDate + ")"
	// Inject the request context so templates can call {{ T $.ctx "..." }}
	// and every other locale-reading template function. This is this
	// application's one injection point; the admin console's renderer has its
	// own, and the two are deliberately separate (#385).
	data["ctx"] = r.Context()

	name := filepath.Base(layoutName)

	templateName = strings.TrimPrefix(templateName, "/")
	layoutName = strings.TrimPrefix(layoutName, "/")

	// Per-locale email template lookup. For emails (templateName under
	// "emails/"), a copy for exactly the recipient's tag still wins first,
	// and when there is none the locale is matched against the languages a
	// copy of this email exists in, not taken literally, with the English
	// fallback the senders give the subject (i18n.WithRecipientLanguage for
	// an email to a user, the registration page's language for one to an
	// address with no account). A regional variant
	// then falls back to its base language (es-MX renders the .es copy, the
	// subject renders from the es catalog), and a locale no copy shares a
	// language with keeps <name>.html, the English baseline. The default
	// locale "en" is always served by the base file (#531).
	//
	// The layout marks the email with the language of the copy chosen, which
	// is the body's, not the recipient's locale (#645 decision 10).
	if strings.HasPrefix(templateName, "emails/") {
		requested := templateName
		locale := i18n.LocaleTag(r.Context())
		if locale != "" && locale != "en" {
			ext := filepath.Ext(templateName)
			base := strings.TrimSuffix(templateName, ext)
			candidate := base + "." + locale + ext
			if _, err := fs.Stat(h.templateFS, candidate); err == nil {
				templateName = candidate
			} else {
				templateName = localizedEmailTemplate(h.templateFS, templateName, locale)
			}
		}
		data["emailLang"] = emailCopyLang(requested, templateName)
	}

	templateFiles := []string{
		layoutName,
		templateName,
	}

	files, err := fs.ReadDir(h.templateFS, "partials")
	if err == nil && len(files) > 0 {
		// Partials directory exists and has files, so include them
		for _, file := range files {
			templateFiles = append(templateFiles, "partials/"+file.Name())
		}
	}

	templ, err := template.New(name).Funcs(templateFuncMap).Funcs(template.FuncMap{"asset": h.assets.url}).ParseFS(h.templateFS, templateFiles...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to render template")
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return nil, errs.Wrap(err, "unable to execute template")
	}
	return &buf, nil
}

// localizedEmailTemplate answers the name of the email template copy to render
// for a recipient reading locale, or templateName itself when the English base
// template is the right body. It is consulted only when no copy named for
// exactly the locale exists, which the caller's own lookup settles.
//
// The choice mirrors how the catalog matcher resolves the subject
// (core/i18n localizerFor): the languages a copy of this email exists in are
// the available languages, English first because the base file renders it, and
// the locale is matched followed by English, the fallback the stored-locale
// senders attach beside it. A base-language copy serves a regional variant of
// that language. Without the fallback the matcher answers a guess in another
// language or script (an sr copy for ru, zh for zh-TW, a stray note.bak.html,
// Bashkir, for ru) where the subject's English fallback wins; with it, a locale
// no copy shares a language with resolves to English - the base file. The
// returned name always maps back to a file the directory actually holds, via
// the index the matcher answers rather than the tag it prints, because a
// matched tag can come back region-extended (es-MX matched against es answers
// "es-u-rg-mxzzzz") (#531).
func localizedEmailTemplate(templateFS fs.FS, templateName, locale string) string {
	ext := filepath.Ext(templateName)
	base := strings.TrimSuffix(templateName, ext)
	fileName := filepath.Base(templateName)
	stem := strings.TrimSuffix(fileName, ext)

	// suffixes[i] is the filename piece between the stem and the extension of
	// the copy whose language tag is tags[i]; the empty suffix at index 0 is
	// the English base file, the matcher's no-match answer.
	suffixes := []string{""}
	tags := []language.Tag{language.English}

	entries, err := fs.ReadDir(templateFS, filepath.Dir(templateName))
	if err != nil {
		return templateName
	}
	seen := map[language.Tag]bool{language.English: true}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == fileName || !strings.HasPrefix(name, stem+".") || !strings.HasSuffix(name, ext) {
			continue
		}
		suffix := strings.TrimSuffix(strings.TrimPrefix(name, stem+"."), ext)
		tag, parseErr := language.Parse(suffix)
		// A suffix that is not a well-formed language tag, or a second copy of
		// a language already listed, is not a choice this email offers.
		if parseErr != nil || seen[tag] {
			continue
		}
		seen[tag] = true
		suffixes = append(suffixes, suffix)
		tags = append(tags, tag)
	}

	// The catalog side parses the same string with ParseAcceptLanguage, so a
	// locale it would reject leaves the base template here too.
	parsed, _, err := language.ParseAcceptLanguage(locale)
	if err != nil || len(parsed) == 0 {
		return templateName
	}
	_, idx, _ := language.NewMatcher(tags).Match(append(parsed, language.English)...)
	if suffixes[idx] == "" {
		return templateName
	}
	return base + "." + suffixes[idx] + ext
}

// emailCopyLang answers the language the chosen copy of an email is written in:
// English for the base file, and for a copy <name>.<tag>.html its own tag,
// written as BCP 47 spells it, so an operator's .es copy is es and the .pt-BR
// copy pt-BR. A suffix that does not parse is written as it stands, being
// the only name the copy has for its language.
func emailCopyLang(requested, chosen string) string {
	if chosen == requested {
		return "en"
	}
	ext := filepath.Ext(requested)
	suffix := strings.TrimSuffix(strings.TrimPrefix(chosen, strings.TrimSuffix(requested, ext)+"."), ext)
	if tag, err := language.Parse(suffix); err == nil {
		return tag.String()
	}
	return suffix
}

func (h *Renderer) JSONError(w http.ResponseWriter, r *http.Request, err error) {
	// RFC 6749 Section 5.2: Error responses must use application/json
	w.Header().Set("Content-Type", "application/json")

	// RFC 6749 Section 5.1: Cache-Control and Pragma headers MUST be included
	// in any response containing tokens, credentials, or other sensitive information.
	// Error responses may contain sensitive information about client state.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	requestId := requestid.FromContext(r.Context())

	var errorStr, errorDescriptionStr string

	// errors.As rather than a bare assertion, so an *ErrorDetail still decides the status after
	// anything on the way up has wrapped it. The assertion this replaces was correct only while the
	// unwritten rule "never wrap a wire error" held, and a wrap turned a validator's 400 into a 500
	// with the sentence in the log instead of on the wire (#279 decision 6).
	var errorDetail *oauth.ErrorDetail
	if errors.As(err, &errorDetail) {
		// error detail
		statusCode := errorDetail.HTTPStatus()
		if statusCode == 0 {
			statusCode = http.StatusInternalServerError
		}

		// RFC 6749 Section 5.2: If the client attempted to authenticate via the
		// "Authorization" request header field, the authorization server MUST
		// respond with HTTP 401 and include the "WWW-Authenticate" response header.
		wwwAuthenticate := errorDetail.WWWAuthenticate()
		if wwwAuthenticate != "" {
			w.Header().Set("WWW-Authenticate", wwwAuthenticate)
		}

		w.WriteHeader(statusCode)
		errorStr = errorDetail.Code()
		errorDescriptionStr = errorDetail.Description()
		// A detail answered 500 is a server fault whichever branch of this writer produced it, and
		// whether its status was chosen or defaulted from none above. It therefore owes the same
		// single record and the same request id as the generic branch below, or it is a 500 nobody
		// can find a log line for. A chosen 4xx stays silent, because that is the whole of answering
		// a client's mistake as a client's mistake. An explicit 500 was silent until #435, because
		// the token endpoint's own wrapper logged it before handing it over; that wrapper is gone and
		// this is the one place a 500 is recorded (#279 decisions 9 and 12, #435).
		if statusCode == http.StatusInternalServerError {
			slog.ErrorContext(r.Context(), "internal server error", "error", errs.WithStack(err))
			errorDescriptionStr = fmt.Sprintf("%s Request Id: %v", errorDescriptionStr, requestId)
		}
	} else {
		// any other error
		w.WriteHeader(http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "internal server error", "error", errs.WithStack(err))
		errorStr = "server_error"
		errorDescriptionStr = fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId)
	}

	// Every caller of this writer is a protocol endpoint (token, userinfo, JWKS, discovery), and RFC
	// 6749 Appendix A.8 confines error_description to NQSCHAR there. Both branches interpolate text
	// somebody else chose: a validator's description carries request text, and the request id is
	// requestid.Middleware adopting an inbound X-Request-Id verbatim, so a request carrying
	// `X-Request-Id: a"b` would put 0x22 on the wire with no validator involved. One call, on the
	// final description after the id is appended, so no branch reaches the wire unfiltered (#213,
	// #435).
	values := map[string]string{
		"error":             errorStr,
		"error_description": oauth.ConformErrorDescription(errorDescriptionStr),
	}
	err = json.NewEncoder(w).Encode(values)
	if err != nil {
		h.InternalServerError(w, r, err)
	}
}

func (h *Renderer) EncodeJSON(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		h.JSONError(w, r, err)
	}
}

// The two functions below are package functions rather than renderer methods because they render
// nothing, and because two callers in different packages must read a parameter the same way. They
// were also delegate methods on Renderer until #435, which only let tests stub a request's
// parameters instead of building a request that carries them.
//
// The CSRF middleware and the logout handler are those callers (#109). The middleware decides
// whether to exempt POST /auth/logout on whether an id_token_hint is PRESENT, and the logout
// handler then classifies the very same parameter. Those two readings have to be the same
// reading: middleware saying "present" where the handler says "absent" exempts a cross-site POST
// and then routes it down the hintless branch, which tears the whole session down with no
// consent. A second implementation beside this one is how that drift arrives, so there is one
// implementation and both halves call it.

// QueryOrFormValue returns the value of key from the URL query, falling back to the
// form body. It cannot distinguish an absent parameter from one supplied empty: both are "".
func QueryOrFormValue(r *http.Request, key string) string {
	value := r.URL.Query().Get(key)
	if len(value) == 0 {
		value = r.FormValue(key)
	}
	return value
}

// LookupQueryOrFormValue reports the value of key and whether the parameter was
// supplied at all. QueryOrFormValue cannot express that difference: it returns
// "" both for a parameter that was absent and for one supplied empty.
//
// RP-initiated logout needs the distinction, because the OP echoes the RP's "state" back
// on the post-logout redirect and the two cases have different answers: an RP that sent
// "state=" must get "state=" back, and one that sent nothing must get no state parameter
// at all. Collapsing them either invents a parameter the RP never sent or drops one it
// did (#109).
//
// The value comes from QueryOrFormValue rather than being re-derived, so the
// query-beats-body precedence cannot drift between the two helpers. Presence is only
// consulted when that value is empty, and r.PostForm is populated by then: an empty
// query value is exactly the case where the legacy helper falls through to r.FormValue,
// which parses the body.
func LookupQueryOrFormValue(r *http.Request, key string) (string, bool) {
	value := QueryOrFormValue(r, key)
	if len(value) > 0 {
		return value, true
	}
	if _, ok := r.URL.Query()[key]; ok {
		return "", true
	}
	if _, ok := r.PostForm[key]; ok {
		return "", true
	}
	return "", false
}
