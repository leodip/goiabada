package handlerhelpers

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

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/oauth"
)

// This renderer is one of two. The auth server has its own copy in
// authserver/internal/handlerhelpers, and about 210 of the lines below are the same in both.
//
// The duplication is deliberate and is what owning a renderer costs. The single copy this
// replaced lived in core and hid two things only one binary ever reached: the loggedInUser and
// isAdmin page data, which the auth server never binds, and a template FuncMap of which this
// application calls all twenty-two entries where the auth server calls four. Passing either in as
// a parameter would have left one shared package behaving differently for its two callers, which
// is the shape #385
// exists to remove. Drift between the two copies is the accepted price; a change worth making in
// one is worth reading the other for (#385).

type HttpHelper struct {
	templateFS fs.FS
}

func NewHttpHelper(templateFS fs.FS) *HttpHelper {
	return &HttpHelper{templateFS: templateFS}
}

// InternalServerError logs err once, with a stack and the request id the page shows, and renders
// the 500 page.
//
// errs.WithStack is applied here rather than at the 876 call sites, which is what lets every one of
// them pass err bare: it is the identity on anything this tree constructed, so the only value it
// changes is a bare error from the standard library or a dependency, which would otherwise log with
// no frames at all. The attributes are structured, and the stack rides inside the error attribute
// because slog's default handler formats an error value with %+v (#279 decisions 9 and 10).
func (h *HttpHelper) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	requestId := middleware.GetReqID(r.Context())
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
		// variable, and it is client-chosen: chi's RequestID adopts an inbound X-Request-Id
		// verbatim, so it is escaped and clipped before it is echoed (#159, #414, #425).
		slog.ErrorContext(r.Context(), "unable to render the error page", "error", err)
		http.Error(w, i18n.T(r.Context(), "adminconsole.error.body")+" "+
			i18n.T(r.Context(), "adminconsole.error.request_id_label")+" "+logging.FieldForLog(requestId),
			http.StatusInternalServerError)
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
func (h *HttpHelper) NotFound(w http.ResponseWriter, r *http.Request) {
	err := h.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/not_found.html", map[string]interface{}{
		"_httpStatus": http.StatusNotFound,
	})
	if err != nil {
		h.InternalServerError(w, r, err)
	}
}

func (h *HttpHelper) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	buf, err := h.renderToBuffer(r, layoutName, templateName, data)
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
	// The position matters as much as the values. It is after renderToBuffer has returned
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

// renderToBuffer renders a page without touching the response, which is what lets RenderTemplate
// leave a failed render's response untouched. It is unexported because a page is the only thing
// this binary renders: the auth server's twin exports its own for email bodies, and the console
// sends no email (#440).
func (h *HttpHelper) renderToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {

	// Every application route is mounted under the settings-cache middleware, so a render without
	// settings is a wiring defect. It is refused rather than rendered under an invented blank app
	// name and theme, and when the refused page is the error page itself, InternalServerError ends
	// in its plain-text last resort (#440 decision 3).
	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return nil, reqctx.ErrNoSettings
	}
	// The layout's values are written into the caller's map rather than a copy, and
	// TestRenderTemplate_Binds reads isAdmin back out of it; a nil map is therefore allocated
	// here rather than panicking on the first write below. No caller passes nil today, so this
	// closes a latent panic, and the auth server's twin carries the same guard (#435).
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
	// application's one injection point; the auth server's renderer has its
	// own, and the two are deliberately separate (#385).
	data["ctx"] = r.Context()

	if jwtInfo, ok := reqctx.JwtInfoFrom(r.Context()); ok {
		if jwtInfo.IdToken != nil && jwtInfo.IdToken.Claims["sub"] != nil {
			// Extract user info from ID token claims instead of database lookup
			// The ID token contains: sub, name, email, email_verified, etc.
			claims := jwtInfo.IdToken.Claims
			loggedInUser := make(map[string]interface{})

			// Map claims to match User model field names (capitalized for template access)
			if sub, ok := claims["sub"].(string); ok {
				loggedInUser["Subject"] = sub
			}
			if email, ok := claims["email"].(string); ok {
				loggedInUser["Email"] = email
			}
			if emailVerified, ok := claims["email_verified"].(bool); ok {
				loggedInUser["EmailVerified"] = emailVerified
			}
			if givenName, ok := claims["given_name"].(string); ok {
				loggedInUser["GivenName"] = givenName
			}
			if middleName, ok := claims["middle_name"].(string); ok {
				loggedInUser["MiddleName"] = middleName
			}
			if familyName, ok := claims["family_name"].(string); ok {
				loggedInUser["FamilyName"] = familyName
			}
			if username, ok := claims["name"].(string); ok {
				loggedInUser["Username"] = username
			}

			// The menu label, joined by the rule UserFullName applies to a user response, an absent
			// claim reading as empty. An empty name has no email fallback here: the template shows the
			// email on its own line (#440).
			givenName, _ := claims["given_name"].(string)
			middleName, _ := claims["middle_name"].(string)
			familyName, _ := claims["family_name"].(string)
			loggedInUser["GetFullName"] = fullName(givenName, middleName, familyName)

			data["loggedInUser"] = loggedInUser
		}
		// The grant the token response records, not the access token, which the console carries
		// without decoding (#427).
		if jwtInfo.HasScope(builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier) {
			data["isAdmin"] = true
		}
	}

	name := filepath.Base(layoutName)

	templateName = strings.TrimPrefix(templateName, "/")
	layoutName = strings.TrimPrefix(layoutName, "/")

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

	templ, err := template.New(name).Funcs(templateFuncMap).ParseFS(h.templateFS, templateFiles...)
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

func (h *HttpHelper) JsonError(w http.ResponseWriter, r *http.Request, err error) {
	// RFC 6749 Section 5.2: Error responses must use application/json
	w.Header().Set("Content-Type", "application/json")

	// RFC 6749 Section 5.1: Cache-Control and Pragma headers MUST be included
	// in any response containing tokens, credentials, or other sensitive information.
	// Error responses may contain sensitive information about client state.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	requestId := middleware.GetReqID(r.Context())

	errorStr := ""
	errorDescriptionStr := ""

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

		w.WriteHeader(statusCode)
		errorStr = errorDetail.Code()
		errorDescriptionStr = errorDetail.Description()
		// A detail answered 500 is a server fault whichever branch of this writer produced it, and
		// whether its status was chosen or defaulted from none above. It therefore owes the same
		// single record and the same request id as the generic branch below, or it is a 500 nobody
		// can find a log line for. A chosen 4xx stays silent, because that is the whole of answering
		// a client's mistake as a client's mistake. An explicit 500 was silent on the strength of the
		// auth server's token endpoint logging it first, a builder this binary has not reached since
		// #385 and which #435 deleted; the auth server's twin records it here too (#279 decisions 9
		// and 12, #435).
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

	values := map[string]string{
		"error":             errorStr,
		"error_description": errorDescriptionStr,
	}
	err = json.NewEncoder(w).Encode(values)
	if err != nil {
		h.InternalServerError(w, r, err)
	}
}

func (h *HttpHelper) EncodeJson(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		h.JsonError(w, r, err)
	}
}
