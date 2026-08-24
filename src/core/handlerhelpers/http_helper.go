package handlerhelpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

type HttpHelper struct {
	templateFS fs.FS
}

func NewHttpHelper(templateFS fs.FS) *HttpHelper {
	return &HttpHelper{
		templateFS: templateFS,
	}
}

func (h *HttpHelper) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	requestId := middleware.GetReqID(r.Context())
	slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, requestId))

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
		http.Error(w, fmt.Sprintf("unable to render the error page: %v", err.Error()), http.StatusInternalServerError)
	}
}

func (h *HttpHelper) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
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
			return errors.WithStack(errors.New("unable to cast _httpStatus to int"))
		}
		w.WriteHeader(httpStatus)
	}

	_, err = buf.WriteTo(w)
	if err != nil {
		return errors.WithStack(errors.New("unable to write to response writer"))
	}
	return nil
}

func (h *HttpHelper) RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
	data["appName"] = settings.AppName
	data["uiTheme"] = settings.UITheme
	data["urlPath"] = r.URL.Path
	data["smtpEnabled"] = settings.SMTPEnabled
	data["goiabadaVersion"] = constants.Version + " (" + constants.BuildDate + ")"
	// Inject the request context so templates can call {{ T $.ctx "..." }}
	// (and SysName/SysDesc/DirAttr). This is the single canonical injection
	// point for both authserver and adminconsole render paths.
	data["ctx"] = r.Context()

	var jwtInfo oauth.JwtInfo
	if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			return nil, errors.WithStack(errors.New("unable to cast jwtInfo to dtos.JwtInfo"))
		}
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

			// Build a GetFullName equivalent as a simple field
			// This mimics what User.GetFullName() does
			// NOTE: We don't use email as fallback here - the template will show email separately
			fullName := ""
			if givenName, ok := loggedInUser["GivenName"].(string); ok && givenName != "" {
				fullName = givenName
			}
			if middleName, ok := loggedInUser["MiddleName"].(string); ok && middleName != "" {
				if fullName != "" {
					fullName += " "
				}
				fullName += middleName
			}
			if familyName, ok := loggedInUser["FamilyName"].(string); ok && familyName != "" {
				if fullName != "" {
					fullName += " "
				}
				fullName += familyName
			}

			// Set GetFullName - will be empty string if no name components exist
			// The template will handle showing just the email in that case
			loggedInUser["GetFullName"] = fullName

			data["loggedInUser"] = loggedInUser
		}
		if jwtInfo.AccessToken != nil &&
			jwtInfo.AccessToken.HasScope(constants.AuthServerResourceIdentifier+":"+constants.ManagePermissionIdentifier) {
			data["isAdmin"] = true
		}
	}

	name := filepath.Base(layoutName)

	templateName = strings.TrimPrefix(templateName, "/")
	layoutName = strings.TrimPrefix(layoutName, "/")

	// Per-locale email template lookup. For emails (templateName under
	// "emails/"), try <name>.<locale>.html before <name>.html so a translated
	// copy of the whole email body wins over the English baseline. Falls
	// through to the base template when no locale-specific copy exists.
	// The default locale "en" is always served by the base file.
	if strings.HasPrefix(templateName, "emails/") {
		locale := i18n.LocaleTag(r.Context())
		if locale != "" && locale != "en" {
			ext := filepath.Ext(templateName)
			base := strings.TrimSuffix(templateName, ext)
			candidate := base + "." + locale + ext
			if _, err := fs.Stat(h.templateFS, candidate); err == nil {
				templateName = candidate
			}
		}
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

	templ, err := template.New(name).Funcs(templateFuncMap).ParseFS(h.templateFS, templateFiles...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to render template")
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute template")
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

	errorDetail, ok := err.(*customerrors.ErrorDetail)
	if ok {
		// error detail
		statusCode := errorDetail.GetHttpStatusCode()
		if statusCode == 0 {
			statusCode = http.StatusInternalServerError
		}

		// RFC 6749 Section 5.2: If the client attempted to authenticate via the
		// "Authorization" request header field, the authorization server MUST
		// respond with HTTP 401 and include the "WWW-Authenticate" response header.
		wwwAuthenticate := errorDetail.GetWWWAuthenticate()
		if wwwAuthenticate != "" {
			w.Header().Set("WWW-Authenticate", wwwAuthenticate)
		}

		w.WriteHeader(statusCode)
		errorStr = errorDetail.GetCode()
		errorDescriptionStr = errorDetail.GetDescription()
	} else {
		// any other error
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, requestId))
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

func (h *HttpHelper) GetFromUrlQueryOrFormPost(r *http.Request, key string) string {
	return GetFromUrlQueryOrFormPost(r, key)
}

func (h *HttpHelper) LookupFromUrlQueryOrFormPost(r *http.Request, key string) (string, bool) {
	return LookupFromUrlQueryOrFormPost(r, key)
}

// The two functions below carry the behaviour and the methods above are delegates, because a
// caller that has no HttpHelper still has to read a parameter exactly as a handler would.
//
// The CSRF middleware is that caller (#109). It decides whether to exempt POST /auth/logout on
// whether an id_token_hint is PRESENT, and the logout handler then classifies the very same
// parameter. Those two readings have to be the same reading: middleware saying "present" where the
// handler says "absent" exempts a cross-site POST and then routes it down the hintless branch,
// which tears the whole session down with no consent. A second implementation beside this one is
// how that drift arrives, so there is one implementation and both halves call it.

// GetFromUrlQueryOrFormPost returns the value of key from the URL query, falling back to the
// form body. It cannot distinguish an absent parameter from one supplied empty: both are "".
func GetFromUrlQueryOrFormPost(r *http.Request, key string) string {
	value := r.URL.Query().Get(key)
	if len(value) == 0 {
		value = r.FormValue(key)
	}
	return value
}

// LookupFromUrlQueryOrFormPost reports the value of key and whether the parameter was
// supplied at all. GetFromUrlQueryOrFormPost cannot express that difference: it returns
// "" both for a parameter that was absent and for one supplied empty.
//
// RP-initiated logout needs the distinction, because the OP echoes the RP's "state" back
// on the post-logout redirect and the two cases have different answers: an RP that sent
// "state=" must get "state=" back, and one that sent nothing must get no state parameter
// at all. Collapsing them either invents a parameter the RP never sent or drops one it
// did (#109).
//
// The value comes from GetFromUrlQueryOrFormPost rather than being re-derived, so the
// query-beats-body precedence cannot drift between the two helpers. Presence is only
// consulted when that value is empty, and r.PostForm is populated by then: an empty
// query value is exactly the case where the legacy helper falls through to r.FormValue,
// which parses the body.
func LookupFromUrlQueryOrFormPost(r *http.Request, key string) (string, bool) {
	value := GetFromUrlQueryOrFormPost(r, key)
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
