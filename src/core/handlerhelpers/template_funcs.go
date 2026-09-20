package handlerhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/stringutil"
)

// jsBootstrapKeys is the catalog-key list emitted by the JSBootstrap helper.
// Keep in sync with the admin console's utils.js / image-upload.js, which are
// the only consumers: every key consumed by t() or tFormat() in those files
// must appear here, and every key listed here must have a corresponding entry
// in active.en.toml. The auth server serves neither file and no longer calls
// JSBootstrap from its layouts, its one client-side helper being
// showModalDialog, which takes strings the server has already localized (#360).
var jsBootstrapKeys = []string{
	"js.error.session_expired_title",
	"js.error.session_expired_body",
	"js.error.server_error_title",
	"js.error.error_title",
	"js.error.unexpected",
	"js.image_upload.invalid_format",
	"js.image_upload.file_too_large",
	"js.image_upload.uploading",
	"js.image_upload.upload_url_missing",
	"js.image_upload.upload_failed",
	"js.image_upload.updated_successfully",
	"js.image_upload.confirm_delete",
	"js.image_upload.deleting",
	"js.image_upload.delete_url_missing",
	"js.image_upload.delete_failed",
	"js.image_upload.deleted_successfully",
	"js.image_upload.upload_button",
	"js.image_upload.delete_button",
	"js.image_upload.error_prefix",
}

// addUrlParam is the template function that appends one query parameter to a URL. It is the one
// closure of templateFuncMap lifted to a name, because html/template calls a function with no
// context and its record therefore carries no request_id: testutil's slogPlainSites lists it by
// this name as the reason a plain slog call stands in a request-path package (#320).
func addUrlParam(u string, k string, v interface{}) string {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		slog.Warn("unable to parse url", "url", u)
		return u
	}
	query := parsedUrl.Query()

	query.Add(k, stringutil.ConvertToString(v))
	parsedUrl.RawQuery = query.Encode()
	return parsedUrl.String()
}

// instantOf normalizes whatever a template binds into the pointer the i18n
// formatters take. The console's responses carry both shapes on purpose — a
// nullable column reaches the wire as *time.Time and a NOT NULL one, like an
// audit entry's createdAt, as time.Time — and a template cannot take the
// address of a value, so the adapter belongs at this boundary rather than in
// the formatter's signature. Anything else answers nil and therefore renders
// blank, which is what deref below does for a *bool (#373).
func instantOf(v any) *time.Time {
	switch t := v.(type) {
	case *time.Time:
		return t
	case time.Time:
		return &t
	default:
		return nil
	}
}

var templateFuncMap = template.FuncMap{
	// T translates key against the localizer carried on ctx. ctx is the
	// request context, injected into bind maps by RenderTemplateToBuffer
	// (see http_helper.go), so templates write {{ T $.ctx "auth.pwd.title" }}.
	//
	// Variadic kv pairs build a map[string]any for parameterized messages:
	//   {{ T $.ctx "validator.address.locality_too_long" "max" 60 }}
	// Each odd-indexed value is a key (must be a string); the next value is
	// the substitution. Pairs are dropped silently if mistyped.
	"T": func(ctx context.Context, key string, kv ...any) string {
		if len(kv) == 0 {
			return i18n.T(ctx, key)
		}
		args := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				continue
			}
			args[k] = kv[i+1]
		}
		return i18n.T(ctx, key, args)
	},
	// Lang resolves the active locale's BCP 47 tag for the <html lang="...">
	// attribute, so the document advertises the language it actually renders
	// in (screen readers, hyphenation, translation tools). Falls back to "en".
	"Lang": func(ctx context.Context) string { return i18n.LocaleTag(ctx) },

	// DateTime renders an instant as an absolute date and time in the active
	// locale's numeric layout, which lives in the catalog because Go's
	// time.Format has no locale of its own. Takes a *time.Time or a time.Time
	// through instantOf and renders "" for a nil or absent one, so a template
	// can bind a nullable column straight into a cell (#373).
	"DateTime": func(ctx context.Context, v any) string {
		return i18n.FormatDateTime(ctx, instantOf(v))
	},
	// Since renders how long ago an instant was, as one translated phrase
	// rather than a Go duration with a translated suffix after it. It supplies
	// the clock, so a template reads {{ Since $.ctx .Started }} (#373).
	"Since": func(ctx context.Context, v any) string {
		return i18n.FormatSince(ctx, instantOf(v), time.Now().UTC())
	},

	// RefCountry / RefPhoneCountry / RefTimezone resolve a country code,
	// phone country, or IANA zone to its localized label. Country names come
	// from CLDR (golang.org/x/text/display) for the active locale. The
	// trailing fallback (the existing English struct field or pre-assembled
	// label) is rendered when the code or locale tag is unparseable or CLDR
	// has no name.
	"RefCountry": func(ctx context.Context, alpha2, fallback string) string {
		return i18n.RefCountry(ctx, alpha2, fallback)
	},
	// RefPhoneCountry rebuilds the "<emoji> - <country> (<code>)" label with
	// the country name localized; emoji and calling code pass through.
	"RefPhoneCountry": func(ctx context.Context, emoji, alpha2, callingCode, fallback string) string {
		return i18n.RefPhoneCountry(ctx, emoji, alpha2, callingCode, fallback)
	},
	// LocaleLabel renders a locale-picker option as "<native> (<english>)"
	// (e.g. "português (Brasil) (Portuguese (Brazil))"), so users recognize
	// their language regardless of the UI's current language. The label is
	// viewer-independent, so it takes no context.
	"LocaleLabel": func(id, englishName string) string {
		return i18n.LocaleLabel(id, englishName)
	},
	// RefTimezone takes the zone identifier plus the country code and
	// English country name from the timezones table. The country portion
	// of the assembled label gets localized via CLDR; the IANA zone ID
	// and comments stay in English.
	"RefTimezone": func(ctx context.Context, zoneID, countryCode, countryName, comments string) string {
		return i18n.RefTimezone(ctx, zoneID, countryCode, countryName, comments)
	},

	// JSBootstrap renders a <script> block that populates window.i18n with
	// the strings client-side JS needs (session-expired modal, image-upload
	// status messages, etc.). The admin console's two layouts call it once
	// after loading utils.js, whose t() / tFormat() helpers read window.i18n
	// at runtime; they are the only callers, and a layout that emits the block
	// without serving a reader ships a table nothing consumes (#360).
	//
	// The set of bootstrap keys is fixed and small. Adding a new client-side
	// string means: (1) add a "js.*" key to active.en.toml, (2) extend the
	// jsBootstrapKeys list below, (3) consume via t()/tFormat() in JS.
	//
	//
	// Uses i18n.Raw (not T): several keys carry {{param}} placeholders that
	// tFormat() substitutes client-side. T() would try to execute them as
	// text/templates, fail on the unknown "param", and leak the key. Raw
	// returns the un-templated string so the placeholders reach the browser.
	"JSBootstrap": func(ctx context.Context) template.HTML {
		m := make(map[string]string, len(jsBootstrapKeys))
		for _, k := range jsBootstrapKeys {
			m[k] = i18n.Raw(ctx, k)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		// SetEscapeHTML is the default but be explicit: it escapes "<", ">",
		// "&" to their \uXXXX forms, which makes the JSON safe to embed in a
		// <script> tag (a literal "</script>" inside a value would otherwise
		// terminate the script).
		enc.SetEscapeHTML(true)
		if err := enc.Encode(m); err != nil {
			slog.ErrorContext(ctx, "unable to encode the js i18n bootstrap", "error", err)
			return template.HTML("<script>window.i18n={};</script>")
		}
		// enc.Encode appends a trailing newline; trim it.
		out := strings.TrimSpace(buf.String())
		return template.HTML("<script>window.i18n=" + out + ";</script>")
	},

	// https://dev.to/moniquelive/passing-multiple-arguments-to-golang-templates-16h8
	"args": func(els ...any) []any {
		return els
	},
	// deref dereferences a pointer to a bool. Returns false if nil.
	"deref": func(b *bool) bool {
		if b == nil {
			return false
		}
		return *b
	},
	"isLast": func(index int, len int) bool {
		return index == len-1
	},
	"add": func(a int, b int) int {
		return a + b
	},
	"concat": func(parts ...string) string {
		return strings.Join(parts, "")
	},
	"addUrlParam": addUrlParam,
	"marshal": func(v interface{}) template.JS {
		a, _ := json.Marshal(v)
		return template.JS(a)
	},
	"versionComment": func() template.HTML {
		return template.HTML("<!-- version: " + constants.Version + "; build date: " + constants.BuildDate + "; git commit: " + constants.GitCommit + "-->")
	},
	"isAdminClientPage": func(urlPath string) bool {
		if urlPath == "/admin/clients" {
			return true
		}

		if strings.HasPrefix(urlPath, "/admin/clients/") {
			if strings.HasSuffix(urlPath, "/settings") ||
				strings.HasSuffix(urlPath, "/tokens") ||
				strings.HasSuffix(urlPath, "/authentication") ||
				strings.HasSuffix(urlPath, "/oauth2-flows") ||
				strings.HasSuffix(urlPath, "/redirect-uris") ||
				strings.HasSuffix(urlPath, "/web-origins") ||
				strings.HasSuffix(urlPath, "/user-sessions") ||
				strings.HasSuffix(urlPath, "/permissions") ||
				strings.HasSuffix(urlPath, "/delete") ||
				strings.HasSuffix(urlPath, "/new") {
				return true
			}
		}
		return false
	},
	"isAdminResourcePage": func(urlPath string) bool {
		if urlPath == "/admin/resources" {
			return true
		}

		if strings.HasPrefix(urlPath, "/admin/resources/") {
			if strings.HasSuffix(urlPath, "/settings") ||
				strings.HasSuffix(urlPath, "/permissions") ||
				strings.Contains(urlPath, "/users-with-permission") ||
				strings.Contains(urlPath, "/groups-with-permission") ||
				strings.HasSuffix(urlPath, "/delete") ||
				strings.HasSuffix(urlPath, "/new") {
				return true
			}
		}
		return false
	},
	"isAdminGroupPage": func(urlPath string) bool {
		if urlPath == "/admin/groups" {
			return true
		}

		if strings.HasPrefix(urlPath, "/admin/groups/") {
			if strings.HasSuffix(urlPath, "/settings") ||
				strings.HasSuffix(urlPath, "/attributes") ||
				strings.HasSuffix(urlPath, "/attributes/add") ||
				strings.HasSuffix(urlPath, "/permissions") ||
				strings.Contains(urlPath, "/members") ||
				strings.HasSuffix(urlPath, "/members/add") ||
				strings.HasSuffix(urlPath, "/new") ||
				strings.HasSuffix(urlPath, "/delete") {
				return true
			}
		}
		return false
	},
	"isAdminUserPage": func(urlPath string) bool {
		if urlPath == "/admin/users" {
			return true
		}

		if strings.HasPrefix(urlPath, "/admin/users/") {
			if strings.HasSuffix(urlPath, "/details") ||
				strings.HasSuffix(urlPath, "/profile") ||
				strings.HasSuffix(urlPath, "/email") ||
				strings.HasSuffix(urlPath, "/phone") ||
				strings.HasSuffix(urlPath, "/address") ||
				strings.HasSuffix(urlPath, "/authentication") ||
				strings.HasSuffix(urlPath, "/consents") ||
				strings.HasSuffix(urlPath, "/sessions") ||
				strings.HasSuffix(urlPath, "/attributes") ||
				strings.HasSuffix(urlPath, "/permissions") ||
				strings.HasSuffix(urlPath, "/groups") ||
				strings.HasSuffix(urlPath, "/new") ||
				strings.HasSuffix(urlPath, "/delete") {
				return true
			}
		}
		return false
	},
	"isAdminSettingsEmailPage": func(urlPath string) bool {
		if urlPath == "/admin/settings" {
			return true
		}

		if strings.HasPrefix(urlPath, "/admin/settings/") {
			if strings.HasSuffix(urlPath, "/email") ||
				strings.HasSuffix(urlPath, "/email/send-test-email") {
				return true
			}
		}
		return false
	},
}
