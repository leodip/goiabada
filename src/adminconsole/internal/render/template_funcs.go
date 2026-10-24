package render

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/buildinfo"
	"github.com/leodip/goiabada/core/i18n"
)

// This file is one of two. The auth server's copy declares the four entries its templates call --
// T, Lang, args and versionComment -- and the twenty-one below include those four. The one map
// both binaries parsed with lived in core until #385, so every page this server renders parsed
// eighteen functions it could not reach, five of them predicates over this console's own URL
// paths (#385).

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
	"js.error.unexpected_text",
	"js.image_upload.invalid_format",
	"js.image_upload.file_too_large",
	"js.image_upload.uploading",
	"js.image_upload.upload_failed",
	"js.image_upload.delete_failed",
	"js.image_upload.unreadable",
	"js.combobox.no_matches",
	"js.combobox.one_result",
	"js.combobox.results",
}

// addUrlParam is the template function that appends one query parameter to a URL. It is one of two
// closures of templateFuncMap lifted to a name, because html/template calls a function with no
// context and its record therefore carries no request_id: core/guard's slogPlainSites lists it by
// this name as the reason a plain slog call stands in a request-path package (#320).
//
// convertToString below is the other, and it is why the pair is here rather than in core. It was
// core/stringutil.ConvertToString, exported for this one caller and writing its plain record
// lawfully only because core/stringutil sat outside the request-path scope of the day. Moving it
// in with its caller cost it a slogPlainSites row and retired that exemption by directory (#385).
func addUrlParam(u string, k string, v interface{}) string {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		slog.Warn("unable to parse url", "url", u)
		return u
	}
	query := parsedUrl.Query()

	query.Add(k, convertToString(v))
	parsedUrl.RawQuery = query.Encode()
	return parsedUrl.String()
}

// convertToString renders a template's bind value as the string a query parameter carries. Only
// addUrlParam calls it, which is why it is unexported and why it lives beside it: it was
// core/stringutil.ConvertToString, and core published it for this one caller (#385).
func convertToString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		// The type rather than val, which is what this record has always claimed to carry and
		// never did: "type" held the value itself, so an unconvertible value of an unknown
		// type was written into the log under a key naming what it is not (#320 decision 3).
		slog.Warn("unable to convert a value to a string, the type is not supported",
			"type", fmt.Sprintf("%T", v))
		return ""
	}
}

// instantOf normalizes whatever a template binds into the pointer the
// formatters in timefmt.go take. The console's responses carry both shapes on purpose — a
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
	// request context, injected into bind maps by renderToBuffer
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
	// Lang is the tag of the catalog the page rendered from, for the <html lang="..."> attribute,
	// so the document advertises the language it is written in (screen readers, hyphenation,
	// translation tools): a browser asking for de-DE, with no German catalog, reads an English page
	// marked en, not de-DE (WCAG 2.2 SC 3.1.1, #645 decision 8).
	"Lang": i18n.CatalogTag,
	// CatalogLang is the same tag, kept under its own name because operators' templates and the
	// page scripts of #559 name it: the layouts publish it as data-catalog-lang, and every request a
	// page script sends names it back as ui_locales, so a refusal in that page's dialog is in the
	// page's language whatever the browser or the profile says (#559 decisions 3 and 7).
	"CatalogLang": i18n.CatalogTag,

	// DateTime renders an instant as an absolute date and time in the active
	// locale's numeric layout, which lives in the catalog because Go's
	// time.Format has no locale of its own. Takes a *time.Time or a time.Time
	// through instantOf and renders "" for a nil or absent one, so a template
	// can bind a nullable column straight into a cell (#373).
	"DateTime": func(ctx context.Context, v any) string {
		return formatDateTime(ctx, instantOf(v))
	},
	// Since renders how long ago an instant was, as one translated phrase
	// rather than a Go duration with a translated suffix after it. It supplies
	// the clock, so a template reads {{ Since $.ctx .Started }} (#373).
	"Since": func(ctx context.Context, v any) string {
		return formatSince(ctx, instantOf(v), time.Now().UTC())
	},

	// RefCountry / RefPhoneCountry / RefTimezone resolve a country code,
	// phone country, or IANA zone to its localized label. Country names come
	// from CLDR (golang.org/x/text/language/display) for the active locale. The
	// trailing fallback (the existing English struct field or pre-assembled
	// label) is rendered when the code or locale tag is unparseable or CLDR
	// has no name.
	"RefCountry": refCountry,
	// RefPhoneCountry rebuilds the "<emoji> - <country> (<code>)" label with
	// the country name localized; emoji and calling code pass through.
	"RefPhoneCountry": refPhoneCountry,
	// LocaleLabel renders a locale-picker option as "<native> (<english>)"
	// (e.g. "português (Brasil) (Portuguese (Brazil))"), so users recognize
	// their language regardless of the UI's current language. The label is
	// viewer-independent, so it takes no context.
	"LocaleLabel": localeLabel,
	// RefTimezone takes the zone identifier plus the country code and
	// English country name from the timezones table. The country portion
	// of the assembled label gets localized via CLDR; the IANA zone ID
	// and comments stay in English.
	"RefTimezone": refTimezone,

	// JSBootstrap returns the strings client-side JS needs (session-expired modal,
	// image-upload status messages, etc.), keyed by catalog key, for the
	// window.i18n script element. The admin console's two layouts write that
	// element themselves, once, after loading utils.js, whose t() / tFormat()
	// helpers read window.i18n at runtime; they are the only callers, and a
	// layout that emits the block without serving a reader ships a table nothing
	// consumes (#360).
	//
	// It returns the map as a plain value rather than the encoded element, so the
	// template engine escapes it for the script it lands in: as JSON with every
	// <, > and & escaped, so no catalog value, an operator's override included,
	// can close the script. It returned the whole element typed as already safe
	// until #120, which the engine copied out unescaped wherever it was called.
	//
	// The set of bootstrap keys is fixed and small. Adding a new client-side
	// string means: (1) add a "js.*" key to active.en.toml, (2) extend the
	// jsBootstrapKeys list below, (3) consume via t()/tFormat() in JS.
	//
	// Uses i18n.Raw (not T): several keys carry {{param}} placeholders that
	// tFormat() substitutes client-side. T() would try to execute them as
	// text/templates, fail on the unknown "param", and leak the key. Raw
	// returns the un-templated string so the placeholders reach the browser.
	"JSBootstrap": func(ctx context.Context) map[string]string {
		m := make(map[string]string, len(jsBootstrapKeys))
		for _, k := range jsBootstrapKeys {
			m[k] = i18n.Raw(ctx, k)
		}
		return m
	},

	// ScopeList words each scope of a consent as the consent screen does (scopeList).
	"ScopeList": scopeList,

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
	"isLast": func(index int, length int) bool {
		return index == length-1
	},
	"add": func(a int, b int) int {
		return a + b
	},
	"concat": func(parts ...string) string {
		return strings.Join(parts, "")
	},
	"addUrlParam": addUrlParam,
	"versionComment": func() template.HTML {
		//nolint:gosec // G203: build-time constants stamped by the linker, never request input
		return template.HTML("<!-- version: " + buildinfo.Version + "; build date: " + buildinfo.BuildDate + "; git commit: " + buildinfo.GitCommit + "-->")
	},
	"isAdminClientPage": func(urlPath string) bool {
		return inSection(urlPath, "/admin/clients")
	},
	"isAdminResourcePage": func(urlPath string) bool {
		return inSection(urlPath, "/admin/resources")
	},
	"isAdminGroupPage": func(urlPath string) bool {
		return inSection(urlPath, "/admin/groups")
	},
	"isAdminUserPage": func(urlPath string) bool {
		return inSection(urlPath, "/admin/users")
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

// inSection reports whether urlPath is the list at base or any page under it, so the sidebar marks
// its section current on every page of one record, a tab added later included.
func inSection(urlPath, base string) bool {
	return urlPath == base || strings.HasPrefix(urlPath, base+"/")
}
