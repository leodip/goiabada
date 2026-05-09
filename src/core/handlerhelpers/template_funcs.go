package handlerhelpers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/stringutil"
)

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
	// SysName / SysDesc resolve built-in system entity names against the
	// catalog. User-created entities fall back to the DB-stored value.
	"SysName": func(ctx context.Context, kind, identifier, dbFallback string) string {
		return i18n.SystemEntityDisplay(ctx, kind, identifier, dbFallback)
	},
	"SysDesc": func(ctx context.Context, kind, identifier, dbFallback string) string {
		return i18n.SystemEntityDescription(ctx, kind, identifier, dbFallback)
	},
	// DirAttr resolves to "ltr" or "rtl" for the active locale. Returns
	// "ltr" for every currently supported locale; the hook exists so RTL
	// support can be added later without retrofitting templates.
	"DirAttr": func(_ context.Context) string { return "ltr" },

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
	"addUrlParam": func(u string, k string, v interface{}) string {
		parsedUrl, err := url.Parse(u)
		if err != nil {
			slog.Warn(fmt.Sprintf("unable to parse url %v", u))
			return u
		}
		query := parsedUrl.Query()

		query.Add(k, stringutil.ConvertToString(v))
		parsedUrl.RawQuery = query.Encode()
		return parsedUrl.String()
	},
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
