package handlerhelpers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/stringutil"
)

var templateFuncMap = template.FuncMap{
	// https://dev.to/moniquelive/passing-multiple-arguments-to-golang-templates-16h8
	"args": func(els ...any) []any {
		return els
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
	"string": func(v interface{}) string {
		return fmt.Sprintf("%v", v)
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
