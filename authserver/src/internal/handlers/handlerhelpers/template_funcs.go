package handlerhelpers

import (
	"html/template"

	"github.com/leodip/goiabada/authserver/internal/constants"
)

var templateFuncMap = template.FuncMap{
	// https://dev.to/moniquelive/passing-multiple-arguments-to-golang-templates-16h8
	"args": func(els ...any) []any {
		return els
	},
	"versionComment": func() template.HTML {
		return template.HTML("<!-- version: " + constants.Version + "; build date: " + constants.BuildDate + "; git commit: " + constants.GitCommit + "-->")
	},
}
