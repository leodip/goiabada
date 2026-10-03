package adminsettingshandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
)

// HttpHelper is the page and JSON writer this package's handlers answer through, declared here
// rather than imported from the parent handlers package, so this package compiles against
// nothing above it (#440). It embeds the three writers the classifiers in render answer
// through and adds the two every handler here calls itself. The renderer the composition root
// builds satisfies it structurally, and so does the generated handlers mock.
type HttpHelper interface {
	render.ErrorWriter
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	EncodeJSON(w http.ResponseWriter, r *http.Request, data interface{})
}

// SettingsInvalidator is what a settings save needs of the public settings cache: once the auth
// server has accepted the save, the copy every page renders from is stale, and the next request
// reads it again. A refused save changed nothing and leaves the cache alone (#440).
type SettingsInvalidator interface {
	Invalidate()
}
