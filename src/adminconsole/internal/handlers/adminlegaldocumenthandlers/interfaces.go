package adminlegaldocumenthandlers

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

// publicSettingsCache is the console's cache of the auth server's public settings, which carry the
// legal documents in effect for all apps that My Account's footer links (#622). A change that can
// alter that list, a publish, a retire, a restore or a change of apps, empties it, so the footer
// shows the change at once rather than when the cached value expires.
type publicSettingsCache interface {
	Invalidate()
}
