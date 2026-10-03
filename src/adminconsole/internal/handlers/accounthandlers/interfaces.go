package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
)

// HttpHelper is the page and JSON writer this package's handlers answer through, declared here
// rather than imported from the parent handlers package, so this package compiles against
// nothing above it (#440). It embeds the three writers the classifiers in handlerhelpers answer
// through and adds the two every handler here calls itself. The renderer the composition root
// builds satisfies it structurally, and so does the generated handlers mock.
type HttpHelper interface {
	handlerhelpers.ErrorWriter
	RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
		data map[string]interface{}) error
	EncodeJson(w http.ResponseWriter, r *http.Request, data interface{})
}
