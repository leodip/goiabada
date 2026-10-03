package middleware

import (
	"net/http"

	"github.com/leodip/goiabada/core/i18n"
)

// stubErrorRenderer stands in for *render.Renderer, whose real
// InternalServerError needs a template FS this package has no business carrying.
// It answers the way the real one does on a failed render: 500 with a body, so a
// test that only asserts the status still means what it did before the middleware
// started rendering a page. Stateless on purpose, so one value is safe to share
// across every construction in this package; a test that needs to see the error
// itself declares a recording renderer of its own.
type stubErrorRenderer struct{}

func (stubErrorRenderer) InternalServerError(w http.ResponseWriter, r *http.Request, _ error) {
	http.Error(w, i18n.T(r.Context(), "error.body"), http.StatusInternalServerError)
}
