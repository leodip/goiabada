package middleware

import (
	"net/http"
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/i18n"
)

func TestMain(m *testing.M) {
	config.Init()
	// The rate limiter renders a localized error page on a 429, so without a loaded
	// bundle i18n.T falls back to echoing the key and the body assertions would pass
	// against the key rather than against the message.
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}

// stubErrorRenderer stands in for *handlerhelpers.HttpHelper, whose real
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
