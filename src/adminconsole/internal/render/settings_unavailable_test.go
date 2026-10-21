package render

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

// A page that cannot render still answers: the same sentences in plain text, at 500.
func TestSettingsUnavailable_AFailedRenderAnswersInPlainText(t *testing.T) {
	broken := New(fstest.MapFS{
		"settings_unavailable.html": {Data: []byte(`{{ template "never_defined" . }}`)},
	}, fstest.MapFS{"main.css": {Data: []byte("body{}")}})

	w := httptest.NewRecorder()
	broken.SettingsUnavailable(w, httptest.NewRequest(http.MethodGet, "/", nil),
		"adminconsole.error.issuer_missing_title", "adminconsole.error.issuer_missing")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, w.Body.String(), "The auth server is out of date. The auth server didn't report an issuer.")
}
