package handlers

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
)

// The form_post page cannot change while the server runs, so it is parsed the first time a response
// is posted and kept: each response only executes it (#819 decision 5).

// openCountingFS is a set of templates that counts what is opened.
type openCountingFS struct {
	fs.FS
	opens atomic.Int64
}

func (f *openCountingFS) Open(name string) (fs.File, error) {
	f.opens.Add(1)
	return f.FS.Open(name)
}

func postCode(t *testing.T, formPost formPostTemplate, code string) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
		&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})
	require.NoError(t, issueAuthCode(w, r, formPost,
		&record.Code{Code: code, RedirectURI: "https://example.com/callback", State: "s"}, "form_post"))
	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}

func TestFormPost_ThePagePostedAgainReadsNoTemplate(t *testing.T) {
	templates := &openCountingFS{FS: web.TemplateFS()}
	formPost := newFormPostTemplate(templates, nil)

	first := postCode(t, formPost, "first_code")
	assert.Contains(t, first, `name="code" value="first_code"`)
	read := templates.opens.Load()
	require.Positive(t, read, "the first response reads the page")

	again := postCode(t, formPost, "second_code")
	assert.Contains(t, again, `name="code" value="second_code"`)
	assert.NotContains(t, again, "first_code")
	assert.Equal(t, read, templates.opens.Load(), "a second response reads no template")
}

// The kept page is shared by concurrent responses, the first among them included; the race detector
// runs this under the unit tier.
func TestFormPost_ConcurrentResponsesShareThePage(t *testing.T) {
	formPost := newFormPostTemplate(web.TemplateFS(), nil)

	responses := make([]*httptest.ResponseRecorder, 8)
	failures := make([]error, len(responses))
	var wg sync.WaitGroup
	for i := range responses {
		wg.Go(func() {
			responses[i] = httptest.NewRecorder()
			r := withSettings(httptest.NewRequest(http.MethodGet, "/auth/issue", nil),
				&record.Settings{Issuer: testResponseIssuer, AppName: "Acme Portal"})
			failures[i] = issueAuthCode(responses[i], r, formPost,
				&record.Code{Code: "a_code", RedirectURI: "https://example.com/callback", State: "s"}, "form_post")
		})
	}
	wg.Wait()
	for i, w := range responses {
		require.NoError(t, failures[i])
		assert.Contains(t, w.Body.String(), `name="code" value="a_code"`)
	}
}
