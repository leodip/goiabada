package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The responder's emission gates and encodings are pinned in handler_authorize_test.go, which calls
// them as its methods; these cases own its other answer: the server_error fallback after a failed
// clear.

func TestClientErrorResponder_AnswerClientAfterClear(t *testing.T) {
	input := testRedirectError("access_denied", "The user did not provide consent", "query",
		"https://example.com/callback", "abc123", "code")

	t.Run("a clear that worked answers the client with the input", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)

		testClientErrorResponder(testRegisteredDatabase(t, "https://example.com/callback"), nil, nil).
			answerClientAfterClear(rr, req, input, nil)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t,
			"https://example.com/callback?error=access_denied&error_description=The+user+did+not+provide+consent&state=abc123",
			rr.Header().Get("Location"))
	})

	t.Run("a clear that failed answers server_error and logs the failure at error", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)

		testClientErrorResponder(testRegisteredDatabase(t, "https://example.com/callback"), nil, nil).
			answerClientAfterClear(rr, req, input, assert.AnError)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t,
			"https://example.com/callback?error=server_error&error_description=Internal+server+error&state=abc123",
			rr.Header().Get("Location"))
		records := logged.Records()
		require.Len(t, records, 1)
		assert.Equal(t, "ERROR", records[0].Level.String())
		assert.Equal(t, "unable to clear the auth context, answering the client with server_error", records[0].Message)
	})

	// The responder's own template FS is where form_post.html is read from: one with no such
	// template cannot write the response, and the 500 page is the last resort.
	formPostInput := testRedirectError("access_denied", "The user did not provide consent", "form_post",
		"https://example.com/callback", "abc123", "code")
	for _, clearErr := range []error{nil, assert.AnError} {
		name := "with the clear working"
		if clearErr != nil {
			name = "with the clear failing"
		}
		t.Run("a response that cannot be written is the 500, "+name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
			pageRenderer.On("InternalServerError", rr, req, mock.Anything).Return().Once()

			testClientErrorResponder(testRegisteredDatabase(t, "https://example.com/callback"), pageRenderer,
				fstest.MapFS{}).answerClientAfterClear(rr, req, formPostInput, clearErr)

			assert.Empty(t, rr.Header().Get("Location"))
			assert.Empty(t, rr.Body.String())
		})
	}
}
