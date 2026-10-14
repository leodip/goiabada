package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The responder's emission gates and encodings are pinned in handler_authorize_test.go, which calls
// them as its methods; these cases own its two other answers: the provenance lookup and the
// server_error fallback after a failed clear.

func TestClientErrorResponder_ClientProvenance(t *testing.T) {
	t.Run("the client the identifier names", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		client := &record.Client{Id: 7, ClientIdentifier: "provenance-client"}
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		database.On("GetClientByClientIdentifier", req.Context(), mock.Anything, "provenance-client").Return(client, nil).Once()

		got := testClientErrorResponder(database, nil, nil).clientProvenance(req.Context(), "provenance-client")

		assert.Same(t, client, got)
	})

	t.Run("a failed load is unresolved provenance, logged at error", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)
		database := datamocks.NewDatabase(t)
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		database.On("GetClientByClientIdentifier", req.Context(), mock.Anything, "provenance-client").Return(nil, assert.AnError).Once()

		got := testClientErrorResponder(database, nil, nil).clientProvenance(req.Context(), "provenance-client")

		assert.Nil(t, got)
		records := logged.Records()
		require.Len(t, records, 1)
		assert.Equal(t, "ERROR", records[0].Level.String())
		assert.Equal(t, "unable to load the client while answering it with an error, treating its provenance as unresolved",
			records[0].Message)
		assert.Equal(t, "provenance-client", records[0].Attrs["client_identifier"])
	})
}

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
