package sessionbackend

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The session backend refuses a redirect from the auth server (#715 decision 13): the operation
// fails naming the target's origin and the internal URL setting, and nothing is sent to the target.
// A redirect is an answer, not a failure to reach the endpoint, so the transport retry is not
// spent on it: the stub sees the one request.
func TestHTTPBackend_RefusesARedirect(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			stub := newStubEndpoint(t, func(w http.ResponseWriter, _ int) {
				w.Header().Set("Location", "/elsewhere/path-marker?query-marker=1")
				w.WriteHeader(status)
			})
			backend := New(stub.server.URL, newStubTokens(), nil, nil)

			_, err := backend.Load(context.Background(), httpTestSessionId)

			require.Error(t, err)
			require.NotErrorIs(t, err, sessionstore.ErrNotFound, "a redirect is not a session that is gone")
			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, status, refused.StatusCode)
			assert.Equal(t, stub.server.URL, refused.Origin)
			assert.Contains(t, err.Error(), stub.server.URL)
			assert.Contains(t, err.Error(), "GOIABADA_AUTHSERVER_INTERNALBASEURL")
			assert.NotContains(t, err.Error(), "path-marker")
			assert.NotContains(t, err.Error(), "query-marker")
			requests := stub.recorded()
			require.Len(t, requests, 1, "neither followed nor retried")
			assert.Equal(t, sessionEndpointPrefix+"load", requests[0].path)
		})
	}
}
