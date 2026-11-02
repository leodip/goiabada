package publicsettings

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
	"github.com/leodip/goiabada/adminconsole/internal/upstreammetrics"
	"github.com/leodip/goiabada/core/metrics"
)

// The public settings client refuses a redirect from the auth server (#715 decision 13): the call
// fails naming the target's origin and the internal URL setting, sends nothing to the target, and
// is recorded under the status it arrived with.
func TestClient_RefusesARedirect(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var followed atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/public/settings" {
					followed.Add(1)
					_, _ = w.Write([]byte(`{"appName":"followed"}`))
					return
				}
				w.Header().Set("Location", "https://auth.example.com:8443/path-marker?query-marker=1")
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)
			reg := metrics.NewRegistry()

			settings, err := NewClient(server.URL, nil, upstreammetrics.Register(reg)).GetPublicSettings(context.Background())

			require.Error(t, err)
			assert.Nil(t, settings)
			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, status, refused.StatusCode)
			assert.Equal(t, "https://auth.example.com:8443", refused.Origin)
			assert.Contains(t, err.Error(), "https://auth.example.com:8443")
			assert.Contains(t, err.Error(), "GOIABADA_AUTHSERVER_INTERNALBASEURL")
			assert.NotContains(t, err.Error(), "path-marker")
			assert.NotContains(t, err.Error(), "query-marker")
			assert.Zero(t, followed.Load(), "nothing is sent to the redirect's target")
			assert.Contains(t, scrape(t, reg),
				`goiabada_upstream_requests_total{target="settings",status="`+strconv.Itoa(status)+`"} 1`+"\n",
				"the redirect is recorded as the answer it was")
		})
	}
}
