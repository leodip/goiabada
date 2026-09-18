package integrationtests

import (
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/require"
)

// TestCors_TrailingSlashUsesTheSamePolicy proves the CORS middleware mounted on the running
// server treats paths that chi's StripSlashes routes to the same handler alike. Unit tests can
// prove the policy function's answer, but they stay green if the middleware is no longer mounted.
func TestCors_TrailingSlashUsesTheSamePolicy(t *testing.T) {
	origin := "https://cors-" + strings.ToLower(fake.LetterN(8)) + ".example.com"

	t.Run("always allowed certs needs no database fixture", func(t *testing.T) {
		assertCorsPathPair(t, origin, "/certs", http.StatusOK)
	})

	t.Run("database gated userinfo uses a registered origin", func(t *testing.T) {
		client := &models.Client{
			ClientIdentifier: "cors-slash-" + strings.ToLower(fake.LetterN(8)),
			Enabled:          true,
		}
		require.NoError(t, database.CreateClient(nil, client))
		defer func() { _ = database.DeleteClient(nil, client.Id) }()
		require.NoError(t, database.CreateWebOrigin(nil, &models.WebOrigin{
			ClientId: client.Id,
			Origin:   origin,
		}))

		assertCorsPathPair(t, origin, "/userinfo", http.StatusUnauthorized)
	})
}

func assertCorsPathPair(t *testing.T, origin string, path string, getStatus int) {
	t.Helper()

	methods := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{name: "preflight", method: http.MethodOptions, wantStatus: http.StatusOK},
		{name: "real request", method: http.MethodGet, wantStatus: getStatus},
	}

	for _, method := range methods {
		for _, suffix := range []string{"", "/"} {
			name := method.name + "/exact path"
			if suffix != "" {
				name = method.name + "/trailing slash"
			}
			t.Run(name, func(t *testing.T) {
				req, err := http.NewRequest(method.method, config.GetAuthServer().BaseURL+path+suffix, nil)
				require.NoError(t, err)
				req.Header.Set("Origin", origin)
				if method.method == http.MethodOptions {
					req.Header.Set("Access-Control-Request-Method", http.MethodGet)
				}

				resp, err := createHttpClient(t).Do(req)
				require.NoError(t, err)
				defer func() { _ = resp.Body.Close() }()

				require.Equal(t, method.wantStatus, resp.StatusCode,
					"the slashed path must route to the same handler as the exact path")
				require.Equal(t, origin, resp.Header.Get("Access-Control-Allow-Origin"))
			})
		}
	}
}
