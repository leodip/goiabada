package integration

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CORS answers as the running server sends them, every CORS header field read off the wire
// (#462 decision 8, #280): a preflight's grant and its refusal, its request headers split across
// field lines (#716 item 1), and an ordinary request's, whose grant exposes WWW-Authenticate and
// Retry-After to script (#716 item 2). The
// branches are middleware.CORS's own tests; this holds the middleware mounted, with a registered
// origin read from the real database.
func TestCors_TheAnswersOnTheWire(t *testing.T) {
	registered := "https://cors-answers-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	unregistered := "https://cors-answers-" + strings.ToLower(fake.LetterN(8)) + ".example.com"

	client := &record.Client{
		ClientIdentifier: "cors-answers-" + strings.ToLower(fake.LetterN(8)),
		Enabled:          true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()
	require.NoError(t, database.CreateWebOrigin(context.Background(), nil, &record.WebOrigin{
		ClientId: client.Id,
		Origin:   registered,
	}))

	preflightVary := []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"}
	exposed := []string{"WWW-Authenticate, Retry-After"}

	tests := []struct {
		name       string
		method     string
		path       string
		header     http.Header
		wantStatus int
		want       http.Header
	}{
		{
			name:   "a preflight from a registered origin is granted",
			method: http.MethodOptions, path: "/auth/token",
			header: http.Header{
				"Origin":                         {registered},
				"Access-Control-Request-Method":  {"POST"},
				"Access-Control-Request-Headers": {"authorization,content-type"},
			},
			wantStatus: http.StatusOK,
			want: http.Header{
				"Vary":                         preflightVary,
				"Access-Control-Allow-Origin":  {registered},
				"Access-Control-Allow-Methods": {"POST"},
				"Access-Control-Allow-Headers": {"Authorization, Content-Type"},
				"Access-Control-Max-Age":       {"600"},
			},
		},
		{
			name:   "a preflight's request headers on two lines are both granted",
			method: http.MethodOptions, path: "/userinfo",
			header: http.Header{
				"Origin":                         {registered},
				"Access-Control-Request-Method":  {"GET"},
				"Access-Control-Request-Headers": {"authorization", "x-csrf-token"},
			},
			wantStatus: http.StatusOK,
			want: http.Header{
				"Vary":                         preflightVary,
				"Access-Control-Allow-Origin":  {registered},
				"Access-Control-Allow-Methods": {"GET"},
				"Access-Control-Allow-Headers": {"Authorization, X-Csrf-Token"},
				"Access-Control-Max-Age":       {"600"},
			},
		},
		{
			name:   "a preflight from an unregistered origin is refused",
			method: http.MethodOptions, path: "/auth/token",
			header: http.Header{
				"Origin":                        {unregistered},
				"Access-Control-Request-Method": {"POST"},
			},
			wantStatus: http.StatusOK,
			want:       http.Header{"Vary": preflightVary},
		},
		{
			name:   "a preflight on a path no origin is allowed at is refused",
			method: http.MethodOptions, path: "/auth/authorize",
			header: http.Header{
				"Origin":                        {registered},
				"Access-Control-Request-Method": {"GET"},
			},
			wantStatus: http.StatusOK,
			want:       http.Header{"Vary": preflightVary},
		},
		{
			name:   "a GET of the JWKS names any origin",
			method: http.MethodGet, path: "/certs",
			header:     http.Header{"Origin": {unregistered}},
			wantStatus: http.StatusOK,
			want: http.Header{
				"Vary":                          {"Origin"},
				"Access-Control-Allow-Origin":   {unregistered},
				"Access-Control-Expose-Headers": exposed,
			},
		},
		{
			name:   "a GET of userinfo from a registered origin exposes the bearer challenge",
			method: http.MethodGet, path: "/userinfo",
			header:     http.Header{"Origin": {registered}},
			wantStatus: http.StatusUnauthorized,
			want: http.Header{
				"Vary":                          {"Origin"},
				"Access-Control-Allow-Origin":   {registered},
				"Access-Control-Expose-Headers": exposed,
			},
		},
		{
			name:   "a GET of userinfo from an unregistered origin names none",
			method: http.MethodGet, path: "/userinfo",
			header:     http.Header{"Origin": {unregistered}},
			wantStatus: http.StatusUnauthorized,
			want:       http.Header{"Vary": {"Origin"}},
		},
		{
			name:       "a request with no Origin varies on it",
			method:     http.MethodGet,
			path:       "/certs",
			wantStatus: http.StatusOK,
			want:       http.Header{"Vary": {"Origin"}},
		},
	}

	corsFields := []string{
		"Vary",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Max-Age",
		"Access-Control-Allow-Credentials",
		"Access-Control-Expose-Headers",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, appConfig.AuthServer.BaseURL+tt.path, nil)
			require.NoError(t, err)
			for name, values := range tt.header {
				req.Header[name] = values
			}

			resp, err := createHttpClient(t).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			if tt.method == http.MethodOptions {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Empty(t, body, "a preflight is answered with no content")
			}
			for _, field := range corsFields {
				assert.Equal(t, tt.want.Values(field), resp.Header.Values(field), field)
			}
		})
	}
}
