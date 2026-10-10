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

// headAnswer is what a request got back: its status, its header fields and its content.
type headAnswer struct {
	status int
	header http.Header
	body   []byte
}

func requestWithoutRedirects(t *testing.T, method, url string) headAnswer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://head-check.example")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return headAnswer{status: resp.StatusCode, header: resp.Header, body: body}
}

// TestHead_TheReadOnlyResourcesAnswerAsGetDoes: RFC 9110 section 9.1 has a general-purpose server
// support GET and HEAD, and section 9.3.2 has a HEAD answered as the GET would be, with the same
// header fields and no content. The static files, the favicon, /health, discovery, JWKS, a client's
// logo and a user's picture answered HEAD with 405 until #542's live check, so a cache revalidating
// with HEAD, a monitor or a link checker got an error for a resource that was there.
func TestHead_TheReadOnlyResourcesAnswerAsGetDoes(t *testing.T) {
	ctx := context.Background()
	client := createTestClient(t, "head-check-"+fake.LetterN(8))
	require.NoError(t, database.CreateClientLogo(ctx, nil, &record.ClientLogo{
		ClientId:    client.Id,
		Logo:        createTestPNGImage(32, 32),
		ContentType: "image/png",
	}))
	user := createTestUserForProfilePicture(t)
	require.NoError(t, database.CreateUserProfilePicture(ctx, nil, &record.UserProfilePicture{
		UserId:      user.Id,
		Picture:     createTestPNGImage(64, 64),
		ContentType: "image/png",
	}))

	// The header fields a GET of these resources carries that a HEAD must carry the same. Date
	// and the request id differ between any two requests, so they are not compared, and
	// Content-Length has a rule of its own, below.
	compared := []string{
		"Content-Type", "Cache-Control", "Expires", "ETag", "Last-Modified",
		"Location", "Vary", "Access-Control-Allow-Origin", "X-Content-Type-Options",
	}

	for _, path := range []string{
		"/static/main.css",
		"/static",
		"/favicon.ico",
		"/health",
		"/.well-known/openid-configuration",
		"/certs",
		"/client/logo/" + client.ClientIdentifier,
		"/client/logo/no-such-client-" + fake.LetterN(8),
		"/userinfo/picture/" + user.Subject,
	} {
		t.Run(path, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + path
			get := requestWithoutRedirects(t, http.MethodGet, url)
			head := requestWithoutRedirects(t, http.MethodHead, url)

			assert.NotEqual(t, http.StatusMethodNotAllowed, head.status, "a read-only resource answers HEAD")
			assert.Equal(t, get.status, head.status, "a HEAD gets the GET's status")
			for _, name := range compared {
				// Expires is computed at the second the request is answered, so two requests a
				// second apart may differ; its presence is what must match.
				if name == "Expires" {
					assert.Equalf(t, get.header.Get(name) != "", head.header.Get(name) != "", "%s present on both or neither", name)
					continue
				}
				assert.Equalf(t, get.header.Get(name), head.header.Get(name), "the HEAD's %s is the GET's", name)
			}
			// RFC 9110 section 8.6: a HEAD MAY carry Content-Length, and MUST NOT unless it is the
			// length the GET's content would have had. net/http leaves it off a redirect's HEAD.
			if length := head.header.Get("Content-Length"); length != "" {
				assert.Equal(t, get.header.Get("Content-Length"), length, "a HEAD's Content-Length is the GET's content length")
			}
			assert.Empty(t, head.body, "a HEAD has no content")
		})
	}
}

// The other half: an endpoint whose GET starts or changes something, or that only takes a POST,
// still refuses HEAD, with 405 and an Allow naming what it does take (RFC 9110 section 15.5.6),
// so the change above cannot have widened HEAD to the protocol endpoints.
func TestHead_TheProtocolEndpointsStillRefuseIt(t *testing.T) {
	for _, path := range []string{
		"/auth/authorize",
		"/auth/token",
		"/auth/logout",
		"/userinfo",
		"/connect/register",
		"/auth/pwd",
	} {
		t.Run(path, func(t *testing.T) {
			head := requestWithoutRedirects(t, http.MethodHead, appConfig.AuthServer.BaseURL+path)

			assert.Equal(t, http.StatusMethodNotAllowed, head.status)
			allow := head.header.Get("Allow")
			assert.NotEmpty(t, allow, "a 405 lists what the resource takes")
			assert.NotContains(t, strings.Split(strings.ReplaceAll(allow, " ", ""), ","), http.MethodHead)
		})
	}
}
