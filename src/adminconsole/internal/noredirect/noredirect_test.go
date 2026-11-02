package noredirect_test

// Seam: what a client the admin console calls the auth server through returns when the answer is
// a redirect (#715 decision 13). The calls are real HTTP to a peer this test serves, through a
// client that would follow every one of these redirects but for the refusal.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/noredirect"
)

// The five redirects net/http follows (RFC 9110 section 15.4).
var followedRedirects = []int{
	http.StatusMovedPermanently,
	http.StatusFound,
	http.StatusSeeOther,
	http.StatusTemporaryRedirect,
	http.StatusPermanentRedirect,
}

// redirecting answers /start with status and location, and counts every request that reaches any
// other path, which is what a followed redirect would be.
func redirecting(t *testing.T, status int, location string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path != "/start" {
			followed.Add(1)
			_, _ = w.Write([]byte("followed"))
			return
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, &followed
}

func post(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("client_secret=body-marker"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

func TestClient_RefusesEveryRedirectNetHTTPFollows(t *testing.T) {
	for _, status := range followedRedirects {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, followed := redirecting(t, status, "/followed/path-marker?query-marker=1")

			resp, err := post(t, noredirect.Client(&http.Client{Timeout: 5 * time.Second}), server.URL+"/start")

			require.Error(t, err)
			assert.Nil(t, resp)
			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, status, refused.StatusCode)
			assert.Equal(t, server.URL, refused.Origin, "a relative Location is the request's own origin")
			assert.Equal(t, int32(0), followed.Load(), "nothing is sent to the redirect's target")

			message := err.Error()
			assert.Contains(t, message, server.URL)
			assert.Contains(t, message, "GOIABADA_AUTHSERVER_INTERNALBASEURL")
			assert.NotContains(t, message, "path-marker")
			assert.NotContains(t, message, "query-marker")
		})
	}
}

// The error names the target by its origin alone: the scheme, the host and the port, never the
// user information, the path, the query or the fragment, any of which can carry what the console
// sent.
func TestClient_NamesTheTargetByItsOriginAlone(t *testing.T) {
	for location, origin := range map[string]string{
		"https://userinfo-marker:password-marker@auth.example.com:8443/path-marker?query-marker=1#fragment-marker": "https://auth.example.com:8443",
		"https://auth.example.com/path-marker":                "https://auth.example.com",
		"//other.example.com:9091/path-marker?query-marker=1": "http://other.example.com:9091",
	} {
		t.Run(location, func(t *testing.T) {
			server, _ := redirecting(t, http.StatusMovedPermanently, location)

			_, err := post(t, noredirect.Client(&http.Client{}), server.URL+"/start")

			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, origin, refused.Origin)
			message := err.Error()
			assert.Contains(t, message, origin)
			for _, secret := range []string{"userinfo-marker", "password-marker", "path-marker", "query-marker", "fragment-marker"} {
				assert.NotContains(t, message, secret)
			}
		})
	}
}

// A redirect status with no Location, or one that does not parse, is refused all the same, naming
// no target.
func TestClient_RefusesARedirectWithNoTargetItCanName(t *testing.T) {
	for name, location := range map[string]string{"no Location": "", "an unparsable Location": "http://[::1"} {
		t.Run(name, func(t *testing.T) {
			server, _ := redirecting(t, http.StatusFound, location)

			_, err := post(t, noredirect.Client(&http.Client{}), server.URL+"/start")

			var refused *noredirect.Error
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, http.StatusFound, refused.StatusCode)
			assert.Empty(t, refused.Origin)
			assert.Contains(t, err.Error(), "302")
			assert.Contains(t, err.Error(), "GOIABADA_AUTHSERVER_INTERNALBASEURL")
		})
	}
}

// Every answer that is not a redirect net/http follows reaches the caller as it arrived: a 300 and a
// 304 are 3xx answers net/http never follows.
func TestClient_PassesEveryOtherAnswerThrough(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusMultipleChoices, http.StatusNotModified, http.StatusNotFound, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, _ := redirecting(t, status, "/followed")

			resp, err := post(t, noredirect.Client(&http.Client{}), server.URL+"/start")

			require.NoError(t, err)
			assert.Equal(t, status, resp.StatusCode)
		})
	}
}

// The copy keeps the client's timeout and sends through its transport; the client itself is left
// as it was.
func TestClient_RefusesThroughACopy(t *testing.T) {
	var sent atomic.Int32
	inner := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		sent.Add(1)
		return http.DefaultTransport.RoundTrip(req)
	})
	client := &http.Client{Timeout: 7 * time.Second, Transport: inner}
	server, _ := redirecting(t, http.StatusOK, "")

	refusing := noredirect.Client(client)
	_, err := post(t, refusing, server.URL+"/start")

	require.NoError(t, err)
	assert.Equal(t, int32(1), sent.Load(), "the call goes out through the client's own transport")
	assert.Equal(t, 7*time.Second, refusing.Timeout)
	assert.NotSame(t, client, refusing)
	_, untouched := client.Transport.(roundTripperFunc)
	assert.True(t, untouched, "the client given is not changed")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
