package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/imaging"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The auth server's request-body table (bodyLimitPolicy in server.go) against the routes this
// binary really registers and the bounds its handlers really keep. core's own tests own the
// lookup; what is claimed here is this table (#426).

// TestBodyLimitPolicy_NamesOnlyRegisteredRoutes: an entry naming a route that does not exist
// matches nothing, and the route it was written for silently falls to the default. Walking the
// real registrations is what catches a pattern renamed in routes.go and not here.
func TestBodyLimitPolicy_NamesOnlyRegisteredRoutes(t *testing.T) {
	s := newStaticBranchTestServer(mocks_data.NewDatabase(t))
	s.templateFS = web.TemplateFS()
	s.initRoutes(s.initMiddleware())

	var registered []string
	err := chi.Walk(s.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered = append(registered, method+" "+route)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, registered, "the walk must have reached the routes")

	policy := bodyLimitPolicy(0)
	for key := range policy.Routes {
		assert.Contains(t, registered, key, "a Routes key must be a registered method and pattern")
	}
	for prefix := range policy.Prefixes {
		covered := false
		for _, route := range registered {
			_, pattern, _ := strings.Cut(route, " ")
			covered = covered || strings.HasPrefix(pattern, prefix)
		}
		assert.True(t, covered, "the prefix %s must cover at least one registered route", prefix)
	}
}

// TestBodyLimitPolicy_EachRowAtItsBoundary sends each row's limit and one byte more through the
// real root chain, to a stub at a pattern that row governs.
func TestBodyLimitPolicy_EachRowAtItsBoundary(t *testing.T) {
	uploadLimit := imaging.MaxFileSize(config.GetAuthServer().ProfilePictureMaxSizeBytes) + 64*1024

	tests := []struct {
		name    string
		method  string
		pattern string
		target  string
		limit   int64
	}{
		{"the default, at a browser form", http.MethodPost, "/auth/pwd", "/auth/pwd", 64 * 1024},
		{"the default, at registration", http.MethodPost, "/connect/register", "/connect/register", 64 * 1024},
		{"the admin API", http.MethodPut, "/api/v1/admin/users/{id}/profile", "/api/v1/admin/users/1/profile", 1 << 20},
		{"the account API", http.MethodPut, "/api/v1/account/profile", "/api/v1/account/profile", 1 << 20},
		{"the session transport", http.MethodPost, "/api/v1/sessions/load", "/api/v1/sessions/load", sessionstore.MaxSessionWireBytes},
		{"the admin user picture upload", http.MethodPost, "/api/v1/admin/users/{id}/profile-picture", "/api/v1/admin/users/1/profile-picture", uploadLimit},
		{"the client logo upload", http.MethodPost, "/api/v1/admin/clients/{id}/logo", "/api/v1/admin/clients/1/logo", uploadLimit},
		{"the account picture upload", http.MethodPost, "/api/v1/account/profile-picture", "/api/v1/account/profile-picture", uploadLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStaticBranchTestServer(mocks_data.NewDatabase(t))
			s.initMiddleware()
			s.router.Method(test.method, test.pattern, http.HandlerFunc(readWholeBody))

			assert.Equal(t, fmt.Sprintf("read %d", test.limit), sendBody(s.router, test.method, test.target, test.limit),
				"a body of exactly the limit reads whole")
			assert.Equal(t, fmt.Sprintf("refused at %d", test.limit), sendBody(s.router, test.method, test.target, test.limit+1),
				"one byte more is refused")
		})
	}
}

// TestBodyLimitPolicy_EachRowHoldsItsHandlersBound: a handler that bounds its own body answers for
// it with its own documented error, and it can only do so while the row around it is at least as
// wide. A row narrower than its handler would refuse first, and the handler would read a cut body
// as some other failure.
func TestBodyLimitPolicy_EachRowHoldsItsHandlersBound(t *testing.T) {
	uploads := []string{
		"POST /api/v1/admin/users/{id}/profile-picture",
		"POST /api/v1/admin/clients/{id}/logo",
		"POST /api/v1/account/profile-picture",
	}

	// The upload handlers bound their bodies at the image size plus 1 KiB, and the image size
	// follows GOIABADA_PROFILE_PICTURE_MAX_SIZE_BYTES, so the rows must follow it too: at the
	// default, and at a raised setting.
	for _, configured := range []int64{0, 10 << 20} {
		policy := bodyLimitPolicy(configured)
		for _, route := range uploads {
			assert.Greater(t, policy.Routes[route], imaging.MaxFileSize(configured)+1024,
				"%s at a configured size of %d", route, configured)
		}
	}

	policy := bodyLimitPolicy(0)

	// The session handlers bound theirs at the store's wire ceiling, on purpose, and the row is
	// that same constant rather than a wider one, so it is equal rather than greater.
	assert.Equal(t, int64(sessionstore.MaxSessionWireBytes), policy.Prefixes["/api/v1/sessions/"])

	// The account OTP PUT bounds its body at 64 KiB (maxOTPRequestBodyBytes in apihandlers).
	assert.Greater(t, policy.Prefixes["/api/v1/account/"], int64(64*1024))
}

// readWholeBody answers how much of the body it read, or the limit that refused it.
func readWholeBody(w http.ResponseWriter, r *http.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		_, _ = fmt.Fprintf(w, "refused at %d", tooLarge.Limit)
	case err != nil:
		_, _ = fmt.Fprintf(w, "error %v", err)
	default:
		_, _ = fmt.Fprintf(w, "read %d", n)
	}
}

func sendBody(router http.Handler, method string, target string, size int64) string {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, target, strings.NewReader(strings.Repeat("x", int(size)))))
	return recorder.Body.String()
}
