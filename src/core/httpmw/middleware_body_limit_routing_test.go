package httpmw

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/core/routing"
)

// The lookup through core/routing's router, the form both servers move to in #462; the rules are
// the chi form's, so the fixture and the answers are too.
func newBodyLimitRoutingRouter(policy BodyLimitPolicy, handler http.HandlerFunc) *routing.Router {
	router := routing.New()
	router.Use(StripTrailingSlash)
	router.Use(BodyLimitOn(router, policy))
	router.NotFound(handler)
	router.Post("/plain", handler)
	router.Route("/api", func(api *routing.Router) {
		api.Post("/items", handler)
		api.Post("/items/{id}", handler)
		api.Put("/items/{id}", handler)
		api.Post("/deep/thing", handler)
	})
	return router
}

// bodyLimitRoutingReader is bodyLimitReader with the {id} parameter read as ServeMux sets it.
func bodyLimitRoutingReader(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		_, _ = fmt.Fprintf(w, "refused at %d", tooLarge.Limit)
	case err != nil:
		_, _ = fmt.Fprintf(w, "error %v", err)
	default:
		_, _ = fmt.Fprintf(w, "read %d id=%s", len(body), r.PathValue("id"))
	}
}

func TestBodyLimitOn_TheLimitEachRequestMeets(t *testing.T) {
	router := newBodyLimitRoutingRouter(bodyLimitFixturePolicy(), bodyLimitRoutingReader)

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"a path no route matches gets the default", http.MethodPost, "/nowhere", "refused at 16"},
		{"a path under a prefix no route matches gets the default", http.MethodPost, "/api/nowhere", "refused at 16"},
		{"a route no entry names gets the default", http.MethodPost, "/plain", "refused at 16"},
		{"a route under a prefix gets the prefix", http.MethodPost, "/api/items", "refused at 32"},
		{"the longest prefix wins", http.MethodPost, "/api/deep/thing", "refused at 48"},
		{"an exact route wins over its prefix", http.MethodPost, "/api/items/7", "refused at 64"},
		{"the same pattern under another method falls to the prefix", http.MethodPut, "/api/items/7", "refused at 32"},
		{"a trailing slash resolves as the strip routes it", http.MethodPost, "/api/items/7/", "refused at 64"},
		{"an escaped parameter resolves to its route", http.MethodPost, "/api/items/a%2Fb", "refused at 64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, serveBody(router, test.method, test.target, 1000))
		})
	}
}

func TestBodyLimitOn_TheBoundary(t *testing.T) {
	router := newBodyLimitRoutingRouter(bodyLimitFixturePolicy(), bodyLimitRoutingReader)

	assert.Equal(t, "read 64 id=7", serveBody(router, http.MethodPost, "/api/items/7", 64), "a body of exactly the limit reads whole")
	assert.Equal(t, "refused at 64", serveBody(router, http.MethodPost, "/api/items/7", 65), "one byte more is refused")
}

func TestBodyLimitOn_RefusesASilentlyWrongPolicy(t *testing.T) {
	policy := bodyLimitFixturePolicy()
	policy.Default = 0
	assert.Panics(t, func() { BodyLimitOn(routing.New(), policy) })
}
