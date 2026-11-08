package server

import (
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bearerGuardPrefix is the compiler-assigned name every bearer guard's closure starts with.
const bearerGuardPrefix = "github.com/leodip/goiabada/authserver/internal/middleware.(*BearerToken)."

// TestInitRoutes_EveryBearerRouteSpendsTheDPoPProofOnce: the parse guard spends a DPoP request's
// proof in the replay store as soon as it accepts it (#42 decision 9), so every route behind the
// bearer guards mounts it first, ahead of the other guards, and once. A second parse guard on a
// route would find the proof spent and refuse every DPoP request as a replay. The route set is the
// router's, so a route added later with the guard mounted twice fails here.
func TestInitRoutes_EveryBearerRouteSpendsTheDPoPProofOnce(t *testing.T) {
	s := newRoutesTestServer(t)

	seen := map[string]bool{}
	err := s.router.Walk(func(method string, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		var guards []string
		for _, mw := range middlewares {
			name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
			if guard, ok := strings.CutPrefix(name, bearerGuardPrefix); ok {
				guards = append(guards, strings.Split(guard, ".")[0])
			}
		}
		if len(guards) == 0 {
			return nil
		}
		for _, prefix := range []string{"/userinfo", "/api/v1/admin/", "/api/v1/account/", "/api/v1/sessions/"} {
			if strings.HasPrefix(route, prefix) {
				seen[prefix] = true
			}
		}
		t.Run(method+" "+route, func(t *testing.T) {
			assert.Equal(t, "JwtAuthorizationHeaderToContext", guards[0], "the parse guard comes first: %v", guards)
			count := 0
			for _, g := range guards {
				if g == "JwtAuthorizationHeaderToContext" {
					count++
				}
			}
			assert.Equal(t, 1, count, "the parse guard, which spends the proof, is mounted once: %v", guards)
		})
		return nil
	})
	require.NoError(t, err)

	for _, prefix := range []string{"/userinfo", "/api/v1/admin/", "/api/v1/account/", "/api/v1/sessions/"} {
		assert.True(t, seen[prefix], "no bearer-guarded route under %s was enumerated", prefix)
	}
}
