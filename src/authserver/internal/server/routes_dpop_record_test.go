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

// TestInitRoutes_EveryBearerRouteRecordsTheDPoPProofAfterItsGuards: a route behind the bearer
// guards records a DPoP request's proof in the replay store once, after every bearer guard on the
// route has passed, so a request a guard refuses spends nothing and a request that reaches its
// handler always has (#42 decision 9). The route set is the router's, so a route added later
// without the replay guard, or with a guard behind it, fails here.
func TestInitRoutes_EveryBearerRouteRecordsTheDPoPProofAfterItsGuards(t *testing.T) {
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
			assert.Equal(t, "RecordDPoPProof", guards[len(guards)-1], "the replay guard comes after every other: %v", guards)
			count := 0
			for _, g := range guards {
				if g == "RecordDPoPProof" {
					count++
				}
			}
			assert.Equal(t, 1, count, "the proof is recorded once: %v", guards)
		})
		return nil
	})
	require.NoError(t, err)

	for _, prefix := range []string{"/userinfo", "/api/v1/admin/", "/api/v1/account/", "/api/v1/sessions/"} {
		assert.True(t, seen[prefix], "no bearer-guarded route under %s was enumerated", prefix)
	}
}
