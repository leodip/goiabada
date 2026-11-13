package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// GOIABADA_AUTHSERVER_BRAND_SAFE_MODE draws every page in safe mode, whatever the request: on, every
// request carries it, a page with no page client included; off, none does (#816 decision 3).
func TestBrandSafeMode_MarksEveryRequestWhileTheSwitchIsOn(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "on", false: "off"}[enabled], func(t *testing.T) {
			for _, target := range []string{"/auth/pwd", "/no-such-page", "/api/public/settings"} {
				var safe, reached bool
				handler := BrandSafeMode(enabled)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached = true
					safe = reqctx.BrandSafeMode(r.Context())
				}))

				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))

				assert.True(t, reached, target)
				assert.Equal(t, enabled, safe, target)
			}
		})
	}
}
