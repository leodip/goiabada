package apihandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// The administrative policy's 403 MANAGE_SCOPE_REQUIRED carries the challenge of the scheme the
// token was presented with alone, insufficient_scope naming authserver:manage, as every 403 of the
// API does (RFC 9449 section 7.1, #42 decision 10): Bearer for a bearer token, DPoP for a token
// presented with its proof.
func TestRefuseAdministratorChange_ChallengesInTheSchemeUsed(t *testing.T) {
	const algs = `algs="ES256 ES384 ES512 PS256 PS384 PS512 RS256 RS384 RS512 Ed25519 EdDSA"`
	const rest = `error="insufficient_scope", error_description="` + manageScopeRequiredDescription + `", scope="authserver:manage"`
	for scheme, challenge := range map[string]string{
		"Bearer": `Bearer realm="goiabada", ` + rest,
		"DPoP":   `DPoP realm="goiabada", ` + algs + `, ` + rest,
	} {
		t.Run(scheme, func(t *testing.T) {
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			req := setTokenContextWithClaims(httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/1/permissions", nil),
				map[string]interface{}{"sub": "an-administrator"})
			if scheme == "DPoP" {
				req = req.WithContext(reqctx.WithDPoPProof(req.Context(), &dpop.Proof{}))
			}

			rr := httptest.NewRecorder()
			refuseAdministratorChange(rr, req, auditLogger, administratorChangeRefusal{ceiling: "grant"})

			require.Equal(t, http.StatusForbidden, rr.Code)
			var body map[string]string
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "MANAGE_SCOPE_REQUIRED", body["error_code"])
			assert.Equal(t, challenge, rr.Header().Get("WWW-Authenticate"))
		})
	}
}
