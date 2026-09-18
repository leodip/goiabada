package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/audit-logs/event-types
//
// Seam 5 (#351). The admin console's audit log viewer no longer compiles an audit event name
// into its binary; it fills its filter dropdown from this response. So the catalog arriving
// over the wire, complete and under the same read scope as the log query it describes, is the
// contract rather than an implementation detail.

const auditEventTypesURL = "/api/v1/admin/audit-logs/event-types"

func TestAPIAuditEventTypesGet_ServesTheWholeCatalog(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resp := makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+auditEventTypesURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body api.GetAuditEventTypesResponse
	require.NoError(t, json.Unmarshal(bodyBytes, &body))

	// Every declared name, in the order the catalog declares them, and nothing else. Equality
	// rather than containment: a catalog that had grown an extra entry would offer the operator
	// a filter value no row can ever carry.
	assert.Equal(t, audit.AuditEventTypes, body.AuditEventTypes)
	assert.Len(t, body.AuditEventTypes, 100,
		"the catalog is the 104 declared names less the four #351 decision 11 deleted")

	// The wire end of the chain openapi.yaml declares. The unit tier's
	// TestOpenAPI_SchemaPropertiesMatchTheAPIStructs holds GetAuditEventTypesResponse's schema
	// to the Go struct; this holds the served bytes to that same struct, so a handler writing
	// a body of its own shape would fail here rather than reach a generated client.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(bodyBytes, &raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	assert.Equal(t, []string{"auditEventTypes"}, keys,
		"the catalog body carries a property the schema does not declare")
}

// The catalog describes GET /api/v1/admin/audit-logs and tells a caller nothing that endpoint
// does not, so it is refused in the same three ways.
func TestAPIAuditEventTypes_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + auditEventTypesURL

	// No token
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	bodyBytes, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(bodyBytes), "Access token required.")

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// A real token holding a scope that is not settings-read.
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier,
		constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	bodyBytes3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(bodyBytes3), "Insufficient scope.")
}
