package apiclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 8's client half (#328). The viewer's two filters reach the auth server as a URL this
// client builds by hand out of strings, and one of them is a request id: whatever the client
// of the audited request put in X-Request-Id. An "&" in it, concatenated raw, would arrive as
// a second parameter rather than as part of the id, so the operator would be shown the wrong
// rows and a "page" smuggled in that way would be read by the API over the real one.
func TestGetAuditLogsPaginated_BothFiltersReachTheServerEscaped(t *testing.T) {
	testCases := []struct {
		name       string
		auditEvent string
		requestId  string
	}{
		{"neither", "", ""},
		{"the event alone", "user_login", ""},
		{"the id alone", "", "host/Ppg6bHPK5f-000012"},
		{"both", "user_login", "host/Ppg6bHPK5f-000012"},
		{"an id carrying a query separator", "", "x&page=9"},
		{"an id carrying a fragment marker", "", "x#y"},
		{"an id carrying a space and a plus", "", "x +y"},
		{"an id carrying a quote and a tag", "", `"><script>`},
		{"an id that is only an equals sign", "", "="},
		// auditEvent's values come from a fixed list, so nothing can get a separator
		// into it today. The case exists so the escaping added beside requestId's is
		// held by something rather than resting on that argument staying true.
		{"an event carrying a query separator", "a&page=9", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got url.Values
			var gotPath string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query()
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(api.GetAuditLogsResponse{Total: 0, Page: 1, Size: 20})
			}))
			defer server.Close()

			client := NewAuthServerClient(server.URL)
			resp, err := client.GetAuditLogsPaginated("an-access-token", 1, 20, tc.auditEvent, tc.requestId)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, "/api/v1/admin/audit-logs", gotPath)
			assert.Equal(t, "1", got.Get("page"))
			assert.Equal(t, "20", got.Get("size"))

			// Byte for byte, and once only: a value that split would arrive as two.
			assert.Equal(t, tc.requestId, got.Get("requestId"), "the request id did not survive the URL")
			assert.Equal(t, tc.auditEvent, got.Get("auditEvent"), "the event did not survive the URL")
			assert.LessOrEqual(t, len(got["requestId"]), 1, "requestId arrived more than once")
			assert.LessOrEqual(t, len(got["auditEvent"]), 1, "auditEvent arrived more than once")

			// An empty filter is absent rather than present and empty, which is what the
			// API reads as "no filter" either way but is what the URL says today.
			if tc.requestId == "" {
				assert.Empty(t, got["requestId"], "an empty request id was still sent")
			}
			if tc.auditEvent == "" {
				assert.Empty(t, got["auditEvent"], "an empty event was still sent")
			}

			// Nothing the id carried became another parameter.
			for key := range got {
				assert.Contains(t, []string{"page", "size", "auditEvent", "requestId"}, key,
					"an unexpected parameter %q reached the server", key)
			}
		})
	}
}
