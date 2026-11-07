package integration

// A registration's dpop_bound_access_tokens, through POST /connect/register (RFC 9449 section 5.2,
// #42 decision 12): stored on the new client as "Require DPoP for token requests", echoed in the
// answer (RFC 7591 section 3.2.1), false when left out, and read back through the admin API. A value
// that is not a boolean is refused invalid_client_metadata naming the field, and creates nothing.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDCR_DPoPBoundAccessTokensIsStoredAndEchoed(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)

	tests := []struct {
		name   string
		member string
		want   bool
	}{
		{name: "true", member: `,"dpop_bound_access_tokens":true`, want: true},
		{name: "false", member: `,"dpop_bound_access_tokens":false`, want: false},
		{name: "left out", member: ``, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, members := postDCRBody(t, `{"client_name":"DPoP Registration","token_endpoint_auth_method":"none",`+
				`"redirect_uris":["http://127.0.0.1/callback"]`+tc.member+`}`)
			require.Equal(t, http.StatusCreated, status, "%v", members)

			want := `false`
			if tc.want {
				want = `true`
			}
			assert.JSONEq(t, want, string(members["dpop_bound_access_tokens"]), "the answer echoes what was stored")

			client := registeredClientThroughTheAdminAPI(t, adminToken, members)
			assert.Equal(t, tc.want, client.DPoPBoundAccessTokens)
		})
	}
}

func TestDCR_ADPoPBoundAccessTokensThatIsNotABooleanCreatesNothing(t *testing.T) {
	enableDCR(t)
	adminToken, _ := createAdminClientWithToken(t)
	before := countClientsThroughTheAdminAPI(t, adminToken)

	for _, value := range []string{`"true"`, `1`, `null`, `{}`, `[true]`} {
		t.Run(value, func(t *testing.T) {
			status, members := postDCRBody(t, `{"redirect_uris":["https://dcr-dpop.example.com/callback"],`+
				`"dpop_bound_access_tokens":`+value+`}`)
			require.Equal(t, http.StatusBadRequest, status, "%v", members)
			assert.JSONEq(t, `"invalid_client_metadata"`, string(members["error"]))
			assert.JSONEq(t, `"dpop_bound_access_tokens must be a boolean"`, string(members["error_description"]))
			assert.NotContains(t, members, "client_id")
		})
	}

	// The back-channel logout flag keeps naming its own field beside the new one.
	status, members := postDCRBody(t, `{"redirect_uris":["https://dcr-dpop.example.com/callback"],`+
		`"backchannel_logout_uri":"https://dcr-dpop.example.com/bcl","backchannel_logout_session_required":"yes",`+
		`"dpop_bound_access_tokens":true}`)
	require.Equal(t, http.StatusBadRequest, status, "%v", members)
	assert.JSONEq(t, `"backchannel_logout_session_required must be a boolean"`, string(members["error_description"]))

	assert.Equal(t, before, countClientsThroughTheAdminAPI(t, adminToken), "a refused registration creates no client")
}
