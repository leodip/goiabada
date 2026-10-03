package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// consentsApiClient holds one user with the consents it is given, and records each revoke.
type consentsApiClient struct {
	consents []api.UserConsentResponse
	revoked  []int64
}

func (c *consentsApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Username: "jdoe"}, nil
}

func (c *consentsApiClient) GetUserConsents(_ context.Context, _ string, _ int64) ([]api.UserConsentResponse, error) {
	return c.consents, nil
}

func (c *consentsApiClient) DeleteUserConsent(_ context.Context, _ string, consentId int64) error {
	c.revoked = append(c.revoked, consentId)
	return nil
}

func revokeConsent(t *testing.T, apiClient *consentsApiClient, consentId string) *httptest.ResponseRecorder {
	t.Helper()

	req := handlertest.Request(http.MethodPost, "/admin/users/42/consents",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42"),
		handlertest.WithBody(strings.NewReader(`{"consentId":`+consentId+`}`)),
		handlertest.WithContentType("application/json"))
	recorder := httptest.NewRecorder()

	// The real writer, because what is under test is the answer on the wire and the log it does
	// or does not leave, and both are the writer's.
	HandleAdminUserConsentsPost(render.New(fstest.MapFS{}), apiClient).ServeHTTP(recorder, req)
	return recorder
}

// A revoke naming a consent this user no longer holds is a stale page: another administrator, or
// the user, revoked it after this page loaded. It names nothing here, so it is answered as the 404
// JSONNotFound gives every such id, with nothing logged, rather than a 500 with a stack (#440
// decision 6).
func TestHandleAdminUserConsentsPost_AConsentTheUserNoLongerHoldsIs404WithNothingLogged(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	apiClient := &consentsApiClient{consents: []api.UserConsentResponse{{Id: 7, UserId: 42}}}

	recorder := revokeConsent(t, apiClient, "13")

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "not_found", body["error"])
	assert.Empty(t, apiClient.revoked, "nothing is revoked")
	assert.Empty(t, logs.Records(), "a stale page is not a server fault")
}

// The other side of the same check: a consent the user does hold is revoked and answered as before.
func TestHandleAdminUserConsentsPost_AConsentTheUserHoldsIsRevoked(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	apiClient := &consentsApiClient{consents: []api.UserConsentResponse{{Id: 7, UserId: 42}, {Id: 13, UserId: 42}}}

	recorder := revokeConsent(t, apiClient, "13")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.JSONEq(t, `{"Success":true}`, recorder.Body.String())
	assert.Equal(t, []int64{13}, apiClient.revoked)
	assert.Empty(t, logs.Records())
}
