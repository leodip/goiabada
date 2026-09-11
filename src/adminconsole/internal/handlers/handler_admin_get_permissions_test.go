package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
)

// This handler carried the console's only caller-side error log: a slog.Error on every apiClient
// failure, written before HandleAPIErrorJson had classified it. An upstream 500 was therefore
// recorded twice, once here and once in JsonError, and a 400, 404 or 409 that the classifier
// forwards silently on purpose was still announced at ERROR with a stack. Counting records is the
// only way to see either: the status and the body are identical with the extra line and without it.
//
// The real HttpHelper rather than the mock, for the same reason: the mock's JsonError logs nothing,
// so a handler that logged once would look correct against it (#279).

type permissionsByResourceClient struct {
	apiclient.ApiClient
	permissions []models.Permission
	err         error
}

func (c *permissionsByResourceClient) GetPermissionsByResource(accessToken string, resourceId int64) ([]models.Permission, error) {
	return c.permissions, c.err
}

// permissionRecords runs the handler over a chi router carrying the request id middleware, and
// returns the response together with every ERROR line the whole chain wrote.
func permissionRecords(t *testing.T, client apiclient.ApiClient, query string) (*httptest.ResponseRecorder, []string) {
	t.Helper()

	capture := testutil.CaptureSlog(t)

	httpHelper := handlerhelpers.NewHttpHelper(&mocks.TestFS{})

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router.Get("/admin/permissions", HandleAdminGetPermissionsGet(httpHelper, client))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/permissions?"+query, nil))

	var errorLines []string
	for _, line := range strings.Split(strings.TrimSpace(capture.Text()), "\n") {
		if strings.Contains(line, "level=ERROR") {
			errorLines = append(errorLines, line)
		}
	}
	return recorder, errorLines
}

// A server fault is logged once and answered with a request id, which is what every other 500 in
// the tree does. Twice is the defect: an operator counting 500s in the log counts this endpoint's
// twice, and the second record is the one with no request id on it.
func TestAdminGetPermissions_AnUpstreamServerFaultIsLoggedOnce(t *testing.T) {
	client := &permissionsByResourceClient{err: &apiclient.APIError{
		Code:       "INTERNAL_SERVER_ERROR",
		Message:    "the database is on fire",
		StatusCode: http.StatusInternalServerError,
	}}

	recorder, errorLines := permissionRecords(t, client, "resourceId=7")

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Len(t, errorLines, 1, "one record per 500, and JsonError is the one that writes it")
	assert.Contains(t, errorLines[0], "unable to get the permissions of resource 7",
		"the id the caller-side line carried survives, in the message the one record logs")

	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "server_error", body["error"])
}

// A client's mistake the classifier forwards is not an event an operator has to read, and the
// caller-side line announced every one of them at ERROR with a stack behind it.
func TestAdminGetPermissions_AForwardedClientErrorIsSilent(t *testing.T) {
	client := &permissionsByResourceClient{err: &apiclient.APIError{
		Code:       "VALIDATION_ERROR",
		Message:    "resourceId must name a resource",
		StatusCode: http.StatusBadRequest,
	}}

	recorder, errorLines := permissionRecords(t, client, "resourceId=7")

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Empty(t, errorLines, "a forwarded 400 is the administrator's to read, not the operator's")

	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "VALIDATION_ERROR", body["error"])
	assert.Equal(t, "resourceId must name a resource", body["error_description"],
		"wrapping the error to keep the resource id must not cost the API's own sentence")
}

// And the wrap that carries the resource id has to stay invisible to the classifier, which is
// decision 6's whole claim: errors.As sees the *APIError through it, so a row the API says is gone
// still reaches the console's own 404 sentence rather than the generic 500.
func TestAdminGetPermissions_AMissingResourceStillAnswers404(t *testing.T) {
	client := &permissionsByResourceClient{err: &apiclient.APIError{
		Code:       "NOT_FOUND",
		Message:    "Resource not found",
		StatusCode: http.StatusNotFound,
	}}

	recorder, errorLines := permissionRecords(t, client, "resourceId=7")

	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Empty(t, errorLines)

	var body map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "not_found", body["error"])
}

// The success path, so the rows above cannot be satisfied by a handler that fails everything.
func TestAdminGetPermissions_ReturnsThePermissions(t *testing.T) {
	client := &permissionsByResourceClient{permissions: []models.Permission{{Id: 3, PermissionIdentifier: "read"}}}

	recorder, errorLines := permissionRecords(t, client, "resourceId=7")

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, errorLines)
	assert.Contains(t, recorder.Body.String(), "\"PermissionIdentifier\":\"read\"")
}
