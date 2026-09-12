package adminclienthandlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil"
)

// logoApiClient answers the two calls this page makes: the client it renders, and the logo
// lookup that is allowed to fail. Separate from stubApiClient so that adding a failing method
// here cannot change what the redirect-URI cases see.
type logoApiClient struct {
	apiclient.ApiClient
	logoErr error
}

func (c *logoApiClient) GetClientById(accessToken string, clientId int64) (*api.ClientResponse, error) {
	return &api.ClientResponse{Id: clientId, ClientIdentifier: "an-client"}, nil
}

func (c *logoApiClient) GetClientLogo(accessToken string, clientId int64) (*apiclient.ClientLogoInfo, error) {
	return nil, c.logoErr
}

// The logo lookup's refusal, which held the last non-snake attribute key in the tree (#320
// decision 3), the last capitalised message and the last "Failed to" one (decision 4).
//
// The level is the part no lint can hold, so it is pinned here: the page renders without a logo,
// the administrator is served, and nobody has to act, which is the definition decision 5 gives
// Warn rather than the Error a failed call reads like. It also carries the request id from the
// context, with neither the key nor the value named at the call site.
func TestHandleAdminClientLogoGet_TheLogoRefusalIsOneWarnWithASnakeKeyAndTheRequestId(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	httpHelper := &stubHttpHelper{}
	apiClient := &logoApiClient{logoErr: errs.New("the auth server is unreachable")}

	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), constants.ContextKeyJwtInfo,
				oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "an-access-token"}})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router.Get("/admin/clients/{clientId}/logo", HandleAdminClientLogoGet(httpHelper, apiClient))

	req := httptest.NewRequest(http.MethodGet, "/admin/clients/42/logo", nil)
	req.Header.Set("X-Request-Id", "req-client-logo")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code, "the page still renders, which is why this is a Warn")
	require.NotNil(t, httpHelper.bind, "the page is rendered with no logo rather than refused")
	assert.Empty(t, httpHelper.bind["logoUrl"])

	records := logs.Records()
	require.Len(t, records, 1, "one record, which is the one under test")
	assert.Equal(t, slog.LevelWarn, records[0].Level,
		"a condition met and handled: the page is served without the logo")
	assert.Equal(t, "unable to fetch the client logo info", records[0].Message,
		"lowercase, literal, and the one verb the convention allows")
	assert.Equal(t, int64(42), records[0].Attrs["client_id"],
		"the numeric row id under decision 3's name for it, where the key used to be clientId")
	assert.Equal(t, "req-client-logo", records[0].Attrs["request_id"],
		"from chi's id on the context, with nothing at the call site naming it")

	logged, _ := records[0].Attrs["error"].(error)
	require.NotNil(t, logged, "the error rides as a value, so %+v prints the frames it captured")
	assert.Contains(t, logged.Error(), "unreachable")
}
