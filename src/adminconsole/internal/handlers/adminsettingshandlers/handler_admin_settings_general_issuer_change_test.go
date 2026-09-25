package adminsettingshandlers

import (
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/cache"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

// issuerChangingAPI answers the issuer the settings held before the save, then the one the save
// wrote.
type issuerChangingAPI struct {
	before, after string
}

func (a issuerChangingAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: a.before}, nil
}

func (a issuerChangingAPI) UpdateSettingsGeneral(context.Context, string, *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: a.after}, nil
}

// Changing the issuer signs the administrator who changed it out, and the access token's recorded
// expiry goes with the token response it describes. The console reads that expiry instead of
// decoding its access token, so a value left behind would describe a token the session no longer
// holds (#427 decision 15).
//
// Observed through the store's own Get with the cookie the handler answered with, which is what
// the next request would load; the unrelated value proves the session was edited, not discarded.
func TestHandleAdminSettingsGeneralPost_AnIssuerChangeDeletesTheTokenResponseAndItsExpiry(t *testing.T) {
	gob.Register(oauth.TokenResponse{})
	store := newSettingsTestStore()

	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seeded, err := store.Get(seedReq, coreconstants.AdminConsoleSessionName)
	require.NoError(t, err)
	seeded.Values[constants.SessionKeyJwt] = oauth.TokenResponse{AccessToken: "the-access-token"}
	seeded.Values[constants.SessionKeyJwtExpiresAt] = int64(1_900_000_000)
	seeded.Values["Unrelated"] = "kept"
	seedW := httptest.NewRecorder()
	require.NoError(t, store.Save(seedReq, seedW, seeded))
	cookies := seedW.Result().Cookies()
	require.NotEmpty(t, cookies)

	req := handlertest.Request(http.MethodPost, "/admin/settings/general",
		handlertest.WithAccessToken(),
		handlertest.WithForm(url.Values{"issuer": {"https://new-issuer.example"}}))
	for _, c := range cookies {
		req.AddCookie(c)
	}

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	w := httptest.NewRecorder()
	HandleAdminSettingsGeneralPost(httpHelper, store,
		issuerChangingAPI{before: "https://old-issuer.example", after: "https://new-issuer.example"},
		cache.NewSettingsCache("http://auth.example.invalid"),
	).ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, config.GetAdminConsole().BaseURL+"/auth/logout", w.Header().Get("Location"))

	readReq := httptest.NewRequest(http.MethodGet, "/", nil)
	answered := w.Result().Cookies()
	if len(answered) == 0 {
		answered = cookies
	}
	for _, c := range answered {
		readReq.AddCookie(c)
	}
	readBack, err := store.Get(readReq, coreconstants.AdminConsoleSessionName)
	require.NoError(t, err)
	require.False(t, readBack.IsNew, "the session is still there")
	assert.NotContains(t, readBack.Values, constants.SessionKeyJwt)
	assert.NotContains(t, readBack.Values, constants.SessionKeyJwtExpiresAt)
	assert.Equal(t, "kept", readBack.Values["Unrelated"])
}
