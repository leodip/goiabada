package reqctx

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// present reports which of the two values ctx carries, so a test can say which it expects.
func present(ctx context.Context) map[string]bool {
	_, jwtInfo := JwtInfoFrom(ctx)
	_, settings := SettingsFrom(ctx)
	return map[string]bool{
		"jwtInfo":  jwtInfo,
		"settings": settings,
	}
}

func TestReqctx_RoundTrip(t *testing.T) {
	ctx := context.Background()

	t.Run("token set", func(t *testing.T) {
		want := oauthclient.JwtInfo{
			TokenResponse: oauth.TokenResponse{AccessToken: "access", Scope: "openid"},
			IdToken:       &oauth.JwtToken{TokenBase64: "id", Claims: jwt.MapClaims{"sub": "user-1"}},
		}
		got, ok := JwtInfoFrom(WithJwtInfo(ctx, want))
		require.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("settings", func(t *testing.T) {
		want := &api.PublicSettingsResponse{AppName: "sentinel app", Issuer: "https://issuer.example"}
		got, ok := SettingsFrom(WithSettings(ctx, want))
		require.True(t, ok)
		assert.Same(t, want, got)
	})
}

func TestReqctx_EmptyContextHoldsNothing(t *testing.T) {
	for name, ok := range present(context.Background()) {
		assert.False(t, ok, "%s read from an empty context", name)
	}
}

// A nil *api.PublicSettingsResponse stored under the key is still a value of the asserted type, so
// a bare checked assertion would answer true and hand the caller a pointer it cannot dereference.
func TestReqctx_SettingsFromRefusesTypedNil(t *testing.T) {
	got, ok := SettingsFrom(WithSettings(context.Background(), nil))
	assert.False(t, ok)
	assert.Nil(t, got)
}

// An empty token set is still one: the scope check decides what it grants, which is nothing, and a
// reader that took the zero value for absence would send an authenticated-but-empty session down
// the unauthenticated path without saying so.
func TestReqctx_AnEmptyTokenSetIsPresent(t *testing.T) {
	got, ok := JwtInfoFrom(WithJwtInfo(context.Background(), oauthclient.JwtInfo{}))
	assert.True(t, ok)
	assert.Equal(t, oauthclient.JwtInfo{}, got)
}

func TestReqctx_EachWriterSetsOnlyItsOwnValue(t *testing.T) {
	ctx := context.Background()

	cases := map[string]context.Context{
		"jwtInfo":  WithJwtInfo(ctx, oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "a"}}),
		"settings": WithSettings(ctx, &api.PublicSettingsResponse{}),
	}

	for written, writtenCtx := range cases {
		t.Run(written, func(t *testing.T) {
			for name, ok := range present(writtenCtx) {
				assert.Equal(t, name == written, ok, "after writing %s, %s present = %v", written, name, ok)
			}
		})
	}
}

func TestReqctx_SentinelsMatchThroughAWrap(t *testing.T) {
	require.ErrorIs(t, errs.Wrap(ErrNoJwtInfo, "x"), ErrNoJwtInfo)
	require.ErrorIs(t, errs.Wrap(ErrNoSettings, "x"), ErrNoSettings)
	assert.NotErrorIs(t, ErrNoJwtInfo, ErrNoSettings, "the two sentinels are one error")
}

// Every authenticated request carries both values, written by two middlewares in turn, so each key
// must be its own: two keys comparing equal would let the later writer hide the earlier value, and
// its reader would answer absent on a request that has it. Both orders, because which one hides
// depends on which is written last.
func TestReqctx_BothValuesTravelTogether(t *testing.T) {
	jwtInfo := oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: "a"}}
	settings := &api.PublicSettingsResponse{AppName: "sentinel app"}

	orders := map[string]context.Context{
		"token set first": WithSettings(WithJwtInfo(context.Background(), jwtInfo), settings),
		"settings first":  WithJwtInfo(WithSettings(context.Background(), settings), jwtInfo),
	}

	for name, ctx := range orders {
		t.Run(name, func(t *testing.T) {
			gotJwtInfo, ok := JwtInfoFrom(ctx)
			require.True(t, ok, "token set hidden by the settings")
			assert.Equal(t, jwtInfo, gotJwtInfo)
			gotSettings, ok := SettingsFrom(ctx)
			require.True(t, ok, "settings hidden by the token set")
			assert.Same(t, settings, gotSettings)
		})
	}
}
