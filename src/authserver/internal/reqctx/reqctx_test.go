package reqctx

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// present reports which of the four values ctx carries, so a test can say which it expects.
func present(ctx context.Context) map[string]bool {
	_, settings := SettingsFrom(ctx)
	_, sessionIdentifier := SessionIdentifierFrom(ctx)
	_, bearer := BearerTokenFrom(ctx)
	_, validated := ValidatedTokenFrom(ctx)
	return map[string]bool{
		"settings":          settings,
		"sessionIdentifier": sessionIdentifier,
		"bearer":            bearer,
		"validated":         validated,
	}
}

func TestReqctx_RoundTrip(t *testing.T) {
	ctx := context.Background()

	t.Run("settings", func(t *testing.T) {
		want := &models.Settings{Issuer: "https://issuer.example"}
		got, ok := SettingsFrom(WithSettings(ctx, want))
		require.True(t, ok)
		assert.Same(t, want, got)
	})

	t.Run("session identifier", func(t *testing.T) {
		got, ok := SessionIdentifierFrom(WithSessionIdentifier(ctx, "session-1"))
		require.True(t, ok)
		assert.Equal(t, "session-1", got)
	})

	t.Run("bearer token", func(t *testing.T) {
		want := oauth.JwtToken{TokenBase64: "bearer", Claims: jwt.MapClaims{"sub": "user-1"}}
		got, ok := BearerTokenFrom(WithBearerToken(ctx, want))
		require.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("validated token", func(t *testing.T) {
		want := oauth.JwtToken{TokenBase64: "validated", Claims: jwt.MapClaims{"sub": "user-2"}}
		got, ok := ValidatedTokenFrom(WithValidatedToken(ctx, want))
		require.True(t, ok)
		assert.Equal(t, want, got)
	})
}

func TestReqctx_EmptyContextHoldsNothing(t *testing.T) {
	for name, ok := range present(context.Background()) {
		assert.False(t, ok, "%s read from an empty context", name)
	}
}

// A nil *models.Settings stored under the key is still a value of the asserted type, so a bare
// checked assertion would answer true and hand the caller a pointer it cannot dereference.
func TestReqctx_SettingsFromRefusesTypedNil(t *testing.T) {
	got, ok := SettingsFrom(WithSettings(context.Background(), nil))
	assert.False(t, ok)
	assert.Nil(t, got)
}

// The two token keys hold the same type, so a writer that used the other's key would still
// type-check and still read back as a token, from the wrong accessor.
func TestReqctx_EachWriterSetsOnlyItsOwnValue(t *testing.T) {
	ctx := context.Background()
	token := oauth.JwtToken{TokenBase64: "t"}

	cases := map[string]context.Context{
		"settings":          WithSettings(ctx, &models.Settings{}),
		"sessionIdentifier": WithSessionIdentifier(ctx, "session-1"),
		"bearer":            WithBearerToken(ctx, token),
		"validated":         WithValidatedToken(ctx, token),
	}

	for written, writtenCtx := range cases {
		t.Run(written, func(t *testing.T) {
			for name, ok := range present(writtenCtx) {
				assert.Equal(t, name == written, ok, "after writing %s, %s present = %v", written, name, ok)
			}
		})
	}
}

func TestReqctx_ErrNoSettingsMatchesThroughAWrap(t *testing.T) {
	assert.True(t, errors.Is(errs.Wrap(ErrNoSettings, "x"), ErrNoSettings))
}
