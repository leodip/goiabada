package reqctx

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// present reports which of the five values ctx carries, so a test can say which it expects.
func present(ctx context.Context) map[string]bool {
	_, settings := SettingsFrom(ctx)
	_, sessionIdentifier := SessionIdentifierFrom(ctx)
	_, bearer := BearerTokenFrom(ctx)
	_, validated := ValidatedTokenFrom(ctx)
	_, reservation := CredentialReservationFrom(ctx)
	return map[string]bool{
		"settings":          settings,
		"sessionIdentifier": sessionIdentifier,
		"bearer":            bearer,
		"validated":         validated,
		"reservation":       reservation,
	}
}

func TestReqctx_RoundTrip(t *testing.T) {
	ctx := context.Background()

	t.Run("settings", func(t *testing.T) {
		want := &record.Settings{Issuer: "https://issuer.example"}
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

	// The same pointer and not a copy: the rate limiter keeps the reservation it wrote and reads
	// the verdict off it after the handler returns, so a mark made through a copy is a failure
	// the limiter never charges.
	t.Run("credential reservation", func(t *testing.T) {
		want := &CredentialReservation{}
		got, ok := CredentialReservationFrom(WithCredentialReservation(ctx, want))
		require.True(t, ok)
		assert.Same(t, want, got)

		got.MarkFailed()
		assert.True(t, want.Failed(), "a mark through the reader is not seen by the writer's reservation")
	})
}

// A reservation starts unmarked, so a handler that never reaches its credential check leaves
// the slot to be dropped rather than charged, and a mark stays made.
func TestReqctx_CredentialReservationIsUnmarkedUntilMarked(t *testing.T) {
	res := &CredentialReservation{}
	assert.False(t, res.Failed())

	res.MarkFailed()
	assert.True(t, res.Failed())

	res.MarkFailed()
	assert.True(t, res.Failed())
}

func TestReqctx_EmptyContextHoldsNothing(t *testing.T) {
	for name, ok := range present(context.Background()) {
		assert.False(t, ok, "%s read from an empty context", name)
	}
}

// A nil *record.Settings stored under the key is still a value of the asserted type, so a bare
// checked assertion would answer true and hand the caller a pointer it cannot dereference.
func TestReqctx_SettingsFromRefusesTypedNil(t *testing.T) {
	got, ok := SettingsFrom(WithSettings(context.Background(), nil))
	assert.False(t, ok)
	assert.Nil(t, got)
}

// The reservation is a pointer for the same reason, and a caller that sees true marks it.
func TestReqctx_CredentialReservationFromRefusesTypedNil(t *testing.T) {
	got, ok := CredentialReservationFrom(WithCredentialReservation(context.Background(), nil))
	assert.False(t, ok)
	assert.Nil(t, got)
}

// The two token keys hold the same type, so a writer that used the other's key would still
// type-check and still read back as a token, from the wrong accessor.
func TestReqctx_EachWriterSetsOnlyItsOwnValue(t *testing.T) {
	ctx := context.Background()
	token := oauth.JwtToken{TokenBase64: "t"}

	cases := map[string]context.Context{
		"settings":          WithSettings(ctx, &record.Settings{}),
		"sessionIdentifier": WithSessionIdentifier(ctx, "session-1"),
		"bearer":            WithBearerToken(ctx, token),
		"validated":         WithValidatedToken(ctx, token),
		"reservation":       WithCredentialReservation(ctx, &CredentialReservation{}),
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
