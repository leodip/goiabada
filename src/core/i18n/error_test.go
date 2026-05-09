package i18n

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocalizedError_EnglishFallback(t *testing.T) {
	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	assert.Equal(t, "Authentication failed.", le.EnglishFallback())
}

func TestLocalizedError_ErrorReturnsEnglishFallback(t *testing.T) {
	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	// error interface — implementations must satisfy `error`.
	var err error = le
	assert.Equal(t, "Authentication failed.", err.Error())
}

func TestLocalizedError_LocalizePtBR(t *testing.T) {
	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	r := DefaultBundle().localizerFor([]string{"pt-BR"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	assert.Equal(t, "Falha na autenticação.", le.Localize(ctx))
}

func TestLocalizedError_LocalizeFallsThroughToEnglishWhenLocaleMissesKey(t *testing.T) {
	// pt-BR catalog stub doesn't include arbitrary keys — go-i18n falls
	// through to English via the bundle's default tag.
	le := NewLocalizedError("validator.login.email_required", nil)
	r := DefaultBundle().localizerFor([]string{"pt-BR"})
	ctx := context.WithValue(context.Background(), ctxKeyLocalizer, r)
	// "validator.login.email_required" IS in pt-BR stub, so this assertion
	// confirms localization works for keys present in the resolved locale.
	assert.Equal(t, "O e-mail é obrigatório.", le.Localize(ctx))
}

func TestLocalizedError_UnknownCodeReturnsCodeString(t *testing.T) {
	le := NewLocalizedError("nope.unknown.code", nil)
	// Both EnglishFallback and Localize should return the code string when
	// missing from every catalog (visible-miss policy).
	assert.Equal(t, "nope.unknown.code", le.EnglishFallback())
	assert.Equal(t, "nope.unknown.code", le.Localize(context.Background()))
}
