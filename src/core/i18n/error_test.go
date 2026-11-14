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
	assert.Equal(t, "Falha na autenticação.", le.Localize(ctxFor("pt-BR")))
}

// A language whose catalog misses the code renders the English message, not the code.
func TestLocalizedError_LocalizeFallsThroughToEnglishWhenLocaleMissesKey(t *testing.T) {
	b := builtInWithout(t, "pt-BR", ErrCodeLoginAuthFailed)

	le := NewLocalizedError(ErrCodeLoginAuthFailed, nil)
	assert.Equal(t, "Authentication failed.", le.Localize(ctxForBundle(b, "pt-BR")))
}

func TestLocalizedError_ArgsSubstituteInEveryRendering(t *testing.T) {
	// 15 production constructors pass Args; all three renderings must
	// substitute them, in the resolved locale and in English.
	le := NewLocalizedError(ErrCodeEmailTooLong, map[string]any{"max": 60})
	const english = "The email address cannot exceed a maximum length of 60 characters."
	assert.Equal(t, english, le.EnglishFallback())
	assert.Equal(t, english, le.Error())
	assert.Equal(t, "O endereço de e-mail não pode ter mais que 60 caracteres.",
		le.Localize(ctxFor("pt-BR")))
}

func TestLocalizedError_UnknownCodeReturnsCodeString(t *testing.T) {
	le := NewLocalizedError("nope.unknown.code", nil)
	// Both EnglishFallback and Localize should return the code string when
	// missing from every catalog (visible-miss policy).
	assert.Equal(t, "nope.unknown.code", le.EnglishFallback())
	assert.Equal(t, "nope.unknown.code", le.Localize(context.Background()))
}
