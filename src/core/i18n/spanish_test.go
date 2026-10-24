package i18n

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpanish_RegionalPreferencesAndRefusals(t *testing.T) {
	for _, tag := range []string{"es", "es-ES", "es-MX", "es-419", "es-AR"} {
		t.Run(tag, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, tag)
			assert.Equal(t, "es", CatalogTag(ctx))
			assert.Equal(t, "Iniciar sesión", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "La dirección de correo electrónico no puede superar los 254 caracteres.",
				NewLocalizedError(ErrCodeEmailTooLong, map[string]any{"max": 254}).Localize(ctx))
			assert.Equal(t, "{{count}} resultados", Raw(ctx, "js.combobox.results"))
		})
	}
}

func TestSpanish_OverridesWinAndUnspecifiedKeysKeepSpanish(t *testing.T) {
	b, err := loadWithOverrides(t, map[string]string{
		"active.es.toml": `"auth.pwd.title" = "Acceder a Acme"
"auth.pwd.email_label" = ""
`,
	})
	require.NoError(t, err)
	ctx := ctxForBundle(b, "es-MX")
	assert.Equal(t, "Acceder a Acme", T(ctx, "auth.pwd.title"))
	assert.Equal(t, "Contraseña", T(ctx, "auth.pwd.password_label"))
	assert.Equal(t, "Email", T(ctx, "auth.pwd.email_label"), "an explicitly empty override still requests English")
}
