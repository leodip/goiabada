package i18n

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRaw_PreservesPlaceholdersAndLocalizes(t *testing.T) {
	_, err := LoadBundle()
	require.NoError(t, err)

	en := attachLocale(context.Background(), defaultBundle.english, "en", false)
	pt := attachLocale(context.Background(), defaultBundle.english, "pt-BR", false)

	// A parameterized JS key: the {{detail}} placeholder must survive verbatim
	// for client-side tFormat(). T() leaks the key here; Raw() must not.
	raw := Raw(en, "js.error.unexpected")
	assert.Contains(t, raw, "{{detail}}", "Raw must preserve the client-side placeholder")
	assert.NotEqual(t, "js.error.unexpected", raw, "Raw must not leak the key")
	assert.Equal(t, "js.error.unexpected", T(en, "js.error.unexpected"),
		"documents why Raw exists: T() leaks the key for {{param}} messages")

	// Localizes like T for plain (non-parameterized) keys.
	assert.Equal(t, "Enviar", Raw(pt, "js.image_upload.upload_button"))
	assert.NotEmpty(t, Raw(en, "js.image_upload.upload_button"))

	// pt-BR falls back to English when a key is absent only in pt-BR — but the
	// parity test guarantees that shouldn't happen; here just assert the miss
	// policy: an unknown key returns the key itself.
	assert.Equal(t, "no.such.key.zzz", Raw(en, "no.such.key.zzz"))
}
