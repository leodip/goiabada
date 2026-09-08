package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRaw_PreservesPlaceholdersAndLocalizes(t *testing.T) {
	_, err := LoadBundle()
	require.NoError(t, err)

	en := ctxFor("en")
	pt := ctxFor("pt-BR")

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

	// Miss policy: an unknown key returns the key itself.
	assert.Equal(t, "no.such.key.zzz", Raw(en, "no.such.key.zzz"))
}

// TestRaw_ResolvesTheLocaleTheSameWayTAsDoes is the case that fails under the
// old Raw, which indexed the catalogs by the request's primary tag string:
// "pt" and "pt-PT" matched no catalog, so the page rendered in pt-BR while the
// JS bootstrap strings came back in English (#273).
func TestRaw_ResolvesTheLocaleTheSameWayTAsDoes(t *testing.T) {
	for _, tc := range []struct {
		acceptLanguage string
		wantRaw        string
		wantT          string
	}{
		{"pt-BR", "Enviar", "Entrar"},
		{"pt", "Enviar", "Entrar"},
		{"pt-PT", "Enviar", "Entrar"},
		// The primary tag is fr-FR, which matches no catalog, while the
		// matcher takes the second range: the page is pt-BR, so the JS
		// strings must be too.
		{"fr-FR,pt;q=0.8", "Enviar", "Entrar"},
		// English outranks pt-BR here, and both surfaces must say so.
		{"en-US,pt-BR;q=0.5", "Upload", "Login"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
		req.Header.Set("Accept-Language", tc.acceptLanguage)

		var gotRaw, gotT string
		MiddlewareLocale(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			gotRaw = Raw(r.Context(), "js.image_upload.upload_button")
			gotT = T(r.Context(), "auth.pwd.title")
		})).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equalf(t, tc.wantRaw, gotRaw, "Raw for Accept-Language %q", tc.acceptLanguage)
		assert.Equalf(t, tc.wantT, gotT, "T for Accept-Language %q", tc.acceptLanguage)
	}
}

func TestRaw_NoLocalizerOnContextResolvesFromLocaleTag(t *testing.T) {
	// EmailContext and bare test contexts carry the tag but no translator.
	ctx := context.WithValue(context.Background(), ctxKeyLocaleTag, "pt-BR")
	assert.Equal(t, "Enviar", Raw(ctx, "js.image_upload.upload_button"))
}
