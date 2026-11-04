package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A recovery-code notice's advice fits the codes left (#737): with none left there is nothing to
// run out of, so it tells a user who still has the app to make a new set now; with some left it
// says to make one before they run out. Each built-in language says the same.
func TestRecoveryCodeUsedNotice_AdviceFitsTheCodesLeft(t *testing.T) {
	for _, tc := range []struct {
		locale   string
		noneLeft string
		someLeft string
	}{
		{"en", "get a new set of recovery codes there now, so you can still sign in if you lose it.",
			"you can get a new set of recovery codes there before you run out."},
		{"de", "erstellen Sie dort jetzt einen neuen Satz Wiederherstellungscodes, damit Sie sich weiterhin anmelden können, falls Sie sie verlieren.",
			"können Sie dort einen neuen Satz Wiederherstellungscodes erstellen, bevor Ihnen die Codes ausgehen."},
		{"es", "obtén allí ahora un nuevo conjunto de códigos de recuperación, para poder iniciar sesión si la pierdes.",
			"puedes obtener allí un nuevo conjunto de códigos de recuperación antes de que se te acaben."},
		{"fr", "obtenez dès maintenant un nouveau jeu de codes de récupération dans les paramètres de votre compte, pour pouvoir vous connecter si vous la perdez.",
			"vous pouvez obtenir un nouveau jeu de codes de récupération dans les paramètres de votre compte avant d’en manquer."},
		{"it", "ottieni subito lì un nuovo set di codici di recupero, per poter accedere se la perdi.",
			"puoi ottenere lì un nuovo set di codici di recupero prima di esaurirli."},
		{"pt-BR", "gere lá agora um novo conjunto de códigos de recuperação, para poder entrar se perdê-lo.",
			"pode gerar lá um novo conjunto de códigos de recuperação antes que eles acabem."}, //nolint:misspell // the pt-BR template's text: "eles" is Portuguese, not a misspelling
	} {
		for _, remaining := range []int{0, 3} {
			t.Run(tc.locale, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "Acme"}))
				r = r.WithContext(i18n.WithLocale(r.Context(), true, tc.locale, "en"))
				buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(r,
					"layouts/email_layout.html", "emails/email_recovery_code_used.html",
					map[string]interface{}{"name": "Ana", "remaining": remaining})
				require.NoError(t, err)
				body := buf.String()
				if remaining == 0 {
					assert.Contains(t, body, tc.noneLeft)
					assert.NotContains(t, body, tc.someLeft, "with no codes left there is nothing to run out of")
				} else {
					assert.Contains(t, body, tc.someLeft)
					assert.NotContains(t, body, tc.noneLeft)
				}
			})
		}
	}
}
