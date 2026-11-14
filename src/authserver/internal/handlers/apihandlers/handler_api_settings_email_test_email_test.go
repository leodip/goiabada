package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/web"
)

// testEmailBrands answers the default brand, on the plum theme, and a client's brand on the sunny
// theme to a page that names a client, which an administrator's request never does.
type testEmailBrands struct {
	defaultBrand *record.Brand
	clientReads  int
}

func (b *testEmailBrands) GetDefaultBrand(context.Context, *sql.Tx) (*record.Brand, error) {
	return b.defaultBrand, nil
}

func (b *testEmailBrands) GetClientPageBrand(context.Context, *sql.Tx, string) (*record.Brand, error) {
	b.clientReads++
	brand := record.NewBrand("Client", record.BrandAppearanceLight, "sunny")
	return &brand, nil
}

func (b *testEmailBrands) GetBrandAssetsByIds(context.Context, *sql.Tx, []int64) ([]record.BrandAsset, error) {
	return nil, nil
}

// testEmailRenderer draws emails from the built-in templates, in a default brand with no logo.
func testEmailRenderer() PageRenderer {
	return render.New(web.TemplateFS(), web.StaticFS(), nil)
}

// The test email of Admin, Email is an email like the others (#817 decision 8): drawn through the
// email layout in the default brand, as an administrator's action is, with its subject and body in
// the language the administrator is answered in, naming the app. It no longer writes out the date,
// which the message's Date header says.
func TestHandleSettingsEmailSendTestPost_TheTestEmailIsDrawnInTheDefaultBrandInTheAdministratorsLanguage(t *testing.T) {
	for _, tc := range []struct {
		acceptLanguage, lang, subject, opening string
	}{
		{"", "en", "Acme Portal - test email", "This is a test email from Acme Portal."},
		{"de-DE", "de", "Acme Portal – Test-E-Mail", "Dies ist eine Test-E-Mail von Acme Portal."},
		{"es", "es", "Acme Portal - correo de prueba", "Este es un correo de prueba enviado por Acme Portal."},
		{"fr-CA", "fr", "Acme Portal - e-mail de test", "Ceci est un e-mail de test envoyé par Acme Portal."},
		{"it", "it", "Acme Portal - email di prova", "Questa è un’email di prova inviata da Acme Portal."},
		{"pt-BR", "pt-BR", "Acme Portal - e-mail de teste", "Este é um e-mail de teste enviado por Acme Portal."},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			plum := record.NewBrand("Default", record.BrandAppearanceLight, "plum")
			brands := &testEmailBrands{defaultBrand: &plum}
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			var sent *emaildelivery.SendEmailInput
			emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { sent = args.Get(2).(*emaildelivery.SendEmailInput) }).
				Return(emaildelivery.SendResult{Encrypted: true}, nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventSentTestEmail, mock.Anything).Return().Once()

			r := sendTestEmailRequest(t, &record.Settings{SMTPEnabled: true, AppName: "Acme Portal"})
			rr := httptest.NewRecorder()
			HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), emailSender,
				render.New(web.TemplateFS(), web.StaticFS(), brands), auditLogger).
				ServeHTTP(rr, inRequestLanguage(r, tc.acceptLanguage))

			// The request and its answer are as before.
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.JSONEq(t, `{"success":true,"encrypted":true}`, rr.Body.String())
			require.NotNil(t, sent)
			assert.Equal(t, "admin@example.com", sent.To)
			assert.Equal(t, tc.subject, sent.Subject)

			doc, err := goquery.NewDocumentFromReader(strings.NewReader(sent.HtmlBody))
			require.NoError(t, err)
			assert.Equal(t, tc.lang, doc.Find("html").AttrOr("lang", ""), "the body is in the administrator's language")
			assert.Equal(t, tc.subject, doc.Find("title").Text(), "the title is the subject (#818)")
			assert.Equal(t, tc.opening, strings.TrimSpace(doc.Find("main p").First().Text()))
			// Drawn through the email layout, on its card, in the default brand's plum light colors.
			assert.Contains(t, doc.Find("body").AttrOr("style", ""), "background-color: #f6f4f7;")
			assert.Contains(t, doc.Find("body table table").First().AttrOr("style", ""), "background-color: #ffffff;")
			assert.Equal(t, "Acme Portal", strings.TrimSpace(doc.Find("body table table td > p").First().Text()),
				"the app name is drawn above the body, the default brand having no logo")
			assert.Zero(t, brands.clientReads, "an administrator's email reads no client's brand")
			assert.NotContains(t, sent.HtmlBody, time.Now().Format("2006"), "the date is the Date header's, not the body's")
		})
	}
}

// A test email that cannot be drawn, as from a templates directory that has no email layout, is a
// fault of the server: nothing is sent, and no test email is audited.
func TestHandleSettingsEmailSendTestPost_ATestEmailThatCannotBeDrawnIsNotSent(t *testing.T) {
	noLayout := fstest.MapFS{"layouts/auth_layout.html": {Data: []byte("a page layout")}}

	rr := httptest.NewRecorder()
	HandleSettingsEmailSendTestPost(accountvalidation.NewEmailValidator(nil), accounthandlersmocks.NewEmailSender(t),
		render.New(noLayout, web.StaticFS(), nil), handlersmocks.NewAuditLogger(t)).
		ServeHTTP(rr, sendTestEmailRequest(t, &record.Settings{SMTPEnabled: true}))

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
}
