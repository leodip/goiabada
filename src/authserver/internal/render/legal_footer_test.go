package render

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// footerFS is a template set whose every layout writes the footer's links, so a test reads which
// layouts were given them.
var footerFS = fstest.MapFS{
	"layouts/auth_layout.html":    {Data: []byte(`{{template "body" .}}{{range .legalFooter}}[{{.ShortName}}:{{.Title}}]{{end}}`)},
	"layouts/no_menu_layout.html": {Data: []byte(`{{template "body" .}}{{range .legalFooter}}[{{.ShortName}}:{{.Title}}]{{end}}`)},
	"layouts/email_layout.html":   {Data: []byte(`{{template "body" .}}{{range .legalFooter}}[{{.ShortName}}:{{.Title}}]{{end}}`)},
	"page.html":                   {Data: []byte(`{{define "body"}}page {{end}}`)},
}

// footerFrom answers the all-apps documents, plus "shop-terms" for the client "shop", and records
// each client it was asked for.
func footerFrom(asked *[]string) LegalFooter {
	return func(_ context.Context, clientIdentifier string) ([]LegalDocumentLink, error) {
		*asked = append(*asked, clientIdentifier)
		links := []LegalDocumentLink{{Title: "Privacy notice", ShortName: "privacy"}}
		if clientIdentifier == "shop" {
			links = append(links, LegalDocumentLink{Title: "Shop terms", ShortName: "shop-terms"})
		}
		return links, nil
	}
}

func renderFooterPage(t *testing.T, h *Renderer, layout string, data map[string]interface{}) string {
	t.Helper()
	buf, err := h.RenderTemplateToBuffer(newRequest(http.MethodGet, "/", nil), layout, "/page.html", data)
	require.NoError(t, err)
	return buf.String()
}

func TestLegalFooter_TheSignInLayoutsLinkTheAllAppsDocumentsAndThePagesApp(t *testing.T) {
	var asked []string
	h := New(footerFS, nil).WithLegalFooter(footerFrom(&asked))

	for _, layout := range []string{"/layouts/auth_layout.html", "/layouts/no_menu_layout.html"} {
		asked = nil
		assert.Equal(t, "page [privacy:Privacy notice]", renderFooterPage(t, h, layout, map[string]interface{}{}),
			"a page no app is behind")
		assert.Equal(t, "page [privacy:Privacy notice][shop-terms:Shop terms]",
			renderFooterPage(t, h, layout, map[string]interface{}{LegalFooterClient: "shop"}),
			"a page of a sign-in for the app")
		assert.Equal(t, []string{"", "shop"}, asked)
	}
}

func TestLegalFooter_OtherLayoutsAndARendererWithoutItDrawNone(t *testing.T) {
	var asked []string
	h := New(footerFS, nil).WithLegalFooter(footerFrom(&asked))
	assert.Equal(t, "page ", renderFooterPage(t, h, "/layouts/email_layout.html", map[string]interface{}{}))
	assert.Empty(t, asked, "an email is not a sign-in page")

	assert.Equal(t, "page ", renderFooterPage(t, New(footerFS, nil), "/layouts/auth_layout.html", map[string]interface{}{}))
}

// A failed read draws the page without its footer and logs the failure: a sign-in page, or the
// error page, is not failed over its footer.
func TestLegalFooter_AFailedReadDrawsThePageWithoutItAndLogs(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	failure := errors.New("database down")
	h := New(footerFS, nil).WithLegalFooter(func(context.Context, string) ([]LegalDocumentLink, error) {
		return nil, failure
	})

	assert.Equal(t, "page ", renderFooterPage(t, h, "/layouts/auth_layout.html", map[string]interface{}{}))
	var logged []string
	for _, record := range logs.Records() {
		if record.Level == slog.LevelError {
			logged = append(logged, record.Message)
			require.ErrorIs(t, record.Attrs["error"].(error), failure)
		}
	}
	assert.Equal(t, []string{"unable to read the legal documents the footer links"}, logged)
}
