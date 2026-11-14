package render

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/requestid"
)

// settingsUnavailablePage is everything settings_unavailable.html shows. The page is parsed alone,
// with no layout and no template functions, because every layout reads the settings this page
// answers the want of.
type settingsUnavailablePage struct {
	Lang           string
	Stylesheet     string
	Title          string
	Message        string
	RequestIDLabel string
	RequestID      string
}

// SettingsUnavailable answers a request the console cannot serve because it holds no settings from
// the auth server: the auth server did not answer, or answered without an issuer. It renders the
// page titleKey and messageKey name, at 500, in the request's language and the device's theme, and
// with no application name, which is one of the settings. Should that render fail too, the answer
// is the same sentences in plain text, the request id clipped as the error page's last resort
// clips it (#159, #617).
func (h *Renderer) SettingsUnavailable(w http.ResponseWriter, r *http.Request, titleKey, messageKey string) {
	ctx := r.Context()
	page := settingsUnavailablePage{
		Lang:           i18n.CatalogTag(ctx),
		Title:          i18n.T(ctx, titleKey),
		Message:        i18n.T(ctx, messageKey),
		RequestIDLabel: i18n.T(ctx, "adminconsole.error.request_id_label"),
		RequestID:      requestid.FromContext(ctx),
	}

	var buf bytes.Buffer
	stylesheet, err := h.assets.url("/static/main.css")
	if err == nil {
		page.Stylesheet = stylesheet
		var set *templateSet
		set, err = h.settingsUnavailableSet()
		if err == nil {
			err = set.templ.Execute(&buf, page)
		}
	}
	if err != nil {
		slog.ErrorContext(ctx, "unable to render the settings unavailable page", "error", err)
		http.Error(w, page.Title+". "+page.Message+" "+page.RequestIDLabel+" "+logging.FieldForLog(page.RequestID),
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = buf.WriteTo(w)
}

// settingsUnavailableSet is settings_unavailable.html, parsed the first time it is drawn and kept, as
// every page's set is.
func (h *Renderer) settingsUnavailableSet() (*templateSet, error) {
	return h.sets.get(settingsUnavailableTemplate, func() (*templateSet, error) {
		templ, err := template.ParseFS(h.templateFS, settingsUnavailableTemplate)
		if err != nil {
			return nil, errs.Wrap(err, "unable to parse the settings unavailable page")
		}
		return &templateSet{templ: templ}, nil
	})
}

// settingsUnavailableTemplate is the page SettingsUnavailable draws, its file and its key among the
// sets.
const settingsUnavailableTemplate = "settings_unavailable.html"
