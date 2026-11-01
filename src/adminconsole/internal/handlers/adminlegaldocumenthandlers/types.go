package adminlegaldocumenthandlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/i18n"
)

// kindMustAccept is the admin API's spelling of the terms users must accept, beside a notice for
// information, which is shown and never accepted.
const kindMustAccept = "must_accept"

// appliesToAllApps is the admin API's spelling of a document that applies to all apps, beside
// selected_apps, the apps it lists.
const appliesToAllApps = "all_apps"

// legalDocumentErrorFields maps the refusals the new document form and the draft editor can meet
// to the field each is about. A publish refused for a draft with no text is about the text.
var legalDocumentErrorFields = map[string]string{
	i18n.ErrCodeLegalDocumentKindInvalid:       "kind",
	i18n.ErrCodeLegalDocumentShortNameRequired: "shortName",
	i18n.ErrCodeLegalDocumentShortNameInvalid:  "shortName",
	i18n.ErrCodeLegalDocumentShortNameTooLong:  "shortName",
	i18n.ErrCodeLegalDocumentShortNameInUse:    "shortName",
	i18n.ErrCodeLegalDocumentShortNameFixed:    "shortName",
	i18n.ErrCodeLegalDocumentTitleRequired:     "title",
	i18n.ErrCodeLegalDocumentTitleTooLong:      "title",
	i18n.ErrCodeLegalDocumentMarkdownTooLong:   "markdown",
	i18n.ErrCodeLegalDocumentDraftEmpty:        "markdown",
}

// The flashes a write leaves for the page it redirects to.
const (
	flashDraftSaved = "legalDocumentDraftSaved"
	flashPublished  = "legalDocumentPublished"
	flashRetired    = "legalDocumentRetired"
	flashRestored   = "legalDocumentRestored"
	flashAppsSaved  = "legalDocumentAppsSaved"
)

// legalDocumentId reads the {legalDocumentId} path value; false when it is not an id.
func legalDocumentId(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("legalDocumentId"), 10, 64)
	return id, err == nil && id > 0
}

// postedMarkdown is the text as the form posted it. A browser sends a textarea's line breaks as
// CRLF whatever the person typed, so they are stored as the newlines they stand for.
func postedMarkdown(r *http.Request) string {
	return strings.ReplaceAll(r.PostFormValue("markdown"), "\r\n", "\n")
}

// appChoice is one app the Applies to tab offers, ticked when the document lists it.
type appChoice struct {
	Id          int64
	Identifier  string
	Description string
	Selected    bool
}
