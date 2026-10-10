package web

import (
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestServedPages_HandNoDataToAnHTMLParser holds every page and script this server serves to the
// rule core/guard.AssertNoHTMLSinks carries with its reasoning (#120): no value reaches the document
// through an HTML or JavaScript parser. It covers what #105's check on the redirect URI and web
// origin cells held, both the write and the read side, on every page rather than two.
//
// htmlSinkAllowances names the one site that still does it, by file and text so it does not drift:
// the dialog's markup branch, which renders what dialogMarkup or dialogMarkupFormat built, whose
// markup is the catalog's and whose values are escaped. It is the one audited exception. The
// dialog's plain branch shows its message as text, and the table cells, links, buttons and banners
// that were listed here write their data as text; an entry left behind after its site is fixed
// fails this test.
func TestServedPages_HandNoDataToAnHTMLParser(t *testing.T) {
	guard.AssertNoHTMLSinks(t, htmlSinkAllowances, templateFS, withoutVendored{staticFS})
}

// withoutVendored is the static tree with static/vendor hidden: the libraries there are third-party
// code this repository serves but does not write, held instead to the digests versions.yaml pins
// (TestVendoredLibraries_AreTheFilesVersionsYAMLPins) and updated only by version-manager.sh (#542).
type withoutVendored struct{ fs.FS }

func (f withoutVendored) Open(name string) (fs.File, error) {
	if isVendored(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return f.FS.Open(name)
}

func (f withoutVendored) ReadDir(name string) ([]fs.DirEntry, error) {
	if isVendored(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	entries, err := fs.ReadDir(f.FS, name)
	if err != nil {
		return nil, err
	}
	var kept []fs.DirEntry
	for _, e := range entries {
		if !isVendored(path.Join(name, e.Name())) {
			kept = append(kept, e)
		}
	}
	return kept, nil
}

func isVendored(name string) bool {
	return name == "static/vendor" || strings.HasPrefix(name, "static/vendor/")
}

var htmlSinkAllowances = []guard.HTMLSinkAllowance{
	{File: "static/utils.js", Text: `messageElement.innerHTML = message.html;`},
}
