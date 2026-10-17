package guard

import (
	"strings"

	"github.com/leodip/goiabada/core/docsreader"
)

// AssertSectionSays holds one section of a docs page to what it must say and what it must not: one
// failure per text in present the section does not hold verbatim, one per text in absent it holds,
// and a stop for a page or section docsreader.Section does not find, so a check that read nothing
// cannot pass as one that did. The section is read as docsreader.Section reads it, from its heading
// to the next heading of the same level or above outside a code fence.
//
// Every docs test that quotes the code's own text on a page holds it through this one check, which
// is why it takes a Reporter rather than a *testing.T: the auth server's docs guards in handlers,
// authflow, protocolvalidation and apihandlers each spelled it once, and the copy authflow carried
// had no fixture of its own (#584). It is here rather than in core/docsreader because it reports,
// and docsreader stays a leaf the setup wizard's tests can reach (#500).
func AssertSectionSays(r Reporter, root, page, heading string, present, absent []string) {
	r.Helper()
	text, err := docsreader.Section(root, page, heading)
	if err != nil {
		r.Fatalf("%v", err)
		return
	}
	for _, want := range present {
		if !strings.Contains(text, want) {
			r.Errorf("%s: %s does not say %q", page, heading, want)
		}
	}
	for _, refused := range absent {
		if strings.Contains(text, refused) {
			r.Errorf("%s: %s says %q", page, heading, refused)
		}
	}
}
