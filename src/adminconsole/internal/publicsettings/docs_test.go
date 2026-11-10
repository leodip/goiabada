package publicsettings

// The admin console's client, as the Clients page describes it, held to the cache's lifetime
// (#812).
//
// The page tells an administrator how soon a brand given to the console's own client through the
// admin API reaches the console's pages, which is this cache's TTL: a page promising sooner sends
// them looking for a fault that isn't there.
//
// It reads the page, and nothing else.

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

func TestDocs_TheConsolesClientSaysHowSoonABrandChangeShows(t *testing.T) {
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), "site/src/content/docs/concepts/clients.mdx",
		"## The admin console's client",
		[]string{fmt.Sprintf("within %d seconds", int(DefaultTTL.Seconds()))}, nil)
}
