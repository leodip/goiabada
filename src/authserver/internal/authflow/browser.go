package authflow

import "github.com/leodip/goiabada/authserver/internal/ceremony"

// stepSaver is the browser-session write a step makes to move its ceremony on: the auth context
// saved with its next state. The save lands only while the browser session still holds the step's
// ceremony, and otherwise answers ceremony.ErrCeremonyReplaced and writes nothing (#579). The
// handler's per-request adapter satisfies it, over ceremony.Store.
type stepSaver interface {
	SaveAuthContext(authContext *ceremony.AuthContext) error
}

// ceremonyClearer is the browser-session write that ends a ceremony: its auth context cleared, only
// while the browser session still holds it, and otherwise ceremony.ErrCeremonyReplaced with nothing
// written (#579). The handler's per-request adapter satisfies it, over ceremony.Store.
type ceremonyClearer interface {
	ClearAuthContext(ceremonyId string) error
}
