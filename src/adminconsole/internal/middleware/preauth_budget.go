package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Two bounds on the anonymous session row this package's arms can write, both generous
// rather than tuned: a real browser starting a sign-in does not come back twice a second,
// and no page this console renders approaches half a kilobyte of path and query (#620).
const (
	// DefaultPreAuthBudgetPerAddress is how many anonymous session writes one address may
	// cost inside DefaultPreAuthBudgetWindow. A browser that has not signed in starts at
	// most one sign-in per page it opens; a hundred and twenty a minute is an office
	// behind one address, not one browser.
	DefaultPreAuthBudgetPerAddress = 120

	// DefaultPreAuthBudgetWindow is how long one address's slice of the budget lasts.
	// A minute is short enough that a flooder's rows arrive at a rate the reaper can
	// hold, and long enough that no human sign-in has ever crossed a window boundary
	// mid-thought.
	DefaultPreAuthBudgetWindow = time.Minute

	// redirectBackMaxLen bounds the path and query the sign-in arm parks in the session as
	// its return target. The request line is bounded only by the console's 64 KiB header
	// limit, and the row the target is sealed into would otherwise track its length; no
	// return target a page of this console produces approaches the bound (#620).
	redirectBackMaxLen = 512
)

// preAuthAddressCap bounds how many distinct addresses one budget tracks. RealIP is what
// names an address, and only a proxy this console is told to trust lets a caller choose
// its own name, but a budget that tracked every name a request could carry would itself
// be the thing an unauthenticated request grows. Past this many live windows the budget
// refuses new addresses until the sweep empties the map, which fails closed: an address
// refused by the cap is one that was never going to sign in (#620).
const preAuthAddressCap = 1 << 16

// PreAuthBudget is the console's admission limit on the writes that create a
// pre-authentication session row: the sign-in redirect an anonymous /admin or /account
// request starts, and the session-ended route's save (#620). Both write through the auth
// server's /api/v1/sessions, arriving there from the console's own address with the
// console's bearer token, so no tier at the auth server can tell one console caller from
// another — the budget belongs here, before the write, keyed through the RealIP
// middleware the request has already passed when either arm runs.
//
// It is a fixed window per address, in this process only. No row is spent on a settings
// read or a bearer verification to keep it, which is the same reasoning the auth server's
// own authorize tier answers for its rows: what an anonymous request may cost is decided
// before it costs anything (#504, #620).
type PreAuthBudget struct {
	perAddress int
	window     time.Duration

	mu      sync.Mutex
	live    map[string]preAuthWindow
	sweptAt time.Time

	// now is the clock, replaceable by this package's tests the way sessiontest's is.
	now func() time.Time
}

// preAuthWindow is one address's slice of the budget: when its window opened, and how
// many writes it has taken from it.
type preAuthWindow struct {
	opened time.Time
	taken  int
}

// NewPreAuthBudget builds a budget admitting perAddress anonymous session writes per
// address per window.
func NewPreAuthBudget(perAddress int, window time.Duration) *PreAuthBudget {
	return &PreAuthBudget{
		perAddress: perAddress,
		window:     window,
		live:       map[string]preAuthWindow{},
		now:        time.Now,
	}
}

// Allow reports whether the request's address may still write one anonymous session row
// this window, and takes one from the budget when it answers yes. The address is
// r.RemoteAddr as the RealIP middleware left it, the same evidence the console's other
// per-request decisions read.
func (b *PreAuthBudget) Allow(r *http.Request) bool {
	addr := r.RemoteAddr

	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.sweep(now)

	use, ok := b.live[addr]
	if !ok {
		if len(b.live) >= preAuthAddressCap {
			return false
		}
		use = preAuthWindow{opened: now}
	}
	if now.Sub(use.opened) >= b.window {
		// The window is anchored on the address's first write rather than truncated to
		// the clock, so a budget resets exactly one window after the address started
		// rather than at an alignment a client can time its way past.
		use = preAuthWindow{opened: now}
	}
	if use.taken >= b.perAddress {
		return false
	}
	use.taken++
	b.live[addr] = use
	return true
}

// sweep drops the windows that have ended. It runs inside Allow at most once per window,
// so the map only ever holds live windows without a goroutine of its own to keep it that
// way.
func (b *PreAuthBudget) sweep(now time.Time) {
	if now.Sub(b.sweptAt) < b.window {
		return
	}
	for addr, use := range b.live {
		if now.Sub(use.opened) >= b.window {
			delete(b.live, addr)
		}
	}
	b.sweptAt = now
}

// Handler is the route-mounted form, for the one arm outside the JWT middleware: the
// session-ended route. Every request the route serves takes one from its address's
// budget — a signed-out administrator's one visit costs the same as an anonymous one,
// which is what keeps the budget honest about what the route writes (#620).
func (b *PreAuthBudget) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !b.Allow(r) {
				b.Refuse(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Refuse answers a request Allow refused, and is the one refusal both arms share: 429
// with Retry-After, and nothing else written. No session row, which is the point; and no
// address in the record, because the request logger already holds the request line and
// identifiers are kept out of logs by allowlist rather than by exception (#219).
func (b *PreAuthBudget) Refuse(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	use, ok := b.live[r.RemoteAddr]
	b.mu.Unlock()

	retryAfter := b.window
	if ok {
		if elapsed := b.now().Sub(use.opened); elapsed < b.window {
			retryAfter = b.window - elapsed
		}
	}
	// Rounded up: Retry-After is whole seconds, and a window that ends a fraction
	// before the answer's second does not re-admit a client a fraction early.
	seconds := int((retryAfter + time.Second - 1) / time.Second)

	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	slog.WarnContext(r.Context(),
		"the per-address budget on the console's anonymous session rows refused a request",
		"retry_after", seconds)
	http.Error(w, "Too many requests.", http.StatusTooManyRequests)
}
