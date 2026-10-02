package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

// newAccountAt builds the two-tier account limiter on the fake clock, with budgets small
// enough to walk through by hand. The shape is production's: a tight tier with a short
// window and a backstop with a long one.
func newAccountAt(c *clock, tight, backstop int) *AccountLimiter {
	return NewAccountLimiter(
		newFailureAt(c, tight, 15*time.Minute),
		newFailureAt(c, backstop, time.Hour),
	)
}

// failAccount runs one wrong password through the account limiter and reports what Reserve
// answered.
func failAccount(a *AccountLimiter, network, account string) Refusal {
	networkKey := network + "|" + account
	refusal := a.Reserve(networkKey, account)
	if refusal == Admitted {
		a.Release(networkKey, account, true)
	}
	return refusal
}

func TestAccountLimiter_TheTightTierIsPerNetwork(t *testing.T) {
	c := newClock()
	a := newAccountAt(c, 2, 5)

	for i := 1; i <= 2; i++ {
		if got := failAccount(a, "203.0.113.7", "victim@example.com"); got != Admitted {
			t.Fatalf("failure #%d from one network: Reserve = %v, want Admitted", i, got)
		}
	}
	if got := failAccount(a, "203.0.113.7", "victim@example.com"); got != RefusedTight {
		t.Errorf("third failure from one network: Reserve = %v, want RefusedTight", got)
	}
	// The owner, elsewhere, is untouched by it: that is what the tight tier carrying the
	// network buys.
	if got := failAccount(a, "198.51.100.9", "victim@example.com"); got != Admitted {
		t.Errorf("a failure from a second network: Reserve = %v, want Admitted", got)
	}
}

func TestAccountLimiter_TheBackstopIsAccountWide(t *testing.T) {
	c := newClock()
	a := newAccountAt(c, 2, 5)

	// A success spends neither tier, however often.
	for i := 0; i < 20; i++ {
		networkKey := "203.0.113.7|victim@example.com"
		if got := a.Reserve(networkKey, "victim@example.com"); got != Admitted {
			t.Fatalf("successful check #%d: Reserve = %v, want Admitted", i+1, got)
		}
		a.Release(networkKey, "victim@example.com", false)
	}

	// One failure from each of five networks, so no tight bucket is near its budget and
	// only the backstop can refuse the sixth.
	for i := 0; i < 5; i++ {
		if got := failAccount(a, fmt.Sprintf("192.0.2.%d", i), "victim@example.com"); got != Admitted {
			t.Fatalf("failure from network %d: Reserve = %v, want Admitted", i, got)
		}
	}
	if got := failAccount(a, "192.0.2.99", "victim@example.com"); got != RefusedBackstop {
		t.Errorf("sixth failure, from a fresh network: Reserve = %v, want RefusedBackstop", got)
	}
	if got := failAccount(a, "192.0.2.99", "other@example.com"); got != Admitted {
		t.Errorf("a failure against another account: Reserve = %v, want Admitted", got)
	}
}

// TestAccountLimiter_ATightRefusalReservesNothingOnTheBackstop holds the other half of
// "both or neither": a caller the tight tier refuses never reaches the backstop, so it
// cannot spend the account-wide budget it was not admitted against.
func TestAccountLimiter_ATightRefusalReservesNothingOnTheBackstop(t *testing.T) {
	c := newClock()
	a := newAccountAt(c, 1, 2)

	if got := a.Reserve("203.0.113.7|victim@example.com", "victim@example.com"); got != Admitted {
		t.Fatalf("first reservation: Reserve = %v, want Admitted", got)
	}
	for i := 0; i < 10; i++ {
		if got := a.Reserve("203.0.113.7|victim@example.com", "victim@example.com"); got != RefusedTight {
			t.Fatalf("held tight slot, attempt %d: Reserve = %v, want RefusedTight", i+1, got)
		}
	}
	// One backstop slot is held; the second is still free.
	if got := a.Reserve("198.51.100.9|victim@example.com", "victim@example.com"); got != Admitted {
		t.Errorf("second network: Reserve = %v, want Admitted: the tight refusals above held "+
			"backstop slots they were never admitted against", got)
	}
}

// TestAccountLimiter_ABackstopRefusalHandsTheTightSlotBack pins decision 5 of #439. The
// tight tier is reserved first, so when the backstop then refuses, the tight slot is already
// held and has to be handed back. In-flight slots never decay, so a refusal that kept it
// would strand one slot on that (network, account) every time: an owner retrying from home
// while an attacker holds the backstop would lock themselves out of their own account from
// that network until the process restarted, long after the backstop's hour had passed.
func TestAccountLimiter_ABackstopRefusalHandsTheTightSlotBack(t *testing.T) {
	c := newClock()
	a := newAccountAt(c, 2, 3)

	// The attacker exhausts the backstop from networks of their own.
	for i := 0; i < 3; i++ {
		if got := failAccount(a, fmt.Sprintf("192.0.2.%d", i), "victim@example.com"); got != Admitted {
			t.Fatalf("setup: attacker failure %d: Reserve = %v, want Admitted", i+1, got)
		}
	}

	// The owner retries from home, five times the tight budget. Every attempt is the
	// backstop's refusal; one answered by the tight tier means an earlier refusal kept its
	// slot.
	const home = "203.0.113.7|victim@example.com"
	for i := 1; i <= 10; i++ {
		if got := a.Reserve(home, "victim@example.com"); got != RefusedBackstop {
			t.Fatalf("owner attempt %d while the backstop is exhausted: Reserve = %v, want "+
				"RefusedBackstop", i, got)
		}
	}

	// Past the backstop's window twice over, nothing recorded counts on either tier.
	c.advance(2 * time.Hour)
	if got := a.Reserve(home, "victim@example.com"); got != Admitted {
		t.Errorf("owner from home after the backstop's window passed: Reserve = %v, want "+
			"Admitted; the refusals stranded tight slots that never decay", got)
	}
}
