package datatests

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
)

// TryClaimCleanupRun is the cross-instance lock for the background cleanup, so the
// behaviour that matters is that exactly one caller wins per interval. These run
// against every supported engine, which is the point: the claim is a conditional
// UPDATE rather than an engine-specific advisory lock.

// setLastCleanupAt puts settings row 1 into a known state.
func setLastCleanupAt(t *testing.T, at *time.Time) *models.Settings {
	t.Helper()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatalf("Failed to read settings: %v", err)
	}
	if settings == nil {
		// The data-test database is migrated but not seeded. On SQLite the file is
		// recreated per run, so row 1 genuinely does not exist yet; on the server
		// engines it usually survives from an earlier run. createTestSettings knows
		// the NOT NULL columns, so reuse it rather than hand-rolling an insert.
		createTestSettings(t)

		settings, err = database.GetSettingsById(nil, 1)
		if err != nil {
			t.Fatalf("Failed to read settings after creating them: %v", err)
		}
		if settings == nil {
			t.Skip("settings row 1 does not exist in this database; the claim targets id = 1")
		}
	}

	if at == nil {
		settings.LastCleanupAt.Valid = false
	} else {
		settings.LastCleanupAt.Time = *at
		settings.LastCleanupAt.Valid = true
	}
	if err := database.UpdateSettings(nil, settings); err != nil {
		t.Fatalf("Failed to update settings: %v", err)
	}
	return settings
}

func TestTryClaimCleanupRun_ClaimableWhenNeverRun(t *testing.T) {
	setLastCleanupAt(t, nil)

	now := time.Now().UTC().Truncate(time.Second)
	claimed, err := database.TryClaimCleanupRun(nil, now, now.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("TryClaimCleanupRun failed: %v", err)
	}
	if !claimed {
		t.Error("Expected the first ever run to be claimable")
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatalf("Failed to read settings: %v", err)
	}
	if !settings.LastCleanupAt.Valid {
		t.Error("Expected last_cleanup_at to be set by a successful claim")
	}
}

func TestTryClaimCleanupRun_ClaimableWhenTheIntervalHasPassed(t *testing.T) {
	longAgo := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	setLastCleanupAt(t, &longAgo)

	now := time.Now().UTC().Truncate(time.Second)
	claimed, err := database.TryClaimCleanupRun(nil, now, now.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("TryClaimCleanupRun failed: %v", err)
	}
	if !claimed {
		t.Error("Expected a run older than the interval to be claimable")
	}
}

func TestTryClaimCleanupRun_NotClaimableWithinTheInterval(t *testing.T) {
	recent := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	setLastCleanupAt(t, &recent)

	now := time.Now().UTC().Truncate(time.Second)
	claimed, err := database.TryClaimCleanupRun(nil, now, now.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("TryClaimCleanupRun failed: %v", err)
	}
	if claimed {
		t.Error("Expected a run inside the interval not to be claimable")
	}

	// And the stored timestamp must be untouched by a lost claim.
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatalf("Failed to read settings: %v", err)
	}
	if settings.LastCleanupAt.Time.Sub(recent) > time.Second ||
		recent.Sub(settings.LastCleanupAt.Time) > time.Second {
		t.Errorf("Expected last_cleanup_at to stay at %v, got %v", recent, settings.LastCleanupAt.Time)
	}
}

// The property the whole design rests on: several instances polling at the same
// moment must produce exactly one winner.
func TestTryClaimCleanupRun_OnlyOneCallerWinsPerInterval(t *testing.T) {
	longAgo := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	setLastCleanupAt(t, &longAgo)

	now := time.Now().UTC().Truncate(time.Second)
	claimableBefore := now.Add(-12 * time.Hour)

	wins := 0
	for i := 0; i < 5; i++ {
		claimed, err := database.TryClaimCleanupRun(nil, now, claimableBefore)
		if err != nil {
			t.Fatalf("TryClaimCleanupRun failed on attempt %d: %v", i, err)
		}
		if claimed {
			wins++
		}
	}

	if wins != 1 {
		t.Errorf("Expected exactly one winner across 5 attempts, got %d", wins)
	}
}

// A claim taken now blocks the next one until the interval elapses again.
func TestTryClaimCleanupRun_ClaimBlocksTheNextInterval(t *testing.T) {
	longAgo := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	setLastCleanupAt(t, &longAgo)

	now := time.Now().UTC().Truncate(time.Second)

	claimed, err := database.TryClaimCleanupRun(nil, now, now.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("TryClaimCleanupRun failed: %v", err)
	}
	if !claimed {
		t.Fatal("Expected the first claim to succeed")
	}

	// A poll a minute later, with the same interval, must lose.
	later := now.Add(time.Minute)
	claimed, err = database.TryClaimCleanupRun(nil, later, later.Add(-12*time.Hour))
	if err != nil {
		t.Fatalf("TryClaimCleanupRun failed: %v", err)
	}
	if claimed {
		t.Error("Expected the follow-up poll to lose the claim")
	}
}

// The sequential test above proves the predicate is right: once a claim lands,
// later claims see the fresh timestamp and lose. It cannot prove mutual exclusion,
// because nothing ever overlaps, so no row lock is contended and the database
// never has to re-evaluate a blocked writer's WHERE clause.
//
// That distinction matters because a read-then-write implementation
//
//	settings := GetSettingsById(1)
//	if settings.LastCleanupAt.Before(cutoff) { UpdateSettings(...); return true }
//
// passes the sequential test perfectly while being broken under load: two callers
// both read the old timestamp, both pass the check, both write, both win. This
// test is the guard against exactly that refactor.
//
// A green run does not certify atomicity — overlap cannot be forced, only made
// likely — so this detects a broken implementation probabilistically rather than
// proving a correct one. Several rounds are run to raise that probability.
func TestTryClaimCleanupRun_ConcurrentCallersProduceOneWinner(t *testing.T) {
	if strings.Trim(config.GetDatabase().Type, `"'`) == "sqlite" {
		t.Skip("sqlite is limited to one connection (SetMaxOpenConns(1)), so callers queue " +
			"rather than contend; the test would pass without ever creating overlap")
	}

	const (
		callers = 8
		rounds  = 5
	)

	for round := 0; round < rounds; round++ {
		// Make the run claimable again for this round.
		longAgo := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
		setLastCleanupAt(t, &longAgo)

		now := time.Now().UTC().Truncate(time.Second)
		claimableBefore := now.Add(-12 * time.Hour)

		type outcome struct {
			claimed bool
			err     error
		}
		outcomes := make([]outcome, callers)

		// Every caller waits on the same barrier so they hit the row together. Each
		// takes its own pooled connection, since tx is nil.
		start := make(chan struct{})
		var wg sync.WaitGroup

		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				claimed, err := database.TryClaimCleanupRun(nil, now, claimableBefore)
				outcomes[i] = outcome{claimed: claimed, err: err}
			}(i)
		}

		close(start)
		wg.Wait()

		wins, failures := 0, 0
		for _, o := range outcomes {
			if o.err != nil {
				// A lock-wait timeout or deadlock is a legitimate outcome under
				// contention, and counts as "did not claim". In production this is
				// logged and the run is skipped, which is the correct response.
				failures++
				continue
			}
			if o.claimed {
				wins++
			}
		}

		if wins != 1 {
			t.Fatalf("round %d: expected exactly 1 winner among %d concurrent callers, got %d (%d errored)",
				round, callers, wins, failures)
		}
		if failures > 0 {
			t.Logf("round %d: 1 winner, %d lock contention errors (acceptable)", round, failures)
		}

		// Exactly one write landed, and it recorded the claim time.
		settings, err := database.GetSettingsById(nil, 1)
		if err != nil {
			t.Fatalf("round %d: failed to read settings: %v", round, err)
		}
		if !settings.LastCleanupAt.Valid {
			t.Fatalf("round %d: expected last_cleanup_at to be set by the winner", round)
		}
		if settings.LastCleanupAt.Time.Equal(longAgo) {
			t.Fatalf("round %d: last_cleanup_at was not advanced past the pre-round value", round)
		}
	}
}
