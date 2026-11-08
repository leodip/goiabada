package datatests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam of #42 decision 9's replay store, against the real engines: an accepted DPoP proof is stored
// by an atomic insert under the primary key, the SHA-256 of its normalized htu and its jti. The first
// insert of a proof reports it recorded; every later one, from this instance or another sharing the
// database, finds the key taken and reports a replay. The cleanup worker deletes a proof once it
// could no longer be accepted.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// newProofHash is a replay key of the shape the auth server stores, a SHA-256 hex digest. It is
// safe to call from any goroutine: crypto/rand.Read does not fail.
func newProofHash(*testing.T) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recordDPoPProof stores hash through the method under test, through the pool, and returns whether
// this call recorded it.
func recordDPoPProof(t *testing.T, hash string, expiresAt time.Time) bool {
	t.Helper()
	recorded, err := database.RecordDPoPProof(context.Background(), nil, hash, expiresAt)
	require.NoError(t, err, "RecordDPoPProof")
	return recorded
}

// storedDPoPProof reads the stored row's expires_at, and how many rows hold the hash, straight from
// the table, apart from the method under test. The hash is inlined: a value the test drew.
func storedDPoPProof(t *testing.T, hash string) (time.Time, int) {
	t.Helper()
	var count int
	require.NoError(t, rawSQLHandle(t).QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT COUNT(*) FROM dpop_proofs WHERE proof_hash = '%s'", hash)).Scan(&count))
	if count == 0 {
		return time.Time{}, 0
	}
	var expiresAt time.Time
	require.NoError(t, rawSQLHandle(t).QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT expires_at FROM dpop_proofs WHERE proof_hash = '%s'", hash)).Scan(&expiresAt))
	return expiresAt, count
}

// A proof is recorded once, with its expiry. Recording it again is a replay: reported so, with no
// error, and the first expiry stays as it was.
func TestRecordDPoPProof_ASecondRecordOfOneProofIsAReplay(t *testing.T) {
	hash := newProofHash(t)
	expiresAt := time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC)

	assert.True(t, recordDPoPProof(t, hash, expiresAt), "the first use of a proof is recorded")
	stored, count := storedDPoPProof(t, hash)
	require.Equal(t, 1, count)
	assert.True(t, expiresAt.Equal(stored.UTC()), "the proof's expiry is stored: got %v", stored)

	assert.False(t, recordDPoPProof(t, hash, expiresAt.Add(time.Hour)), "the second is a replay")
	stored, count = storedDPoPProof(t, hash)
	assert.Equal(t, 1, count, "still one row")
	assert.True(t, expiresAt.Equal(stored.UTC()), "and the first expiry stays: got %v", stored)
}

// One proof's record answers for no other proof.
func TestRecordDPoPProof_OneProofDoesNotAnswerForAnother(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	first := newProofHash(t)
	require.True(t, recordDPoPProof(t, first, expiresAt))

	assert.True(t, recordDPoPProof(t, newProofHash(t), expiresAt), "another proof is recorded on its own")
}

// A replay key is a SHA-256 hex digest, as the auth server computes it, and anything else is an
// error, never an answer: a caller bug, and SQL Server's `=` pads, so a key with trailing spaces
// would otherwise meet the record of the key without them (#283).
func TestRecordDPoPProof_RefusesAKeyThatIsNoDigest(t *testing.T) {
	hash := newProofHash(t)
	for name, key := range map[string]string{
		"empty":          "",
		"too short":      hash[:63],
		"too long":       hash + "0",
		"upper case":     strings.ToUpper(hash),
		"trailing space": hash[:63] + " ",
		"not hex":        "g" + hash[1:],
	} {
		t.Run(name, func(t *testing.T) {
			recorded, err := database.RecordDPoPProof(context.Background(), nil, key, time.Now().UTC().Add(time.Minute))
			require.Error(t, err)
			assert.False(t, recorded)
		})
	}
}

// Simultaneous uses of one proof, through the pool from many callers at once, as many requests or
// many instances sharing the database would make them: exactly one is recorded, and every other is
// a replay, with no error (#42 decision 9). On SQLite the pool has one connection, so the callers
// queue; the three server engines are where the inserts meet on the key.
func TestRecordDPoPProof_OfSimultaneousUsesOfOneProofExactlyOneIsRecorded(t *testing.T) {
	const callers = 8
	expiresAt := time.Now().UTC().Add(10 * time.Minute)

	for round := 0; round < concurrentRounds; round++ {
		hash := newProofHash(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		recorded := make([]bool, callers)
		errs := make([]error, callers)
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				recorded[i], errs[i] = database.RecordDPoPProof(context.Background(), nil, hash, expiresAt)
			}(i)
		}
		close(start)
		wg.Wait()

		winners := 0
		for i := 0; i < callers; i++ {
			require.NoErrorf(t, errs[i], "round %d: a replay is an answer, not an error", round)
			if recorded[i] {
				winners++
			}
		}
		require.Equalf(t, 1, winners, "round %d: exactly one use is recorded; outcomes %v", round, recorded)
		_, count := storedDPoPProof(t, hash)
		require.Equalf(t, 1, count, "round %d: one row", round)
	}
}

// The cleanup worker deletes a proof once it could no longer be accepted, and no sooner: a record
// expiring at the sweep's moment itself is kept for the next sweep, and an unexpired one stays a
// replay.
func TestDeleteExpiredDPoPProofs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expired := newProofHash(t)
	atTheBoundary := newProofHash(t)
	live := newProofHash(t)
	require.True(t, recordDPoPProof(t, expired, now.Add(-time.Minute)))
	require.True(t, recordDPoPProof(t, atTheBoundary, now))
	require.True(t, recordDPoPProof(t, live, now.Add(10*time.Minute)))

	require.NoError(t, database.DeleteExpiredDPoPProofs(context.Background(), nil, now))

	_, count := storedDPoPProof(t, expired)
	assert.Equal(t, 0, count, "an expired proof's record is deleted")
	_, count = storedDPoPProof(t, atTheBoundary)
	assert.Equal(t, 1, count, "a record expiring at the sweep's moment is kept")
	assert.False(t, recordDPoPProof(t, live, now.Add(10*time.Minute)), "an unexpired proof is still a replay")

	require.NoError(t, database.DeleteExpiredDPoPProofs(context.Background(), nil, now.Add(time.Microsecond)))
	_, count = storedDPoPProof(t, atTheBoundary)
	assert.Equal(t, 0, count, "deleted by the next sweep")
	_, count = storedDPoPProof(t, live)
	assert.Equal(t, 1, count)
}

// dpopMeasureVariable opts into TestDPoPProofs_CostAtTheExpectedVolume, which fills the table and
// takes minutes on the server engines, so it stays out of the ordinary data tier.
const dpopMeasureVariable = "GOIABADA_MEASURE_DPOP_PROOFS"

// The replay store's cost at the volume #42 decision 9 expects: 100 DPoP requests a second
// sustained for ten minutes, about 60,000 live rows. It measures the insert of a new proof and of a
// replay with the table at that volume, and the sweep the worker runs every five minutes, which at
// that rate deletes some 30,000 expired rows beside the live ones. It asserts nothing about the
// figures, which depend on the machine; it logs them for the pull request.
//
//	GOIABADA_MEASURE_DPOP_PROOFS=1 ./run-tests.sh --type data --db <engine> --no-build \
//	  --run TestDPoPProofs_CostAtTheExpectedVolume
func TestDPoPProofs_CostAtTheExpectedVolume(t *testing.T) {
	if os.Getenv(dpopMeasureVariable) == "" {
		t.Skipf("set %s=1 to measure the replay store's cost", dpopMeasureVariable)
	}
	const (
		liveRows    = 60_000
		expiredRows = 30_000
		samples     = 2_000
		fillers     = 8
	)
	ctx := context.Background()
	_, err := rawSQLHandle(t).ExecContext(ctx, "DELETE FROM dpop_proofs")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = rawSQLHandle(t).ExecContext(ctx, "DELETE FROM dpop_proofs") })

	now := time.Now().UTC()
	fill := func(n int, expiresAt time.Time) {
		var wg sync.WaitGroup
		for f := 0; f < fillers; f++ {
			wg.Add(1)
			go func(f int) {
				defer wg.Done()
				for i := f; i < n; i += fillers {
					_, err := database.RecordDPoPProof(ctx, nil, newProofHash(t), expiresAt)
					if err != nil {
						t.Error(err)
						return
					}
				}
			}(f)
		}
		wg.Wait()
		require.False(t, t.Failed())
	}
	fillStarted := time.Now()
	fill(expiredRows, now.Add(-time.Minute))
	fill(liveRows, now.Add(10*time.Minute))
	t.Logf("%s: filled %d live and %d expired rows in %s", dbType(), liveRows, expiredRows, time.Since(fillStarted).Round(time.Millisecond))

	hashes := make([]string, samples)
	inserts := make([]time.Duration, samples)
	for i := range hashes {
		hashes[i] = newProofHash(t)
		started := time.Now()
		require.True(t, recordDPoPProof(t, hashes[i], now.Add(10*time.Minute)))
		inserts[i] = time.Since(started)
	}
	replays := make([]time.Duration, samples)
	for i, hash := range hashes {
		started := time.Now()
		require.False(t, recordDPoPProof(t, hash, now.Add(10*time.Minute)))
		replays[i] = time.Since(started)
	}

	started := time.Now()
	require.NoError(t, database.DeleteExpiredDPoPProofs(ctx, nil, now))
	sweep := time.Since(started)

	var remaining int
	require.NoError(t, rawSQLHandle(t).QueryRowContext(ctx, "SELECT COUNT(*) FROM dpop_proofs").Scan(&remaining))
	require.Equal(t, liveRows+samples, remaining, "the sweep deleted the expired rows and only those")

	t.Logf("%s: a new proof's insert at %d live rows: median %s, p99 %s", dbType(), liveRows,
		percentile(inserts, 50), percentile(inserts, 99))
	t.Logf("%s: a replay's refused insert: median %s, p99 %s", dbType(), percentile(replays, 50), percentile(replays, 99))
	t.Logf("%s: one sweep of %d expired rows beside %d live: %s", dbType(), expiredRows, remaining, sweep.Round(time.Millisecond))
}

func percentile(durations []time.Duration, p int) time.Duration {
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[(len(sorted)-1)*p/100].Round(time.Microsecond)
}
