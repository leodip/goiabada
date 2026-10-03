package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	consentPairIndex000055       = "idx_user_consents_user_id_client_id"
	sessionClientPairIndex000055 = "idx_user_session_clients_user_session_id_client_id"

	// Four save times, one literal format for all four engines, per seedSessionWithoutUserAgent000046.
	// SQLite compares the datetime column as text, so every time in a pair is written as a literal
	// in this one format.
	earliest000055 = "'2026-01-01 00:00:00'"
	middle000055   = "'2026-02-01 00:00:00'"
	later000055    = "'2026-03-01 00:00:00'"
	latest000055   = "'2026-04-01 00:00:00'"
	afterGap000055 = "'2026-05-01 00:00:00'"
)

// Migration 000055 (#249, #115, #437) gives user_consents one row per (user_id, client_id) and
// user_session_clients one per (user_session_id, client_id), sweeping a duplicate first. The golden
// files record the indexes and so cannot say WHICH duplicate survives, or that a deployment already
// holding one still starts; this holds the migration to the claims its comments make, against an
// ISOLATED database of the configured dialect (see migration_testdb_helper_test.go):
//
//   - a consent pair keeps the row with the latest updated_at, the highest id breaking a tie, and
//     keeps that row's scope as it is. The highest id alone is the most recently CREATED row, not the
//     most recently SAVED, because a save rewrites the row it reads in place: a lower-id duplicate
//     saved later holds the user's latest answer;
//   - a NULL updated_at counts as the oldest, so a nullable column cannot leave a pair with no row
//     kept, or two;
//   - a session association pair keeps the lowest id;
//   - a pair nothing duplicated is untouched, and the same client in two sessions is two pairs;
//   - the indexes are unique over the pair in that order, so a second row for one pair is refused
//     as data.ErrUniqueViolation, where another pair is accepted;
//   - the down migration drops both indexes and cannot restore a swept row, and applying the
//     migration again sweeps what the gap let in.
//
// The rows are seeded through the data layer at version 000054, which has no unique key over either
// pair, and each consent's updated_at is then set with a literal so a case can say "equal" or NULL.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000055_OneRowPerConsentAndSessionClient
func TestMigration000055_OneRowPerConsentAndSessionClient(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(ctx, 54), "migrate to 54")
	for _, tc := range pairIndexes000055() {
		require.Falsef(t, describeIndex(t, h, tc.table, tc.name).Exists,
			"%s must not exist at 000054, so what is found afterwards is what 000055 added", tc.name)
	}

	seed := seedDuplicates000055(t, h)

	require.NoError(t, h.Migrator.Migrate(ctx, 55), "apply 000055")
	assertPairIndexes000055(t, h, "after apply")
	seed.assertSwept(t, h, "after apply")
	seed.assertTheKeysRefuseADuplicate(t, h, "after apply")

	// Down: the indexes go, and no swept row comes back. A duplicate is accepted again, which is
	// what says the index, and not something else, was what refused it.
	require.NoError(t, h.Migrator.Migrate(ctx, 54), "roll back to 54")
	for _, tc := range pairIndexes000055() {
		assert.Falsef(t, describeIndex(t, h, tc.table, tc.name).Exists, "%s is gone after the down migration", tc.name)
	}
	seed.assertSwept(t, h, "after the down migration, where nothing swept comes back")

	readmittedConsent := seedConsent000055(t, h, seed.userA, seed.client1, "openid profile", afterGap000055)
	seedSessionClient000055(t, h, seed.session1, seed.client1)
	seedSessionClient000055(t, h, seed.session2, seed.client2)
	seedSessionClient000055(t, h, seed.session2, seed.client2)

	// Up again: what the gap let in is swept by the same rules.
	require.NoError(t, h.Migrator.Migrate(ctx, 55), "apply 000055 again")
	assertPairIndexes000055(t, h, "after down then up")
	assert.Equal(t, []consentRow000055{{readmittedConsent, "openid profile"}}, consentRows000055(t, h, seed.userA, seed.client1),
		"the consent saved while the key was gone is the latest, so it is the one kept, whatever its id")
	assert.Equal(t, []int64{seed.session1Client1Kept}, sessionClientIds000055(t, h, seed.session1, seed.client1),
		"the association inserted while the key was gone is swept, and the lowest id stays")
	assert.Len(t, sessionClientIds000055(t, h, seed.session2, seed.client2), 1,
		"two rows for a pair the first run never saw are swept to one")
}

type pairIndex000055 struct {
	table, name string
	columns     []string
}

func pairIndexes000055() []pairIndex000055 {
	return []pairIndex000055{
		{"user_consents", consentPairIndex000055, []string{"user_id", "client_id"}},
		{"user_session_clients", sessionClientPairIndex000055, []string{"user_session_id", "client_id"}},
	}
}

// assertPairIndexes000055 checks the shape and not the name alone: an index over the wrong columns,
// or in the other order, would pass a name check while refusing nothing the writers need refused.
func assertPairIndexes000055(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	for _, tc := range pairIndexes000055() {
		shape := describeIndex(t, h, tc.table, tc.name)
		require.Truef(t, shape.Exists, "%s is missing on %s %s", tc.name, dbType(), when)
		assert.Truef(t, shape.Unique, "%s is UNIQUE %s: it is the key the writers lose a race on", tc.name, when)
		assert.Equalf(t, tc.columns, shape.Columns, "%s covers the pair, in that order %s", tc.name, when)
	}
}

type consentRow000055 struct {
	id    int64
	scope string
}

// seeded000055 is what the migration is run over, and what each assertion is written against.
type seeded000055 struct {
	userA, userB              int64
	client1, client2, client3 int64
	session1, session2        int64

	// The consent that must survive in each pair, which is the whole of decision 28's claim.
	narrowedAfterward  consentRow000055 // (A,1): the LOWER id, saved later with the narrower scope
	equalTimes         consentRow000055 // (A,2): two rows saved at one instant, the higher id
	nullOnTheHigherId  consentRow000055 // (B,1): the lower id, against a NULL updated_at
	bothNull           consentRow000055 // (B,2): nothing but the id to order by, the higher
	middleOfThree      consentRow000055 // (A,3): neither the highest id nor the lowest, but the latest save
	untouched          consentRow000055 // (B,3): a pair nothing duplicated
	untouchedGrantedAt sql.NullTime

	// The association that must survive in each pair: the lowest id.
	session1Client1Kept, session1Client2Only, session2Client1Kept int64
}

func seedDuplicates000055(t *testing.T, h *isolatedDB) *seeded000055 {
	t.Helper()

	s := &seeded000055{
		userA:   createTestUserOn(t, h.DB).Id,
		userB:   createTestUserOn(t, h.DB).Id,
		client1: createTestClientOn(t, h.DB).Id,
		client2: createTestClientOn(t, h.DB).Id,
		client3: createTestClientOn(t, h.DB).Id,
	}

	// The user who narrowed a consent: two rows, the lower id saved later with the narrower scope.
	// Keeping the higher id would hand back the scope the user removed.
	s.narrowedAfterward = consentRow000055{seedConsent000055(t, h, s.userA, s.client1, "openid", later000055), "openid"}
	seedConsent000055(t, h, s.userA, s.client1, "openid profile email", earliest000055)

	// Equal timestamps: the higher id breaks the tie, and its scope is kept as it is.
	seedConsent000055(t, h, s.userA, s.client2, "openid", middle000055)
	s.equalTimes = consentRow000055{seedConsent000055(t, h, s.userA, s.client2, "openid profile", middle000055), "openid profile"}

	// A NULL updated_at is the oldest: the lower id has a real time and wins against the higher id's NULL.
	s.nullOnTheHigherId = consentRow000055{seedConsent000055(t, h, s.userB, s.client1, "openid", middle000055), "openid"}
	seedConsent000055(t, h, s.userB, s.client1, "openid email", "NULL")

	// Both NULL: nothing to order by but the id, so the higher id is kept.
	seedConsent000055(t, h, s.userB, s.client2, "openid", "NULL")
	s.bothNull = consentRow000055{seedConsent000055(t, h, s.userB, s.client2, "openid email", "NULL"), "openid email"}

	// Three rows, the middle id the latest save.
	seedConsent000055(t, h, s.userA, s.client3, "openid", earliest000055)
	s.middleOfThree = consentRow000055{seedConsent000055(t, h, s.userA, s.client3, "openid email", latest000055), "openid email"}
	seedConsent000055(t, h, s.userA, s.client3, "openid profile email", middle000055)

	// A pair nothing duplicated keeps every column it had.
	s.untouched = consentRow000055{seedConsent000055(t, h, s.userB, s.client3, "openid profile", middle000055), "openid profile"}
	stored, err := h.DB.GetConsentByUserIdAndClientId(context.Background(), nil, s.userB, s.client3)
	require.NoError(t, err)
	require.NotNil(t, stored)
	s.untouchedGrantedAt = stored.GrantedAt

	// Associations: three rows for (S1, C1), one for (S1, C2), two for (S2, C1). The same client in
	// two sessions is two pairs, not a duplicate.
	s.session1 = createTestUserSessionOn(t, h.DB, s.userA).Id
	s.session2 = createTestUserSessionOn(t, h.DB, s.userA).Id
	s.session1Client1Kept = seedSessionClient000055(t, h, s.session1, s.client1)
	seedSessionClient000055(t, h, s.session1, s.client1)
	seedSessionClient000055(t, h, s.session1, s.client1)
	s.session1Client2Only = seedSessionClient000055(t, h, s.session1, s.client2)
	s.session2Client1Kept = seedSessionClient000055(t, h, s.session2, s.client1)
	seedSessionClient000055(t, h, s.session2, s.client1)

	return s
}

// seedConsent000055 creates a consent below 000055, which has no key to refuse a second, and sets
// its updated_at to the literal given, which is NULL for a row a pre-upgrade binary might have left.
func seedConsent000055(t *testing.T, h *isolatedDB, userId, clientId int64, scope, updatedAt string) int64 {
	t.Helper()

	consent := &record.UserConsent{
		UserId: userId, ClientId: clientId, Scope: scope,
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
	}
	require.NoError(t, h.DB.CreateUserConsent(context.Background(), nil, consent), "seed a consent while no key refuses a second")
	_, err := h.SQL.ExecContext(context.Background(), fmt.Sprintf(
		"UPDATE user_consents SET updated_at = %s WHERE id = %d", updatedAt, consent.Id))
	require.NoError(t, err, "set the consent's updated_at")
	return consent.Id
}

func seedSessionClient000055(t *testing.T, h *isolatedDB, sessionId, clientId int64) int64 {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Microsecond)
	association := &record.UserSessionClient{UserSessionId: sessionId, ClientId: clientId, Started: now, LastAccessed: now}
	require.NoError(t, h.DB.CreateUserSessionClient(context.Background(), nil, association),
		"seed an association while no key refuses a second")
	return association.Id
}

// consentRows000055 reads the pair's rows straight from the table, ordered by id, so what is
// asserted is what the migration left and not what a data method chose to return of several.
func consentRows000055(t *testing.T, h *isolatedDB, userId, clientId int64) []consentRow000055 {
	t.Helper()

	rows, err := h.SQL.QueryContext(context.Background(), fmt.Sprintf(
		"SELECT id, scope FROM user_consents WHERE user_id = %d AND client_id = %d ORDER BY id", userId, clientId))
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var found []consentRow000055
	for rows.Next() {
		var row consentRow000055
		require.NoError(t, rows.Scan(&row.id, &row.scope))
		found = append(found, row)
	}
	require.NoError(t, rows.Err())
	return found
}

func sessionClientIds000055(t *testing.T, h *isolatedDB, sessionId, clientId int64) []int64 {
	t.Helper()

	rows, err := h.SQL.QueryContext(context.Background(), fmt.Sprintf(
		"SELECT id FROM user_session_clients WHERE user_session_id = %d AND client_id = %d ORDER BY id", sessionId, clientId))
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}

// assertSwept holds each pair to the one row it keeps, by id and by scope.
func (s *seeded000055) assertSwept(t *testing.T, h *isolatedDB, when string) {
	t.Helper()

	for _, tc := range []struct {
		name           string
		user, client   int64
		want           consentRow000055
		whatItPinsDown string
	}{
		{"the lower id saved later with the narrower scope", s.userA, s.client1, s.narrowedAfterward,
			"the latest save is kept, not the highest id"},
		{"two rows saved at one instant", s.userA, s.client2, s.equalTimes,
			"the highest id breaks a tie, and its scope is unchanged"},
		{"a NULL updated_at on the higher id", s.userB, s.client1, s.nullOnTheHigherId,
			"NULL is the oldest, so a real time outranks a higher id"},
		{"both updated_at NULL", s.userB, s.client2, s.bothNull,
			"with nothing to order by the highest id is kept"},
		{"three rows, the middle one saved last", s.userA, s.client3, s.middleOfThree,
			"neither the highest id nor the lowest: the latest save"},
		{"a pair nothing duplicated", s.userB, s.client3, s.untouched,
			"a pair with one row is not touched"},
	} {
		got := consentRows000055(t, h, tc.user, tc.client)
		assert.Equalf(t, []consentRow000055{tc.want}, got, "%s: %s %s", tc.name, tc.whatItPinsDown, when)
	}

	// The scope a user removed stays removed: the surviving row is the narrower one, which is what
	// every reader that consults the consent (a refresh that needs one, the silent sign-in) goes by.
	narrowed, err := h.DB.GetConsentByUserIdAndClientId(context.Background(), nil, s.userA, s.client1)
	require.NoError(t, err)
	require.NotNil(t, narrowed)
	assert.Truef(t, narrowed.HasScope("openid"), "the scope the user kept is still consented %s", when)
	assert.Falsef(t, narrowed.HasScope("profile"), "the scope the user removed is not handed back %s", when)
	assert.Falsef(t, narrowed.HasScope("email"), "nor the other one %s", when)

	untouched, err := h.DB.GetConsentByUserIdAndClientId(context.Background(), nil, s.userB, s.client3)
	require.NoError(t, err)
	require.NotNil(t, untouched)
	assert.Truef(t, s.untouchedGrantedAt.Time.Equal(untouched.GrantedAt.Time),
		"an untouched consent keeps its granted_at %s: %v and was %v", when, untouched.GrantedAt.Time, s.untouchedGrantedAt.Time)

	assert.Equalf(t, []int64{s.session1Client1Kept}, sessionClientIds000055(t, h, s.session1, s.client1),
		"three associations for a pair keep the lowest id %s", when)
	assert.Equalf(t, []int64{s.session1Client2Only}, sessionClientIds000055(t, h, s.session1, s.client2),
		"an association nothing duplicated is not touched %s", when)
	assert.Equalf(t, []int64{s.session2Client1Kept}, sessionClientIds000055(t, h, s.session2, s.client1),
		"the same client in another session is another pair, with its own lowest id %s", when)
}

// assertTheKeysRefuseADuplicate holds the indexes to what they do: a second row for a pair is
// refused with the sentinel a writer reruns on, where the same statement for another pair is
// accepted, so each refusal is the key's and not a mistake in the statement.
func (s *seeded000055) assertTheKeysRefuseADuplicate(t *testing.T, h *isolatedDB, when string) {
	t.Helper()
	ctx := context.Background()

	err := h.DB.CreateUserConsent(ctx, nil, &record.UserConsent{UserId: s.userA, ClientId: s.client1, Scope: "openid"})
	assert.ErrorIsf(t, err, data.ErrUniqueViolation, "a second consent for a pair is refused by the key %s", when)
	assert.Lenf(t, consentRows000055(t, h, s.userA, s.client1), 1, "and writes nothing %s", when)

	other := createTestClientOn(t, h.DB)
	assert.NoErrorf(t, h.DB.CreateUserConsent(ctx, nil, &record.UserConsent{UserId: s.userA, ClientId: other.Id, Scope: "openid"}),
		"a consent for another pair is accepted %s", when)

	now := time.Now().UTC().Truncate(time.Microsecond)
	err = h.DB.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{UserSessionId: s.session1, ClientId: s.client1, Started: now, LastAccessed: now})
	assert.ErrorIsf(t, err, data.ErrUniqueViolation, "a second association for a pair is refused by the key %s", when)
	assert.Lenf(t, sessionClientIds000055(t, h, s.session1, s.client1), 1, "and writes nothing %s", when)

	assert.NoErrorf(t, h.DB.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{UserSessionId: s.session1, ClientId: s.client3, Started: now, LastAccessed: now}),
		"an association for another client is accepted %s", when)
	assert.NoErrorf(t, h.DB.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{UserSessionId: s.session2, ClientId: s.client2, Started: now, LastAccessed: now}),
		"and so is the same client in another session %s", when)
	// Clear what the two controls added, so the down and up that follow start from the seed.
	_, err = h.SQL.ExecContext(ctx, fmt.Sprintf(
		"DELETE FROM user_session_clients WHERE (user_session_id = %d AND client_id = %d) OR (user_session_id = %d AND client_id = %d)",
		s.session1, s.client3, s.session2, s.client2))
	require.NoError(t, err)
}
