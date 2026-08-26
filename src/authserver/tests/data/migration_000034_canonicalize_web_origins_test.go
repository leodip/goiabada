package datatests

import (
	"errors"
	"strings"
	"testing"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/urlutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webOriginsIndex000034 is the index the migration adds, on every engine.
const webOriginsIndex000034 = "idx_web_origins_origin_client"

// webOriginColumnLimit000034 is the width of web_origins.origin on MySQL,
// PostgreSQL and SQL Server. It is TEXT on sqlite, which is why an over-long row
// can only exist there and why only that engine's seed carries one.
const webOriginColumnLimit000034 = 256

// repair000034 is one seeded row and what migration 000034 must do to it.
//
// want is written by hand rather than taken from CanonicalOrigin, so the table
// pins the migration's behaviour on its own. The two are then tied together by a
// separate assertion, because decision 14's whole property is that the set the
// write path accepts is the set this migration can repair: a case whose expected
// value came only from CanonicalOrigin would agree with itself while both were
// wrong.
type repair000034 struct {
	raw     string // what the OLD validator would have let through and stored
	want    string // the value that must survive, empty when the row must be deleted
	deleted bool
	why     string
}

// TestMigration000034_CanonicalizeWebOrigins exercises the migration that repairs
// stored web origins into the exact string a browser sends in an Origin header,
// deletes the rows no conversion can reach, and adds UNIQUE (origin, client_id)
// (#250). It runs against an ISOLATED database of the configured dialect (see
// migration_testdb_helper.go).
//
// This is the tier that matters for this file. The repair is string surgery
// written four different ways in four different dialects, and decision 10 records
// that as the change's hard part: a literal or a function that is wrong for the
// engine matches nothing SILENTLY rather than failing, which is migration
// 000033's own recorded lesson. Nothing but the data tier runs mysql, postgres
// and mssql at all.
//
// The properties, in the order they appear below:
//
//  1. The index is absent at 000033, so the one found afterwards is the one
//     000034 created rather than one already there under a colliding name.
//
//  2. The uniqueness flag's polarity is checked on this engine before it is
//     trusted, using key_pairs.idx_state as a control. Each catalog reports
//     uniqueness differently and MySQL reports it inverted (NON_UNIQUE), so
//     "unique" would otherwise pass on an engine whose flag was being read
//     backwards.
//
//  3. Every row in the repair table lands on its stated value or is gone, and
//     CanonicalOrigin agrees about each one. The deleted half is where an engine
//     silently differs: a predicate that never fires leaves the row, and a
//     predicate that fires too widely destroys a live CORS origin, which is the
//     direction that costs more.
//
//  4. The duplicates canonicalizing creates collapse to one row per client,
//     keeping MIN(id), and an origin listed by two different clients survives
//     twice. That second half is what would fail under the rejected
//     UNIQUE(origin) alone.
//
//  5. The index covers exactly [origin, client_id], IN THAT ORDER, and is unique.
//     The order is not decoration: the CORS lookup asks about an origin with no
//     client in hand, so the rejected (client_id, origin) would enforce the same
//     invariant while being useless to WebOriginExists.
//
//  6. It bites. A second identical (origin, client_id) is refused while the same
//     origin against another client is accepted.
//
//  7. The down migration runs and re-applying is clean. The down is not an
//     inverse: the repaired values stay repaired and the deleted rows stay
//     deleted, which the file says.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000034_CanonicalizeWebOrigins
func TestMigration000034_CanonicalizeWebOrigins(t *testing.T) {
	h := newIsolatedDB(t)

	// Seeded through the ORM at 000033 after a round trip to head, on
	// migration_000029_created_via_dcr_test.go's pattern: going to head first is
	// what keeps this test working when later migrations add a column, since the
	// ORM writes every column the Go models carry. ErrNoChange is tolerated
	// because 000034 is currently head.
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}
	require.NoError(t, h.Migrator.Migrate(33), "roll back to 000033")

	// 2. Control: a known non-unique index must read as non-unique here. This is
	// what makes the "unique" assertion below mean something.
	control := describeIndex(t, h, "key_pairs", "idx_state")
	require.True(t, control.Exists, "control index idx_state must exist at 000033")
	require.False(t, control.Unique,
		"control index idx_state is non-unique on every engine; reading it as unique means the uniqueness flag is being read backwards")

	// 1. Absent before the migration.
	require.False(t, describeIndex(t, h, "web_origins", webOriginsIndex000034).Exists,
		"%s must not exist at 000033", webOriginsIndex000034)

	clientA := seedClient000034(t, h, "mig34-a")
	clientB := seedClient000034(t, h, "mig34-b")

	cases := repairCases000034(t)
	ids := make([]int64, len(cases))
	for i, c := range cases {
		ids[i] = seedWebOrigin000034(t, h, clientA.Id, c.raw)
	}

	// 4. The collisions canonicalizing creates. Three rows for one client rather
	// than two, so a dedupe that only collapsed pairs would still leave a
	// duplicate behind and fail the index below.
	dupIds := []int64{
		seedWebOrigin000034(t, h, clientA.Id, "https://dup.example.com"),
		seedWebOrigin000034(t, h, clientA.Id, "https://dup.example.com/"),
		seedWebOrigin000034(t, h, clientA.Id, "https://DUP.example.com/x?y=1"),
	}
	// The same origin against a second client. It must survive: client_id is a
	// label, not a boundary, so two clients may each list an origin.
	otherClientDup := seedWebOrigin000034(t, h, clientB.Id, "https://dup.example.com/")

	require.NoError(t, h.Migrator.Migrate(34), "apply 000034")

	// 3. Every seeded shape lands where the table says.
	for i, c := range cases {
		got, err := h.DB.GetWebOriginById(nil, ids[i])
		require.NoErrorf(t, err, "read back the row seeded from %q", c.raw)

		if c.deleted {
			assert.Nilf(t, got, "%q must be deleted: %s", c.raw, c.why)
			continue
		}
		if assert.NotNilf(t, got, "%q must survive as %q: %s", c.raw, c.want, c.why) {
			assert.Equalf(t, c.want, got.Origin, "%q must be repaired to %q: %s", c.raw, c.want, c.why)
		}
	}

	// 4, continued.
	survivors := 0
	for _, id := range dupIds {
		row, err := h.DB.GetWebOriginById(nil, id)
		require.NoError(t, err, "read back a duplicate row")
		if row != nil {
			survivors++
			assert.Equal(t, "https://dup.example.com", row.Origin,
				"the surviving duplicate must carry the canonical value")
			assert.Equalf(t, dupIds[0], id,
				"the dedupe must keep MIN(id), the earliest registration, since the survivors are byte-identical and created_at is all that distinguishes them")
		}
	}
	assert.Equal(t, 1, survivors, "three rows canonicalizing to one value must leave one row for that client")

	other, err := h.DB.GetWebOriginById(nil, otherClientDup)
	require.NoError(t, err, "read back the second client's row")
	if assert.NotNil(t, other,
		"an origin listed by a second client must survive: the index is (origin, client_id), and UNIQUE(origin) alone would have deleted this") {
		assert.Equal(t, "https://dup.example.com", other.Origin)
	}

	// 5 and 6.
	assertWebOriginsIndex000034(t, h, clientA.Id, clientB.Id, "after apply")

	// 7. Down, then up again.
	require.NoError(t, h.Migrator.Migrate(33), "roll back 000034")
	assert.False(t, describeIndex(t, h, "web_origins", webOriginsIndex000034).Exists,
		"%s must be gone after rolling back to 000033", webOriginsIndex000034)

	require.NoError(t, h.Migrator.Migrate(34), "re-apply 000034")
	assertWebOriginsIndex000034(t, h, clientA.Id, clientB.Id, "after down/up round trip")
}

// repairCases000034 is the table, plus the assertion that ties it to the write
// path. Every host is distinct on purpose: two cases canonicalizing to the same
// value for the same client would be deduped, and the row that vanished would
// look like a repair failure.
func repairCases000034(t *testing.T) []repair000034 {
	t.Helper()

	cases := []repair000034{
		// Repaired. The five shapes the old validator let through.
		{"https://slash.example.com/", "https://slash.example.com", false,
			"a trailing slash is what copying a URL out of a browser bar produces, and it is W2's headline case"},
		{"https://path.example.com/callback", "https://path.example.com", false,
			"an Origin header carries nothing after the authority"},
		{"https://query.example.com?x=1", "https://query.example.com", false,
			"the cut takes the first of '/', '?' and '#', not just the first '/'"},
		{"https://frag.example.com/p#f", "https://frag.example.com", false,
			"url.ParseRequestURI refuses a '#' in a host, so a stored '#' always sits behind a '/' or a '?'"},
		{"HTTPS://Case.Example.COM/", "https://case.example.com", false,
			"a browser lowercases scheme and host; the API lowercased on write but a direct row need not have been"},
		{"  https://pad.example.com  ", "https://pad.example.com", false,
			"CanonicalOrigin trims surrounding whitespace, so the repair has to as well or the two sets disagree"},
		{"https://p443.example.com:443", "https://p443.example.com", false,
			"a browser omits the default port entirely"},
		{"http://p80.example.com:80", "http://p80.example.com", false,
			"the http default, which is a different number from the https one"},
		{"https://both.example.com:443/x?y", "https://both.example.com", false,
			"the cut must run BEFORE the port strip, or ':443/x?y' never looks like a default port"},

		// Untouched. Each varies exactly one thing from a case above.
		{"https://keepport.example.com:8443", "https://keepport.example.com:8443", false,
			"a non-default port is part of the origin a browser sends"},
		{"https://https80.example.com:80", "https://https80.example.com:80", false,
			"80 is not the default for https, so it must survive; a port strip written as a bare ':80' suffix test would eat it"},
		{"http://http443.example.com:443", "http://http443.example.com:443", false,
			"the mirror of the case above, on the other scheme"},
		{"http://192.168.1.10:3000", "http://192.168.1.10:3000", false,
			"the dev-setup shape: a strict dotted quad with a port must not be caught by the IPv4 rule"},
		{"http://foo_bar", "http://foo_bar", false,
			"an underscore host is unusual, legal, and works today; a whitelist of [a-z0-9.-] would delete it, which is why the predicate lists what is wrong instead"},
		{"https://trailingdot.example.com.", "https://trailingdot.example.com.", false,
			"a single trailing dot is a distinct host a browser serializes verbatim"},
		{"https://0.0.0.0", "https://0.0.0.0", false,
			"every label is a bare zero, which the leading-zero test must not read as a leading zero"},
		{"https://255.255.255.255", "https://255.255.255.255", false,
			"the boundary of the <= 255 rule, on all four labels at once"},
		{"http://portzero.example.com:0", "http://portzero.example.com:0", false,
			"keep this: port 0 is ACCEPTED. The WHATWG port parser takes 0 to 65535 and serializes '0' verbatim, so it is not a leading-zero case; '0443' is"},

		// Deleted. No conversion reaches these, and each has never matched an
		// Origin header, so removing it removes nothing that ever worked.
		{"https://user@example.com", "", true, "userinfo never appears in an Origin header"},
		{"https://[2001:db8::1]", "", true, "an IPv6 literal: SQL cannot do address compression, so the write path refuses it too"},
		{"https://[fe80::1%25eth0]", "", true, "a zone identifier, refused by the same bracket and percent rule"},
		{"https://bücher.example", "", true, "a non-ASCII host would be punycode to a browser, and SQL cannot do punycode"},
		{"https://emptyport.example.com:", "", true, "an empty port is '' to a browser, a different string from the one stored"},
		{"https://zeroport.example.com:0443", "", true, "'0443' and '443' are the same port and different strings; refused rather than converted"},
		{"https://bigport.example.com:99999", "", true, "above 65535, which the five-digit string comparison is what catches"},
		{"http://127.1", "", true, "a browser re-serializes this as 127.0.0.1, and SQL cannot do IPv4 expansion"},
		{"http://2130706433", "", true, "the same address as one decimal number"},
		{"http://0x7f000001", "", true, "the same address in hexadecimal, which is why the last label is tested for a 0x prefix as well as for digits"},
		{"http://256.1.1.1", "", true, "a label over 255 is not a valid IPv4 address and not a valid domain either"},
		{"http://010.0.0.1", "", true, "a leading zero is octal to the URL parser, so this is 8.0.0.1 to a browser"},
		{"http://1.2.3.4.5", "", true, "five parts, so the last label is a number and the host is not a dotted quad"},
		{"http://1.2.3.4.", "", true, "a browser drops the trailing dot when the host parses as IPv4, so it serializes differently"},
		{"ftp://example.com", "", true, "a scheme that is neither http nor https, which the old validator refused but a direct row need not have"},
		{"https://.leading.example.com", "", true, "an empty leading label"},
		{"https://a..inner.example.com", "", true, "an empty inner label"},
		{"https://escaped.example.com%2f", "", true, "a percent-escape, which a browser does not send in a host"},
		{"https://backslash.example.com\\path", "", true,
			"a backslash is a path separator for special schemes, so this is https://backslash.example.com to a browser; refused rather than cut, because the cut is '/', '?' and '#'"},
	}

	if isSQLite000034() {
		// Only sqlite can hold one: origin is TEXT there and 256 characters on the
		// other three, so the other engines refuse this value at insert.
		long := "https://" + strings.Repeat("a", webOriginColumnLimit000034) + ".example.com"
		cases = append(cases, repair000034{long, "", true,
			"a canonical origin over 256 characters is refused by the endpoint and removed here, rather than the three columns being widened four different ways (decision 14b)"})
	}

	// Decision 14's property, asserted rather than asserted-about: the set the
	// write path accepts is the set this migration repairs. A kept row's repaired
	// value is exactly what CanonicalOrigin returns and is its own fixed point; a
	// deleted row is one CanonicalOrigin refuses, or one whose canonical form
	// cannot be stored.
	for _, c := range cases {
		canonical, ok := urlutil.CanonicalOrigin(c.raw)
		if c.deleted {
			assert.Truef(t, !ok || len(canonical) > webOriginColumnLimit000034,
				"%q is deleted here, so the write path must refuse it too, or this migration is destroying a value the endpoint would accept", c.raw)
			continue
		}
		assert.Truef(t, ok, "%q is repaired here, so the write path must accept it", c.raw)
		assert.Equalf(t, c.want, canonical,
			"%q must repair to the same value the write path would store", c.raw)

		again, ok := urlutil.CanonicalOrigin(c.want)
		assert.Truef(t, ok && again == c.want,
			"%q must be its own canonical form, or the repair has not finished", c.want)
	}

	return cases
}

// assertWebOriginsIndex000034 checks the index's shape in the catalog and then
// checks that the engine actually enforces it.
func assertWebOriginsIndex000034(t *testing.T, h *isolatedDB, clientAId, clientBId int64, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "web_origins", webOriginsIndex000034)

	require.Truef(t, shape.Exists, "[%s] %s is missing", phase, webOriginsIndex000034)
	assert.Truef(t, shape.Unique,
		"[%s] %s must be UNIQUE: without it the table expresses no invariant at all", phase, webOriginsIndex000034)
	assert.Equalf(t, []string{"origin", "client_id"}, shape.Columns,
		"[%s] %s must lead with origin. The CORS lookup asks about an origin with no client in hand, "+
			"since a browser's preflight carries no client identity, so (client_id, origin) would enforce "+
			"the same invariant and be unusable by WebOriginExists", phase, webOriginsIndex000034)

	// Enforced, not merely declared.
	dup := &models.WebOrigin{Origin: "https://dup.example.com", ClientId: clientAId}
	assert.Errorf(t, h.DB.CreateWebOrigin(nil, dup),
		"[%s] a second row with the same origin for the same client must be refused", phase)

	// And enforced no more widely than that.
	spare := &models.WebOrigin{Origin: "https://spare.example.com", ClientId: clientBId}
	require.NoErrorf(t, h.DB.CreateWebOrigin(nil, spare),
		"[%s] an origin no client lists yet must still be insertable", phase)
	require.NoErrorf(t, h.DB.DeleteWebOrigin(nil, spare.Id), "[%s] clean up the spare row", phase)
}

func seedClient000034(t *testing.T, h *isolatedDB, identifier string) *models.Client {
	t.Helper()

	client := &models.Client{
		ClientIdentifier: identifier,
		Description:      "Migration 000034 test client",
	}
	require.NoErrorf(t, h.DB.CreateClient(nil, client), "seed client %s", identifier)
	return client
}

// seedWebOrigin000034 stores raw verbatim and returns its id. It goes through the
// ORM rather than raw SQL because the data layer stores what it is given: the
// validation this migration exists to backfill has only ever lived in the API
// handler.
func seedWebOrigin000034(t *testing.T, h *isolatedDB, clientId int64, raw string) int64 {
	t.Helper()

	webOrigin := &models.WebOrigin{Origin: raw, ClientId: clientId}
	require.NoErrorf(t, h.DB.CreateWebOrigin(nil, webOrigin), "seed web origin %q", raw)
	return webOrigin.Id
}

func isSQLite000034() bool {
	return dbType() == "" || dbType() == "sqlite"
}
