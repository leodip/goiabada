package data

// The cross-engine comparison pointed at the four files that are actually committed (#284,
// seam 3, goals 2 and 3). schema_parity_test.go is the machinery and
// schema_parity_cases_test.go exercises it against synthetic shapes; this is the one place
// the real schema is judged.
//
// It runs in the modules tier with no database, on every CI job rather than only the four
// database ones, because the golden files are the whole input. What makes that trustworthy
// is the other half of the pair: the data tier regenerates each file from a freshly migrated
// database of its own engine and fails if the committed bytes differ, so a file that has
// drifted from the schema it describes is caught there, and everything here is a claim about
// the schema rather than about the files.
//
// The allowlist below is the written record goal 3 asks for: every place the four engines
// deliberately differ, why, and how many places the rule excuses. A rule with no count goes
// on excusing whatever grows under it, which is how a missing length that was a mistake ends
// up indistinguishable from the eighty-nine that were not.

import (
	"os"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/data/schemadump"
	"github.com/stretchr/testify/require"
)

// TestSchemaParity_TheFourCommittedGoldenFiles is #284's goal 2: the four engines build one
// schema, modulo the allowlist.
//
// A failure here is one of three things and the message says which. An unexcused divergence
// is a migration that built something different on one engine, and it is the finding this
// whole change exists to produce. A rule whose count or digest has moved is an idiom that
// has spread, or one place accepted under it being corrected while another appeared; either
// way somebody has to look before the number is updated. A rule excusing what another rule
// already excuses makes both counts meaningless and is refused rather than resolved by
// declaration order.
func TestSchemaParity_TheFourCommittedGoldenFiles(t *testing.T) {
	dumps := map[schemadump.Dialect]schemadump.Schema{}
	for _, d := range parityDialects {
		path, err := schemadump.GoldenPath(d)
		require.NoErrorf(t, err, "locate the %s golden file", d)

		committed, err := os.ReadFile(path)
		require.NoErrorf(t, err, "read %s", path)

		// g.Migrated is deliberately not read here. The four numbers legitimately differ,
		// postgres 39, mssql 40, mysql 42, sqlite 43 at the time of writing, because a
		// migration is free to land on fewer than four engines. checkParity takes
		// map[Dialect]Schema, so the comparison cannot see it even by accident; holding the
		// number to the migrations on disk is the source lint's job (#288).
		g, err := schemadump.Parse(committed)
		require.NoErrorf(t, err, "parse %s", path)
		require.Equalf(t, d, g.Dialect, "%s records the engine it is committed for", path)
		dumps[d] = g.Schema
	}

	problems := checkParity(dumps, parityAllowlist())
	if len(problems) == 0 {
		return
	}
	t.Fatalf("the four engines do not build the same schema:\n\n%s\n\n"+
		"Every entry above is either an idiom that belongs on the allowlist in this file, with "+
		"its reason and its count, or a migration to write. #284 decision 6 says a divergence is "+
		"fixed on the branch that found it and never recorded as a known defect.\n"+
		"If the golden files themselves are stale, regenerate them with:\n"+
		"  cd src/core && go run ./cmd/schemadump",
		strings.Join(problems, "\n\n"))
}

// parityAllowlist is every place the four engines are deliberately allowed to differ.
//
// Eleven rules covering 339 places. It is few rules and many instances on purpose: a
// difference in VOCABULARY, TEXT against varchar(256) against nvarchar(256), or the four
// collation names, is a mapping in canonicalType and canonicalCollation and never a rule
// here. What reaches this list is what survives canonicalisation, which is a real difference
// in what the column accepts or in what the engine built, kept because levelling it would
// cost more than it buys.
//
// Every predicate is written so exactly one rule matches a given divergence. Two rules
// matching is a failure rather than a first-match win, because a divergence quietly landing
// under whichever rule was declared first makes both counts mean nothing.
func parityAllowlist() []parityRule {
	return []parityRule{
		{
			Name: "sqlite: a datetime carries no declared fractional-second precision",
			Why: "SQLite has no datetime type at all. The migrations declare DATETIME and it is " +
				"stored as whatever the driver writes, which is the same microsecond text the " +
				"other three keep in datetime(6). Declaring a precision there would be a lie " +
				"about a type SQLite does not enforce.",
			Count:  66,
			Digest: "34ea9de54fca616e",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.SQLite) &&
					d.Says[schemadump.SQLite] == "datetime(no declared precision)" &&
					strings.HasPrefix(d.Says[schemadump.MySQL], "datetime(")
			},
		},
		{
			Name: "sqlite: a string column carries no declared length",
			Why: "SQLite declares TEXT and applies no length limit whatever the declaration says, " +
				"so a width there would be documentation the engine ignores. The other three " +
				"enforce theirs, which is why this is recorded as a difference rather than " +
				"folded onto unbounded: SQLite really does store a value SQL Server would refuse.",
			Count:  91,
			Digest: "2342129c9784da64",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.SQLite) &&
					d.Says[schemadump.SQLite] == "string(no declared length)" &&
					strings.HasPrefix(d.Says[schemadump.MySQL], "string(")
			},
		},
		{
			Name: "mysql: an id column is bigint unsigned where the other three are signed",
			Why: "The initial MySQL migration declared every primary key bigint unsigned and the " +
				"other three declared theirs signed. It is a real difference in the range the " +
				"column accepts, and it is one-directional: every value the signed three can " +
				"hold fits here. Changing it would rebuild all 25 tables and their foreign keys " +
				"to buy nothing an installation can observe.",
			Count:  50,
			Digest: "008dd98d1685290b",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.MySQL) &&
					d.Says[schemadump.MySQL] == "uint64" && d.Says[schemadump.SQLite] == "int64"
			},
		},
		{
			Name: "sqlite: a boolean is declared numeric",
			Why: "SQLite has no boolean type and stores 0 and 1 whatever the column is declared " +
				"as. The migrations spelled some of these NUMERIC and some INTEGER, which the " +
				"catalog reports verbatim; both accept exactly what the data layer writes.",
			Count:  19,
			Digest: "91d0722568988b8c",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.SQLite) &&
					d.Says[schemadump.SQLite] == "numeric" && d.Says[schemadump.MySQL] == "bool"
			},
		},
		{
			Name: "sqlite: a boolean is declared INTEGER",
			Why: "The other spelling of the rule above, kept apart from it so the two counts move " +
				"independently: a column changing from one to the other is a migration somebody " +
				"wrote, and a single rule covering both would absorb it silently.",
			Count:  11,
			Digest: "035e7590db34c34d",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.SQLite) &&
					d.Says[schemadump.SQLite] == "int64" && d.Says[schemadump.MySQL] == "bool"
			},
		},
		{
			Name: "sqlite: a 32-bit integer is declared INTEGER, which is 64-bit",
			Why: "SQLite stores every integer in up to 8 bytes and its INTEGER declaration says " +
				"nothing about width. The columns are counters and enumerations the data layer " +
				"writes as Go ints, so the narrower declaration on the other three is the " +
				"binding one and SQLite accepts everything it can produce.",
			Count:  8,
			Digest: "818505b5881de1aa",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisType && oddOneOut(d, schemadump.SQLite) &&
					d.Says[schemadump.SQLite] == "int64" && d.Says[schemadump.MySQL] == "int32"
			},
		},
		{
			Name: "sqlite: no index object behind a rowid primary key",
			Why: "Every table declares its key integer PRIMARY KEY AUTOINCREMENT, which SQLite " +
				"makes an alias for the rowid rather than a separate index, so its catalog " +
				"reports no index at all where the other three report one per primary key. The " +
				"uniqueness is enforced identically; only the object is absent. A composite " +
				"primary key would produce an index here, and the schema has none.",
			Count:  25,
			Digest: "bd2874790cb8a4fb",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisIndex && oddOneOut(d, schemadump.SQLite) &&
					d.Object == "unique index(id)" && d.Says[schemadump.SQLite] == "absent"
			},
		},
		{
			Name: "mysql: InnoDB indexes every foreign key and the other three do not",
			Why: "InnoDB requires an index over a foreign key's columns and creates one when the " +
				"migration does not, so MySQL carries an index the other three were never asked " +
				"for. Adding the same indexes elsewhere is a performance change with its own " +
				"risk and its own measurement, which #282 deferred and #284 keeps out of scope. " +
				"One place left this rule rather than being added to it: #139 needed " +
				"user_session_clients(client_id) indexed on the other three, for a read " +
				"DeleteClient now makes, so 000044 creates it there and renames MySQL's " +
				"fk_user_session_clients_client to match.",
			Count:  17,
			Digest: "49bf86090a71d4ad",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisIndex && oddOneOut(d, schemadump.MySQL) &&
					d.Says[schemadump.MySQL] == "present" && d.Says[schemadump.SQLite] == "absent"
			},
		},
		{
			Name: "sqlite: the rowid primary key reports as nullable",
			Why: "pragma_table_info reports notnull=0 for an INTEGER PRIMARY KEY because SQLite " +
				"substitutes a generated rowid for a NULL rather than refusing it. No NULL is " +
				"ever stored, so the column behaves exactly like the NOT NULL the other three " +
				"declare; the catalog is describing how the value arrives, not what it accepts.",
			Count:  25,
			Digest: "92e76f8deff4188f",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisNullable && oddOneOut(d, schemadump.SQLite) &&
					d.Object == "id" && d.Says[schemadump.SQLite] == "nullable"
			},
		},
		{
			Name: "postgres: BIGSERIAL leaves a nextval() default the other three do not have",
			Why: "BIGSERIAL is sugar for a sequence plus a default that draws from it, so " +
				"PostgreSQL numbers its keys through a default where MySQL uses AUTO_INCREMENT, " +
				"SQL Server uses IDENTITY and SQLite uses AUTOINCREMENT. The property that " +
				"matters, that the engine numbers the column, is compared on its own axis and " +
				"agrees on all four; what is left here is where each engine keeps it.",
			Count:  25,
			Digest: "05d89eec488996c9",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisDefault && oddOneOut(d, schemadump.Postgres) &&
					strings.HasPrefix(d.Says[schemadump.Postgres], `default "nextval(`) &&
					d.Says[schemadump.SQLite] == "no default"
			},
		},
		{
			Name: "mysql: audit_logs.details records its default with a charset introducer",
			Why: "MySQL refuses a literal default on a LONGTEXT column, so 000037 had to write it " +
				"as an expression, and MySQL stamps an expression default with the DDL " +
				"connection's character set. The catalog reads _utf8mb4'{}' where the other " +
				"three read '{}'. Same effect, different recorded text, and nothing exercises " +
				"the default on any engine because every insert supplies a value.",
			Count:  1,
			Digest: "3dcfa8347268e73a",
			Excuses: func(d parityDivergence) bool {
				return d.Axis == parityAxisDefault && oddOneOut(d, schemadump.MySQL) &&
					d.Table == "audit_logs" && d.Object == "details" &&
					strings.Contains(d.Says[schemadump.MySQL], "_utf8mb4")
			},
		},
	}
}

// TestSchemaParity_AllowlistRefusesATwoEngineDivergence pins the boundary every rule above
// rests on: a rule excuses one engine's idiom, and stops excusing anything the moment a
// second engine drifts onto the same answer.
//
// The fixture is the defect this stage found, restored: audit_logs.details declared TEXT on
// MySQL capped it at 64 KiB while SQLite declared no length and the other two were
// unbounded. Two engines out of line rather than one, and no rule may excuse it, because the
// SQLite reading and the MySQL reading are the same words for two entirely different facts.
// Migration 000042 is what fixed it; this is what would have caught it.
func TestSchemaParity_AllowlistRefusesATwoEngineDivergence(t *testing.T) {
	before := parityDivergence{
		Table: "audit_logs", Object: "details", Axis: parityAxisType,
		Says: map[schemadump.Dialect]string{
			schemadump.SQLite:   "string(no declared length)",
			schemadump.MySQL:    "string(65535)",
			schemadump.Postgres: "string(unbounded)",
			schemadump.MSSQL:    "string(unbounded)",
		},
	}
	_, unexcused, conflicts := applyAllowlist([]parityDivergence{before}, parityAllowlist())
	require.Empty(t, conflicts, "the fixture must not be excused twice either")
	require.Len(t, unexcused, 1,
		"MySQL's 64 KiB ceiling was a defect and no allowlist rule may cover it: %v", unexcused)

	// The same divergence after 000042, where MySQL agrees with the two unbounded engines
	// and SQLite's undeclared length is the only idiom left. That one IS excused, which is
	// what says the rule above is refusing the second odd engine rather than the shape.
	after := before
	after.Says = map[schemadump.Dialect]string{
		schemadump.SQLite:   "string(no declared length)",
		schemadump.MySQL:    "string(unbounded)",
		schemadump.Postgres: "string(unbounded)",
		schemadump.MSSQL:    "string(unbounded)",
	}
	_, unexcused, conflicts = applyAllowlist([]parityDivergence{after}, parityAllowlist())
	require.Empty(t, conflicts)
	require.Emptyf(t, unexcused,
		"after 000042 only SQLite is out of line, which the missing-length rule covers")
}

// oddOneOut reports whether want is the only engine giving a different answer, which is the
// shape every rule above is written for: three engines agreeing and one idiom.
//
// Rules ask this rather than naming the three agreeing answers one by one, so a second engine
// drifting onto the odd one's answer stops being excused instead of being absorbed. That is
// not hypothetical: audit_logs.details had SQLite declaring no length, MySQL capped at 64 KiB
// and the other two unbounded, which is two odd ones out and a defect that #284 fixed rather
// than allowlisted (migration 000042).
func oddOneOut(d parityDivergence, want schemadump.Dialect) bool {
	var others []string
	for _, dialect := range parityDialects {
		if dialect == want {
			continue
		}
		others = append(others, d.Says[dialect])
	}
	for _, s := range others {
		if s != others[0] || s == d.Says[want] {
			return false
		}
	}
	return true
}
