package data

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

// LowercaseEmailsVersion is migration 000047, which brings every stored users.email down to its
// lowercase form. The pre-flight below is about that one migration, so the number is here rather
// than derived: a later migration renumbering this one would have to move the check with it.
const LowercaseEmailsVersion = 47

// CheckEmailCaseBeforeMigrating refuses an upgrade that crosses migration 000047 when the stored
// addresses hold something that migration cannot resolve, and leaves the database untouched when
// it does: not migrated, not dirty, schema_migrations unchanged (#351 decision 16).
//
// WHY REFUSING RATHER THAN REPAIRING. The repair this replaced picked a survivor out of a case
// collision, disabled the other rows and destroyed their credentials, at startup, with nobody
// asking. A collision cannot pre-exist on MySQL or SQL Server, whose UNIQUE idx_email held a
// folding collation until 000040 relaxed it, and on SQLite and PostgreSQL a colliding row already
// cannot sign in because both have compared byte-wise all along. So the machinery only ever acted
// on rows that were already broken, and the honest answer is to stop and say which ones.
//
// WHY BEFORE Migrate() RATHER THAN LETTING 000047 FAIL. The migrator writes a dirty marker before
// each file runs and clears it after, and a dirty database refuses to start with ErrDirty. The
// migrate subcommand has no force verb, so recovery would mean hand-editing schema_migrations in
// SQL. Checking before anything is written means that state never occurs.
//
// THE VERSIONS ARE PARAMETERS, not something read off a migrator in here, so that each skip is
// policy a test can drive rather than a state only a real database can produce. recorded is what
// schema_migrations holds, migrator.NilVersion when it holds nothing; target is where the caller
// is about to step to.
//
// It skips, returning nil without reading anything, when:
//
//   - recorded is NilVersion. A database that has never been migrated has no users table, so
//     there is nothing to read and nothing 000047 can collide with.
//   - recorded is at or above 000047. The migration has already run; it does not run twice.
//   - target is below 000047. The step does not cross it, which covers `migrate version`, every
//     downward step, and an upward step that stops short.
//
// Otherwise it reads the table once and refuses on either hazard, naming every offending row.
//
// It does NOT make the migration unable to fail, and cannot: it is a scan, and another process
// still serving traffic can insert the lowercase twin of a legacy address between this read and
// 000047's UPDATE. #351 decision 18 answered that with downtime and a release note rather than
// machinery, so an upgrade across 000047 wants traffic stopped first.
func CheckEmailCaseBeforeMigrating(database Database, recorded int, target int) error {
	if recorded == migrator.NilVersion || recorded >= LowercaseEmailsVersion {
		return nil
	}
	if target < LowercaseEmailsVersion {
		return nil
	}

	rows, err := database.ScanEmailCase()
	if err != nil {
		return errs.Wrap(err, "unable to read stored email addresses before migrating")
	}

	collisions := findEmailCaseCollisions(rows)
	unreachable := findEnginesLowerDisagreements(rows)
	if len(collisions) == 0 && len(unreachable) == 0 {
		return nil
	}

	return errs.New(describeEmailCaseHazards(collisions, unreachable))
}

// findEmailCaseCollisions groups the rows by their Go lowercase form and returns every group
// holding more than one row, each group sorted by id and the groups sorted by address.
//
// Go's strings.ToLower decides the grouping, not the engine's, because the collision that
// matters is the one 000047's UPDATE would create: two rows whose repaired values are equal are
// two rows the UNIQUE index cannot both hold afterwards.
func findEmailCaseCollisions(rows []models.EmailCaseRow) [][]models.EmailCaseRow {
	byLowered := map[string][]models.EmailCaseRow{}
	for _, row := range rows {
		lowered := strings.ToLower(row.Email)
		byLowered[lowered] = append(byLowered[lowered], row)
	}

	lowered := make([]string, 0, len(byLowered))
	for key, group := range byLowered {
		if len(group) > 1 {
			lowered = append(lowered, key)
		}
	}
	sort.Strings(lowered)

	groups := make([][]models.EmailCaseRow, 0, len(lowered))
	for _, key := range lowered {
		group := byLowered[key]
		sort.Slice(group, func(i, j int) bool { return group[i].Id < group[j].Id })
		groups = append(groups, group)
	}
	return groups
}

// findEnginesLowerDisagreements returns the rows migration 000047 will not repair even though Go
// says they need repairing: the engine's own LOWER() left something strings.ToLower would have
// reduced, so `WHERE email <> LOWER(email)` either does not select the row or selects it and
// writes a value that is still not the form a credential path looks up.
//
// Engine-agnostic on purpose. SQLite is the widest instance, mapping ASCII only through
// modernc.org/sqlite, and SQL Server leaves U+1E9E and U+212A unchanged at the collation 000040
// installs; MySQL and PostgreSQL agree with Go on both. Written as a comparison rather than as a
// character list, it also covers whatever a future engine, driver or collation does.
func findEnginesLowerDisagreements(rows []models.EmailCaseRow) []models.EmailCaseRow {
	var found []models.EmailCaseRow
	for _, row := range rows {
		if row.EngineLowered != strings.ToLower(row.Email) {
			found = append(found, row)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Id < found[j].Id })
	return found
}

// describeEmailCaseHazards writes the one message an operator gets. It names every offending row
// by id and address and says what to do about it, because this refusal stops a deployment and
// the alternative is an operator who knows only that the server will not start.
//
// Every row rather than the first: two collisions are two separate hand fixes, and a message
// naming one of them turns a single outage into two.
func describeEmailCaseHazards(collisions [][]models.EmailCaseRow, unreachable []models.EmailCaseRow) string {
	var b strings.Builder

	fmt.Fprintf(&b,
		"refusing to migrate: schema version %06d lowercases every stored email address, and the "+
			"users table holds rows it cannot resolve. Nothing has been migrated and the database is "+
			"not dirty. Fix the rows below and start again.", LowercaseEmailsVersion)

	if len(collisions) > 0 {
		b.WriteString("\n\ntwo or more accounts differ only by case, so lowercasing them would " +
			"collide on the UNIQUE index idx_email. Decide which account keeps the address and " +
			"change or delete the others; this server will not choose for you:")
		for _, group := range collisions {
			fmt.Fprintf(&b, "\n  %q is held by:", strings.ToLower(group[0].Email))
			for _, row := range group {
				fmt.Fprintf(&b, "\n    users.id=%d email=%q", row.Id, row.Email)
			}
		}
	}

	if len(unreachable) > 0 {
		b.WriteString("\n\nthis database engine's own LOWER() does not reduce these addresses the " +
			"way Goiabada does, so the migration would report success and leave them unreachable by " +
			"every sign-in path. Lowercase them by hand, then start again:")
		for _, row := range unreachable {
			fmt.Fprintf(&b, "\n  users.id=%d email=%q, engine LOWER() gives %q, Goiabada needs %q",
				row.Id, row.Email, row.EngineLowered, strings.ToLower(row.Email))
		}
	}

	return b.String()
}
