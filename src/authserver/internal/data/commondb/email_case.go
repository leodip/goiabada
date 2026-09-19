package commondb

import (
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

// ScanEmailCase reads every users row as its id, its stored address, and that address as THIS
// engine's own LOWER() reduces it. It is the whole of the read behind the startup pre-flight
// (datafactory.CheckEmailCaseBeforeMigrating) and does no comparing of its own, because the
// comparison is a Go rule and the engines disagree about the SQL one (#351).
//
// LOWER(email) is selected rather than computed, and that is the point of the method. Migration
// 000047 repairs exactly the rows its own `WHERE email <> LOWER(email)` selects, so the only way
// to know what it will miss is to ask the engine what it thinks LOWER(email) is and compare that
// against strings.ToLower. A predicate written here would be answering with the engine that is
// running rather than about it.
//
// The whole table, unfiltered: the caller needs both hazards off one read. A filter would leave
// the collision check unable to see the lowercase twin of a mixed-case address, which is the row
// that makes it a collision. It runs once per upgrade, before the migration chain, and never
// again afterwards.
func (d *CommonDatabase) ScanEmailCase() ([]models.EmailCaseRow, error) {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email", "LOWER(email)").From("users")
	query, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := d.QuerySql(nil, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query users for the email case pre-flight")
	}
	defer func() { _ = rows.Close() }()

	var result []models.EmailCaseRow
	for rows.Next() {
		var row models.EmailCaseRow
		if err := rows.Scan(&row.Id, &row.Email, &row.EngineLowered); err != nil {
			return nil, errs.Wrap(err, "unable to scan a user email for the email case pre-flight")
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "error iterating users for the email case pre-flight")
	}

	return result, nil
}
