package commondb

import "math"

// PageOffset is how many rows a query must skip to reach page, at pageSize rows
// to a page. It is (page-1)*pageSize, saturated so that product can never
// overflow.
//
// The saturation is the point. A page number arrives from a "?page=" query
// parameter -- the admin console's, and the auth server admin API's, which
// validated it as "> 0" and nothing more -- and reaches every paginated read
// through this multiplication. At a page near math.MaxInt the product wraps
// negative, and a negative offset goes two different ways, neither of them the
// empty page the caller asked for (#305):
//
//   - Through sqlbuilder, which is six of the seven reads: SelectBuilder.Offset
//     drops the clause entirely when its argument is negative (select.go:316).
//     The query then runs with no offset at all and returns the FIRST page's
//     rows, labelled as the page that was asked for. A wrong answer rather than
//     an error, and the quieter of the two.
//   - Through the SQL Server audit log override in mssqldb, which formats the
//     number into the statement itself and so has no such guard: SQL Server
//     rejects it -- "The offset specified in a OFFSET clause may not be
//     negative" -- and the API turns that into a 500.
//
// Saturating gives the answer every other page past the end already gets: no
// rows, and the total beside them. The largest multiple of pageSize that fits
// in an int is past the end of any table that will ever exist, so the query is
// well formed and returns nothing.
//
// It normalises page and pageSize itself, so it is correct wherever it is
// called from. Callers keep their own guards because pageSize is also the LIMIT
// and has to be normalised for that too.
func PageOffset(page, pageSize int) int {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 1
	}

	// page-1 cannot overflow, since page is at least 1, and the division is
	// exact, so this is the whole of the overflow check: the product fits
	// exactly when page-1 is at most math.MaxInt/pageSize.
	if page-1 > math.MaxInt/pageSize {
		return math.MaxInt / pageSize * pageSize
	}
	return (page - 1) * pageSize
}
