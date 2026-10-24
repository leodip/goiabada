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
// negative, and a negative offset is never the empty page the caller asked for.
// Every read binds the offset as a parameter, and the engines disagree about a
// negative one: SQLite reads it as no offset at all and returns the FIRST
// page's rows, labelled as the page that was asked for, a wrong answer rather
// than an error and the quieter of the two, while SQL Server refuses it -- "The
// offset specified in a OFFSET clause may not be negative" -- and the API turns
// the refusal into a 500.
//
// When #305 found it the split ran differently: six of the seven reads went
// through the query builder the data layer used until #644, whose Offset
// dropped the clause when its argument was negative, so three engines answered
// with the first page, and the seventh, the SQL Server audit log override,
// formatted the number into the statement and was refused.
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
