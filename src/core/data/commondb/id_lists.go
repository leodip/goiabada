package commondb

// maxIdsPerStatement bounds how many ids one id-list lookup puts into a single statement. Every
// id in an IN list is a bound parameter, and SQL Server refuses a statement carrying more than
// 2,100 of them with error 8003, which is the lowest ceiling of the four supported engines:
// modernc.org/sqlite allows 32,766, PostgreSQL 65,535, and MySQL bounds the statement's size
// rather than its parameter count. Without a bound, a caller holding more ids than one statement
// can carry gets an error rather than its rows, which reached the three session list endpoints as
// an HTTP 500 on a request that was entirely valid (#373).
//
// ceiling: one budget for all four engines rather than each engine's own, so a list of 1,001 to
// 2,100 ids costs two statements on the three engines that would have taken it in one, and a list
// read in several statements is no longer one snapshot -- a row deleted between two of them is
// absent from the result, which is what the same delete already does between loading a session
// and loading its clients. Revisit when a deployment is measured spending real time on the extra
// round trip; a per-flavor budget is the next shape, and it owes a data tier case per engine.
const maxIdsPerStatement = 1000

// forEachIdBatch calls fn once per batch of ids that one statement may carry, and is how every
// id-list lookup in this package issues its query. It exists so the budget above has one home:
// a constant per file is a budget nobody can change in one place, and twelve lookups went on
// expanding without one until the thirteenth crashed and was fixed alone (#373).
//
// The ids are deduplicated first, and that is correctness rather than economy. One IN list
// answers a repeated id once; split across two statements, the same id on either side of the
// boundary comes back twice, and the caller cannot tell two copies of one row from two rows.
// That holds whether the column is the table's own id or a parent's: a repeated parent id
// returns every one of its children a second time.
//
// fn receives a batch that is never empty, so a caller's own "no ids, no query" answer stays its
// own: an empty list calls fn zero times, and the lookups differ on what they return for it.
// Each batch is a window into one slice and is not retained.
func forEachIdBatch(ids []int64, fn func(batch []int64) error) error {

	unique := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if _, alreadySeen := seen[id]; alreadySeen {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}

	for start := 0; start < len(unique); start += maxIdsPerStatement {
		end := start + maxIdsPerStatement
		if end > len(unique) {
			end = len(unique)
		}

		if err := fn(unique[start:end]); err != nil {
			return err
		}
	}

	return nil
}
