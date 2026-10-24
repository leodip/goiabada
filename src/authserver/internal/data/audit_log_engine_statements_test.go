package data_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The audit-log statements the engine packages write themselves, held to the text each engine
// receives and the arguments it binds (#644): each engine's own cleanup, which commondb does not
// declare (#438 decision 7), and SQL Server's page, which closes `=`'s padding in the statement
// (#328). commondb's statements are read by its own scripted-driver tests; these four packages'
// are read here, over a connector that records what reaches it.

var auditCutoff = time.Date(2005, 5, 5, 0, 0, 0, 0, time.UTC)

func TestDeleteOldAuditLogs_EachEngineSendsItsOwnBoundedDelete(t *testing.T) {
	t.Parallel()

	for _, engine := range []struct {
		name string
		open func(db *sql.DB) data.Database
		want string
	}{
		{"sqlite", func(db *sql.DB) data.Database {
			return &sqlitedb.Database{Database: commondb.New(db, data.SQLite, false)}
		}, "DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?)"},
		{"mysql", func(db *sql.DB) data.Database {
			return &mysqldb.Database{Database: commondb.New(db, data.MySQL, false)}
		}, "DELETE FROM audit_logs WHERE created_at < ? ORDER BY id LIMIT ?"},
		{"postgres", func(db *sql.DB) data.Database {
			return &postgresdb.Database{Database: commondb.New(db, data.Postgres, false)}
		}, "DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < $1 LIMIT $2)"},
		{"mssql", func(db *sql.DB) data.Database {
			return &mssqldb.Database{Database: commondb.New(db, data.MSSQL, false)}
		}, "DELETE TOP (@p2) FROM audit_logs WHERE created_at < @p1"},
	} {
		t.Run(engine.name, func(t *testing.T) {
			t.Parallel()
			connector := &recordingConnector{}
			db := sql.OpenDB(connector)
			t.Cleanup(func() { _ = db.Close() })

			if _, err := engine.open(db).DeleteOldAuditLogs(context.Background(), nil, auditCutoff, 25); err != nil {
				t.Fatalf("DeleteOldAuditLogs: %v", err)
			}

			assertRecorded(t, connector, []recordedStatement{{engine.want, []driver.Value{auditCutoff, int64(25)}}})
		})
	}
}

// TestGetAuditLogsPaginated_SQLServerClosesThePaddingInBothStatements holds SQL Server's page to
// each filter it is given: the request id compared as bytes beside the equality in the page and in
// the count alike, the total order, and the offset and the page size bound to OFFSET … FETCH.
func TestGetAuditLogsPaginated_SQLServerClosesThePaddingInBothStatements(t *testing.T) {
	t.Parallel()

	const columns = "SELECT id, created_at, audit_event, details, request_id FROM audit_logs"

	for _, c := range []struct {
		name                  string
		auditEvent, requestId string
		page, count           recordedStatement
	}{
		{
			name: "no filter",
			page: recordedStatement{columns + " ORDER BY created_at DESC, id DESC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY",
				[]driver.Value{int64(20), int64(10)}},
			count: recordedStatement{"SELECT COUNT(*) FROM audit_logs", nil},
		},
		{
			name:       "by event",
			auditEvent: "user_created",
			page: recordedStatement{columns + " WHERE audit_event = @p1 ORDER BY created_at DESC, id DESC OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY",
				[]driver.Value{"user_created", int64(20), int64(10)}},
			count: recordedStatement{"SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1", []driver.Value{"user_created"}},
		},
		{
			name:      "by request id",
			requestId: "req-1",
			page: recordedStatement{columns + " WHERE request_id = @p1 AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512)) " +
				"ORDER BY created_at DESC, id DESC OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY",
				[]driver.Value{"req-1", int64(20), int64(10)}},
			count: recordedStatement{"SELECT COUNT(*) FROM audit_logs WHERE request_id = @p1 " +
				"AND CAST(request_id AS VARBINARY(512)) = CAST(@p1 AS VARBINARY(512))", []driver.Value{"req-1"}},
		},
		{
			name:       "by event and request id",
			auditEvent: "user_created",
			requestId:  "req-1",
			page: recordedStatement{columns + " WHERE audit_event = @p1 AND request_id = @p2 " +
				"AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512)) " +
				"ORDER BY created_at DESC, id DESC OFFSET @p3 ROWS FETCH NEXT @p4 ROWS ONLY",
				[]driver.Value{"user_created", "req-1", int64(20), int64(10)}},
			count: recordedStatement{"SELECT COUNT(*) FROM audit_logs WHERE audit_event = @p1 AND request_id = @p2 " +
				"AND CAST(request_id AS VARBINARY(512)) = CAST(@p2 AS VARBINARY(512))",
				[]driver.Value{"user_created", "req-1"}},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			want := record.AuditLog{Id: 41, CreatedAt: auditCutoff, AuditEvent: "the event", Details: "{}", RequestId: "the request"}
			connector := &recordingConnector{answer: func(query string) (cols []string, values [][]driver.Value) {
				if strings.HasPrefix(query, "SELECT COUNT(*)") {
					return []string{"count"}, [][]driver.Value{{int64(57)}}
				}
				return []string{"id", "created_at", "audit_event", "details", "request_id"},
					[][]driver.Value{{want.Id, want.CreatedAt, want.AuditEvent, want.Details, want.RequestId}}
			}}
			db := sql.OpenDB(connector)
			t.Cleanup(func() { _ = db.Close() })
			d := &mssqldb.Database{Database: commondb.New(db, data.MSSQL, false)}

			logs, total, err := d.GetAuditLogsPaginated(context.Background(), nil, 3, 10, c.auditEvent, c.requestId)
			if err != nil {
				t.Fatalf("GetAuditLogsPaginated: %v", err)
			}

			assertRecorded(t, connector, []recordedStatement{c.page, c.count})
			if len(logs) != 1 || !reflect.DeepEqual(logs[0], want) {
				t.Errorf("logs = %+v, want each column in its own field: %+v", logs, want)
			}
			if total != 57 {
				t.Errorf("total = %d, want the count's 57", total)
			}
		})
	}
}

// recordedStatement is one statement as it reached the connector, and the values it bound.
type recordedStatement struct {
	query string
	args  []driver.Value
}

func assertRecorded(t *testing.T, c *recordingConnector, want []recordedStatement) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.recorded) != len(want) {
		t.Fatalf("%d statements reached the engine, want %d: %+v", len(c.recorded), len(want), c.recorded)
	}
	for i := range want {
		got := c.recorded[i]
		if got.query != want[i].query {
			t.Errorf("statement %d:\n got %s\nwant %s", i+1, got.query, want[i].query)
		}
		if len(got.args) != len(want[i].args) {
			t.Errorf("statement %d binds %v, want %v", i+1, got.args, want[i].args)
			continue
		}
		for j := range got.args {
			if !reflect.DeepEqual(got.args[j], want[i].args[j]) {
				t.Errorf("statement %d argument %d is %#v, want %#v", i+1, j+1, got.args[j], want[i].args[j])
			}
		}
	}
}

// recordingConnector is a database/sql connector that records every statement and its values,
// answers every write as having changed one row, and answers every read with what answer gives
// for it, or no rows. It implements ExecerContext and QueryerContext, so database/sql hands it the
// statement directly and prepares nothing.
type recordingConnector struct {
	answer   func(query string) (cols []string, values [][]driver.Value)
	mu       sync.Mutex
	recorded []recordedStatement
}

func (c *recordingConnector) Connect(context.Context) (driver.Conn, error) {
	return &recordingConn{c}, nil
}
func (c *recordingConnector) Driver() driver.Driver { return failingDriver{} }

func (c *recordingConnector) record(query string, args []driver.NamedValue) {
	values := make([]driver.Value, len(args))
	for i, a := range args {
		values[i] = a.Value
	}
	if len(values) == 0 {
		values = nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recorded = append(c.recorded, recordedStatement{query, values})
}

type recordingConn struct{ c *recordingConnector }

func (r *recordingConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	r.c.record(query, args)
	return driver.RowsAffected(1), nil
}

func (r *recordingConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	r.c.record(query, args)
	rows := &recordedRows{}
	if r.c.answer != nil {
		rows.cols, rows.values = r.c.answer(query)
	}
	return rows, nil
}

func (r *recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("recordingConn prepares nothing")
}
func (r *recordingConn) Close() error { return nil }
func (r *recordingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("recordingConn opens no transaction")
}

type recordedRows struct {
	cols   []string
	values [][]driver.Value
	next   int
}

func (r *recordedRows) Columns() []string { return r.cols }
func (r *recordedRows) Close() error      { return nil }
func (r *recordedRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.next])
	r.next++
	return nil
}
