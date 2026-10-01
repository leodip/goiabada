package data_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// TestDeleteOldAuditLogs_EveryEngineWrapsBothFailures holds the four engines' DeleteOldAuditLogs to
// one error shape. Each engine writes its own since commondb stopped declaring one (#438 decision
// 7), so each has its own two exits, and until #438 MySQL's and SQLite's returned both errors bare.
//
// No data-tier case can tell a wrapped error from a bare one: those check the count and
// errors.Is(err, context.Canceled), which pass either way. And no real engine can be asked for the
// second failure: go-sql-driver/mysql v1.10.1's RowsAffected never fails. So each adapter is built
// over failingConnector, which knows no SQL and answers every statement with what the case asks.
func TestDeleteOldAuditLogs_EveryEngineWrapsBothFailures(t *testing.T) {
	t.Parallel()

	engines := []struct {
		name string
		open func(db *sql.DB) data.Database
	}{
		{"sqlite", func(db *sql.DB) data.Database {
			return &sqlitedb.Database{Database: commondb.New(db, sqlbuilder.SQLite, false)}
		}},
		{"mysql", func(db *sql.DB) data.Database {
			return &mysqldb.Database{Database: commondb.New(db, sqlbuilder.MySQL, false)}
		}},
		{"postgres", func(db *sql.DB) data.Database {
			return &postgresdb.Database{Database: commondb.New(db, sqlbuilder.PostgreSQL, false)}
		}},
		{"mssql", func(db *sql.DB) data.Database {
			return &mssqldb.Database{Database: commondb.New(db, sqlbuilder.SQLServer, false)}
		}},
	}

	cause := errors.New("injected driver failure")

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range []struct {
				name       string
				connector  *failingConnector
				wantPrefix string
			}{
				{"the statement fails", &failingConnector{execErr: cause}, "unable to delete old audit logs: "},
				{"the rows-affected read fails", &failingConnector{rowsAffectedErr: cause}, "unable to get rows affected: "},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					db := sql.OpenDB(tc.connector)
					t.Cleanup(func() { _ = db.Close() })

					deleted, err := engine.open(db).DeleteOldAuditLogs(context.Background(), nil, time.Now().UTC(), 10)

					if err == nil {
						t.Fatal("DeleteOldAuditLogs returned no error over a failing driver")
					}
					if deleted != 0 {
						t.Errorf("deleted = %d, want 0 alongside an error", deleted)
					}
					if !strings.HasPrefix(err.Error(), tc.wantPrefix) {
						t.Errorf("error %q does not start with %q", err.Error(), tc.wantPrefix)
					}
					if !errors.Is(err, cause) {
						t.Errorf("errors.Is does not reach the driver's error through %q", err.Error())
					}
				})
			}

			// The success row, so the two failure rows are known to be the only thing the connector
			// changed: the same adapter over a driver that succeeds answers the driver's count.
			t.Run("the driver's count is returned", func(t *testing.T) {
				t.Parallel()
				db := sql.OpenDB(&failingConnector{rowsAffected: 7})
				t.Cleanup(func() { _ = db.Close() })

				deleted, err := engine.open(db).DeleteOldAuditLogs(context.Background(), nil, time.Now().UTC(), 10)

				if err != nil {
					t.Fatalf("DeleteOldAuditLogs: %v", err)
				}
				if deleted != 7 {
					t.Errorf("deleted = %d, want the driver's 7", deleted)
				}
			})
		})
	}
}

// failingConnector is a database/sql connector whose every statement fails with execErr, or
// succeeds reporting rowsAffected and then fails the read with rowsAffectedErr. It implements
// ExecerContext, so database/sql hands it the statement directly and prepares nothing.
type failingConnector struct {
	execErr         error
	rowsAffectedErr error
	rowsAffected    int64
}

func (c *failingConnector) Connect(context.Context) (driver.Conn, error) { return &failingConn{c}, nil }
func (c *failingConnector) Driver() driver.Driver                        { return failingDriver{} }

type failingDriver struct{}

func (failingDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("failingDriver is reached only through its connector")
}

type failingConn struct{ c *failingConnector }

func (f *failingConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	if f.c.execErr != nil {
		return nil, f.c.execErr
	}
	return failingResult{f.c}, nil
}

func (f *failingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("failingConn prepares nothing")
}
func (f *failingConn) Close() error { return nil }
func (f *failingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("failingConn opens no transaction")
}

type failingResult struct{ c *failingConnector }

func (r failingResult) LastInsertId() (int64, error) {
	return 0, errors.New("failingResult reports no id")
}
func (r failingResult) RowsAffected() (int64, error) {
	if r.c.rowsAffectedErr != nil {
		return 0, r.c.rowsAffectedErr
	}
	return r.c.rowsAffected, nil
}
