package main

import (
	"database/sql"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"
)

// testDatabaseConnection returns true if connection succeeded, false otherwise
func testDatabaseConnection(out *console, e *engine, host, port, name, user, password string) bool {
	out.printf("Testing database connection... ")

	if e.checkDSN == nil {
		out.warning("Database connection test not supported for %s", e.name)
		return true // Skip unsupported databases
	}

	db, err := sql.Open(e.checkDriver, e.checkDSN(host, port, name, user, password))
	if err != nil {
		out.fail("Failed to open connection: %v", err)
		return false
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(5 * time.Second)

	err = db.Ping()
	if err != nil {
		out.fail("Connection failed: %v", err)
		return false
	}

	out.success("Connection successful!")

	// Check if database has Goiabada tables (indicating it's not empty)
	checkDatabaseEmpty(out, db, e)

	return true
}

// checkDatabaseEmpty checks if the database already has Goiabada tables
// and warns the user if it does
func checkDatabaseEmpty(out *console, db *sql.DB, e *engine) {
	out.printf("Checking if database is empty... ")

	if e.emptinessQuery == "" {
		out.println("skipped")
		return
	}

	var count int
	err := db.QueryRow(e.emptinessQuery).Scan(&count) //nolint:gosec // G701: a constant of the engine table; the taint is only that --db chose the row
	if err != nil {
		// If we can't check, just skip
		out.println("skipped")
		return
	}

	if count > 0 {
		out.println()
		out.warning("Database already contains Goiabada tables!")
		out.println()
		out.printf("  %sThe 'users' table exists, indicating this database was used before.%s\n", out.yellow, out.reset)
		out.printf("  %sIf you're deploying with different URLs than before, the OAuth client%s\n", out.yellow, out.reset)
		out.printf("  %sconfiguration will not match and authentication will fail.%s\n", out.yellow, out.reset)
		out.println()
		out.printf("  %sOptions:%s\n", out.bold, out.reset)
		out.println("    1. Use the same URLs as the previous deployment")
		out.println("    2. Use a fresh/empty database")
		out.println("    3. Manually update the OAuth client redirect URIs in the database")
		out.println()
	} else {
		out.success("Database is empty (ready for fresh deployment)")
	}
}
