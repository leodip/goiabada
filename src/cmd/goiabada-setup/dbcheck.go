package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"
)

// testDatabaseConnection returns true if connection succeeded, false otherwise
func testDatabaseConnection(dbType, host, port, name, user, password string) bool {
	fmt.Print("Testing database connection... ")

	var dsn string
	var driver string

	switch dbType {
	case "mysql":
		driver = "mysql"
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?timeout=5s", user, password, host, port, name)
	case "postgres":
		driver = "postgres"
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require connect_timeout=5", host, port, user, password, name)
	case "mssql":
		driver = "sqlserver"
		dsn = fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s&connection+timeout=5", user, password, host, port, name)
	default:
		printWarning("Database connection test not supported for %s", dbType)
		return true // Skip unsupported databases
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		printError("Failed to open connection: %v", err)
		return false
	}
	defer func() { _ = db.Close() }()

	db.SetConnMaxLifetime(5 * time.Second)

	err = db.Ping()
	if err != nil {
		printError("Connection failed: %v", err)
		return false
	}

	printSuccess("Connection successful!")

	// Check if database has Goiabada tables (indicating it's not empty)
	checkDatabaseEmpty(db, dbType)

	return true
}

// checkDatabaseEmpty checks if the database already has Goiabada tables
// and warns the user if it does
func checkDatabaseEmpty(db *sql.DB, dbType string) {
	fmt.Print("Checking if database is empty... ")

	var query string
	switch dbType {
	case "mysql":
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'"
	case "postgres":
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'"
	case "mssql":
		query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users'"
	default:
		fmt.Println("skipped")
		return
	}

	var count int
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		// If we can't check, just skip
		fmt.Println("skipped")
		return
	}

	if count > 0 {
		fmt.Println()
		printWarning("Database already contains Goiabada tables!")
		fmt.Println()
		fmt.Printf("  %sThe 'users' table exists, indicating this database was used before.%s\n", colorYellow, colorReset)
		fmt.Printf("  %sIf you're deploying with different URLs than before, the OAuth client%s\n", colorYellow, colorReset)
		fmt.Printf("  %sconfiguration will not match and authentication will fail.%s\n", colorYellow, colorReset)
		fmt.Println()
		fmt.Printf("  %sOptions:%s\n", colorBold, colorReset)
		fmt.Println("    1. Use the same URLs as the previous deployment")
		fmt.Println("    2. Use a fresh/empty database")
		fmt.Println("    3. Manually update the OAuth client redirect URIs in the database")
		fmt.Println()
	} else {
		printSuccess("Database is empty (ready for fresh deployment)")
	}
}
