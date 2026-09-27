package main

import "testing"

// The database host is what GOIABADA_DB_HOST accepts: a hostname, or an IP literal, IPv6 bare or
// bracketed. Anything else is still refused by the hostname rule (#430).
func TestValidateDatabaseHost(t *testing.T) {
	for _, host := range []string{
		"db.example.com", "localhost", "postgres-service", "10.0.0.5",
		"::1", "[::1]", "2001:db8::5", "[2001:db8::5]", "::ffff:10.0.0.5",
	} {
		if err := validateDatabaseHost(host); err != nil {
			t.Errorf("validateDatabaseHost(%q) = %v, want accepted", host, err)
		}
	}
	for _, host := range []string{
		"", "[::1", "::1]", "[[::1]]", "::g", "[db.example.com]", "db_example", "db example.com",
		"fe80::1%eth0", "-db.example.com", "db.example.com.",
	} {
		if err := validateDatabaseHost(host); err == nil {
			t.Errorf("validateDatabaseHost(%q) accepted, want refused", host)
		}
	}
}
