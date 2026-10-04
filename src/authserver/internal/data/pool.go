package data

import (
	"database/sql"
	"time"
)

// PoolConfig is the connection pool a server engine opens its application database with:
// PostgreSQL, MySQL and SQL Server take it from the four GOIABADA_DB_* pool settings, and SQLite
// has its own fixed one (#394). It is what the start's pool record reports, so the record and
// the handle cannot disagree.
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// ApplyTo sets the pool on db. The idle cap goes after the open cap, because database/sql lowers
// an idle cap above the open cap to it, and the configuration refuses one rather than relying on
// that.
func (p PoolConfig) ApplyTo(db *sql.DB) {
	db.SetMaxOpenConns(p.MaxOpenConns)
	db.SetMaxIdleConns(p.MaxIdleConns)
	db.SetConnMaxLifetime(p.ConnMaxLifetime)
	db.SetConnMaxIdleTime(p.ConnMaxIdleTime)
}
