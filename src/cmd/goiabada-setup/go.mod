module github.com/leodip/goiabada/goiabada-setup

go 1.27.2

require (
	github.com/go-sql-driver/mysql v1.10.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/leodip/goiabada/core v0.0.0
	github.com/microsoft/go-mssqldb v1.11.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/term v0.47.0
)

replace github.com/leodip/goiabada/core => ../../core

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/shopspring/decimal v1.5.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
