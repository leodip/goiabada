module github.com/leodip/goiabada/goiabada-setup

go 1.27.3

require (
	github.com/go-sql-driver/mysql v1.10.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/leodip/goiabada/core v0.0.0
	github.com/microsoft/go-mssqldb v1.11.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/term v0.47.0
	sigs.k8s.io/kustomize/api v0.21.3
	sigs.k8s.io/kustomize/kyaml v0.21.3
)

replace github.com/leodip/goiabada/core => ../../core

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/go-openapi/jsonreference v1.0.0 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/shopspring/decimal v1.6.0 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	k8s.io/kube-openapi v0.0.0-20261001230523-97fa35140926 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
