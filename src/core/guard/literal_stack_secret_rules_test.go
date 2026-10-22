package guard

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures spell no published value themselves: each is built from the guard's own list, so
// this file is not one more place naming them.

// literalStackTree is the tree that must fail: every refused shape once, each in a kind of file the
// guard reads, and the published values outside a runnable file.
func literalStackTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeGoFile(t, root, ".github/workflows/ci.yml", "env:\n"+
		"  GOIABADA_AES_ENCRYPTION_KEY: 4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a\n"+
		"services:\n"+
		"  mysql:\n"+
		"    options: >-\n"+
		"      --health-cmd \"mysqladmin ping -uroot -pdevpass --protocol=tcp\"\n"+
		"      run: mysql --password=devpass -e 'select 1' && mysql --password devpass -e 'select 1'\n")
	writeGoFile(t, root, "deploy/k8s/deployment.yaml", "env:\n"+
		"  - name: GOIABADA_DB_PASSWORD\n"+
		"    value: \"devpass\"\n")
	writeGoFile(t, root, "src/build/Dockerfile-authserver", "FROM scratch\n"+
		"ENV GOIABADA_AES_ENCRYPTION_KEY=4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a\n"+
		"ENV MYSQL_PASSWORD devpass\n"+
		"ARG POSTGRES_PASSWORD=devpass\n")
	writeGoFile(t, root, "src/authserver/Makefile", "MYSQL_ROOT_PASSWORD ?= devpass\n"+
		"PGPASSWORD := devpass\n")
	writeGoFile(t, root, "deploy/goiabada.env", "GOIABADA_DB_PASSWORD=devpass\n")
	writeGoFile(t, root, "e2e/.env.example", "MYSQL_PASSWORD=devpass\n")
	writeGoFile(t, root, "src/.vscode/launch.json", "{\n"+
		"\t\"env\": {\"GOIABADA_AES_ENCRYPTION_KEY\": \"4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a\"}\n}\n")
	writeGoFile(t, root, "docs/notes.txt", "the old key was "+strings.ToUpper(publishedDataKey)+"\n")
	writeGoFile(t, root, "deploy/docker-compose.override.yml", "services:\n"+
		"  db:\n"+
		"    environment:\n"+
		"      POSTGRES_PASSWORD: \"devpass\"  # dev only\n"+
		"      - \"MYSQL_PASSWORD=devpass\"\n")
	writeGoFile(t, root, "src/.devcontainer/devcontainer.json", "{\n"+
		"\t\"containerEnv\": {\n"+
		"\t\t\"GOIABADA_DB_PASSWORD\": \"devpass\",\n"+
		"\t}\n}\n")
	writeGoFile(t, root, "src/run.sh", "#!/bin/sh\n"+
		"export GOIABADA_AES_ENCRYPTION_KEY=\"${GOIABADA_AES_ENCRYPTION_KEY:-4d3c2b1a}\"\n"+
		"docker exec db /opt/mssql-tools18/bin/sqlcmd -S db,1433 -U sa \\\n"+
		"    -P 'devpass' -Q 'SELECT 1'\n"+
		"docker exec -e PGCONNECT_TIMEOUT=3 -e PGPASSWORD=devpass db psql -c 'select 1'\n"+
		"export GOIABADA_DB_PASSWORD=\"${DB_PASS:-devpass}\"\n")
	writeGoFile(t, root, "src/tool/cmd/dump/main.go", "package main\n\n"+
		"var engines = []struct{ password string }{{password: \"devpass\"}}\n\n"+
		"func init() { os.Setenv(\"GOIABADA_DB_PASSWORD\", \"devpass\") }\n")
	writeGoFile(t, root, "site/docs/page.mdx", "Set `SA_PASSWORD=devpass` in prose, which nobody runs.\n\n"+
		"```bash\n"+
		"SA_PASSWORD=devpass ./start.sh\n"+
		"```\n\n"+
		"```yaml\n"+
		"- name: MSSQL_SA_PASSWORD\n"+
		"  value: devpass\n"+
		"```\n")
	writeGoFile(t, root, "src/internal/fixture_test.go", "package p\n\n"+
		"const key = \""+strings.ToUpper(publishedDataKey)+"\"\n"+
		"const pass = \""+publishedPasswords[2]+"\"\n")
	return root
}

// TestLiteralStackSecrets_TheRuleTable is the tree that must fail, each finding named at its own
// line, a continued command at its first, and the Markdown prose and a quoted comment left alone.
// The text file holds the published key in upper case and nothing else, so the case-insensitive
// pre-check is what finds it.
func TestLiteralStackSecrets_TheRuleTable(t *testing.T) {
	root := literalStackTree(t)

	findings, files, err := findLiteralStackSecrets(root)
	require.NoError(t, err)

	assert.Equal(t, 12, files, "the test file and the text file are read for published values but are no runnable files")
	assert.Equal(t, []string{
		".github/workflows/ci.yml:2: GOIABADA_AES_ENCRYPTION_KEY set to a literal: GOIABADA_AES_ENCRYPTION_KEY: 4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a",
		".github/workflows/ci.yml:6: a literal password to mysql: --health-cmd \"mysqladmin ping -uroot -pdevpass --protocol=tcp\"",
		".github/workflows/ci.yml:7: a literal password to mysql: run: mysql --password=devpass -e 'select 1' && mysql --password devpass -e 'select 1'",
		"deploy/docker-compose.override.yml:4: POSTGRES_PASSWORD set to a literal: POSTGRES_PASSWORD: \"devpass\"  # dev only",
		"deploy/docker-compose.override.yml:5: MYSQL_PASSWORD set to a literal: - \"MYSQL_PASSWORD=devpass\"",
		"deploy/goiabada.env:1: GOIABADA_DB_PASSWORD set to a literal: GOIABADA_DB_PASSWORD=devpass",
		"deploy/k8s/deployment.yaml:3: GOIABADA_DB_PASSWORD set to a literal by the value after its name: value: \"devpass\"",
		"docs/notes.txt:1: a published value: the old key was " + strings.ToUpper(publishedDataKey),
		"e2e/.env.example:1: MYSQL_PASSWORD set to a literal: MYSQL_PASSWORD=devpass",
		"site/docs/page.mdx:4: SA_PASSWORD set to a literal: SA_PASSWORD=devpass ./start.sh",
		"site/docs/page.mdx:9: MSSQL_SA_PASSWORD set to a literal by the value after its name: value: devpass",
		"src/.devcontainer/devcontainer.json:3: GOIABADA_DB_PASSWORD set to a literal: \"GOIABADA_DB_PASSWORD\": \"devpass\",",
		"src/.vscode/launch.json:2: GOIABADA_AES_ENCRYPTION_KEY set to a literal: \"env\": {\"GOIABADA_AES_ENCRYPTION_KEY\": \"4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a\"}",
		"src/authserver/Makefile:1: MYSQL_ROOT_PASSWORD set to a literal: MYSQL_ROOT_PASSWORD ?= devpass",
		"src/authserver/Makefile:2: PGPASSWORD set to a literal: PGPASSWORD := devpass",
		"src/build/Dockerfile-authserver:2: GOIABADA_AES_ENCRYPTION_KEY set to a literal: ENV GOIABADA_AES_ENCRYPTION_KEY=4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a4d3c2b1a",
		"src/build/Dockerfile-authserver:3: MYSQL_PASSWORD set to a literal: ENV MYSQL_PASSWORD devpass",
		"src/build/Dockerfile-authserver:4: POSTGRES_PASSWORD set to a literal: ARG POSTGRES_PASSWORD=devpass",
		"src/internal/fixture_test.go:3: a published value: const key = \"" + strings.ToUpper(publishedDataKey) + "\"",
		"src/internal/fixture_test.go:4: a published value: const pass = \"" + publishedPasswords[2] + "\"",
		"src/run.sh:2: GOIABADA_AES_ENCRYPTION_KEY falls back to a literal: export GOIABADA_AES_ENCRYPTION_KEY=\"${GOIABADA_AES_ENCRYPTION_KEY:-4d3c2b1a}\"",
		"src/run.sh:3: a literal -P password to sqlcmd: docker exec db /opt/mssql-tools18/bin/sqlcmd -S db,1433 -U sa  -P 'devpass' -Q 'SELECT 1'",
		"src/run.sh:5: PGPASSWORD set to a literal: docker exec -e PGCONNECT_TIMEOUT=3 -e PGPASSWORD=devpass db psql -c 'select 1'",
		"src/run.sh:6: GOIABADA_DB_PASSWORD falls back to a literal: export GOIABADA_DB_PASSWORD=\"${DB_PASS:-devpass}\"",
		"src/tool/cmd/dump/main.go:3: a password field set to a literal: var engines = []struct{ password string }{{password: \"devpass\"}}",
		"src/tool/cmd/dump/main.go:5: GOIABADA_DB_PASSWORD set to a literal by os.Setenv: func init() { os.Setenv(\"GOIABADA_DB_PASSWORD\", \"devpass\") }",
	}, findings)
}

// TestLiteralStackSecrets_AnEnvironmentDrawnTreeReportsNothing is the tree that must pass: every
// value an interpolation, a GitHub expression, a command's output, empty or a placeholder; a
// required-variable expansion, whose text after `:?` is a message, and an empty or interpolated
// fallback; a mysql --password that prompts; a Dockerfile ARG with no default; a `name:` entry
// whose value comes from a secret, and one naming no listed variable; the guard's own owners naming
// a published value; a test file's literal, the testdata directory, the bare .env generate-env.sh
// writes and a .dockerignore, out of scope.
func TestLiteralStackSecrets_AnEnvironmentDrawnTreeReportsNothing(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, ".github/workflows/ci.yml", "env:\n"+
		"  GOIABADA_AES_ENCRYPTION_KEY: ${{ needs.secrets.outputs.key }}\n"+
		"  MYSQL_ROOT_PASSWORD: \"${{ needs.secrets.outputs.mysql }}\"\n"+
		"      --health-cmd \"mysqladmin ping -uroot -p$${MYSQL_ROOT_PASSWORD} --protocol=tcp\"\n"+
		"      --health-cmd \"sqlcmd -S localhost -U sa -P \\\"$${MSSQL_SA_PASSWORD}\\\" -Q 'SELECT 1'\"\n"+
		"      run: echo \"GOIABADA_AES_ENCRYPTION_KEY=$(openssl rand -hex 32)\" >> \"$GITHUB_ENV\"\n")
	writeGoFile(t, root, "src/.devcontainer/docker-compose.yml", "services:\n"+
		"  db:\n"+
		"    environment:\n"+
		"      MSSQL_SA_PASSWORD: ${MSSQL_SA_PASSWORD:?run .devcontainer/generate-env.sh first}\n"+
		"      GOIABADA_DB_PASSWORD: ${MSSQL_SA_PASSWORD}\n")
	writeGoFile(t, root, "src/run.sh", "#!/bin/sh\n"+
		"export GOIABADA_DB_PASSWORD=\"$MYSQL_ROOT_PASSWORD\"\n"+
		"export GOIABADA_DB_PASSWORD=\"\"\n"+
		"docker compose -p \"$NAME\" exec mysql-server mysql -P 13306 -uroot -p\"$MYSQL_ROOT_PASSWORD\" -e 'select 1'\n"+
		"docker exec db bash -c \"sqlcmd -U sa -P \\\"\\$MSSQL_SA_PASSWORD\\\" -Q 'SELECT 1'\"\n"+
		"mkdir -p /tmp/mysql\n"+
		"export GOIABADA_DB_PASSWORD=\"${DB_PASS:?set DB_PASS}\"\n"+
		"export GOIABADA_DB_PASSWORD=\"${DB_PASS:-}\" MYSQL_PASSWORD=\"${DB_PASS:-$OTHER}\"\n"+
		"mysql --password -e 'select 1' && mysql --password=\"$MYSQL_ROOT_PASSWORD\" -e 'select 1'\n")
	writeGoFile(t, root, "src/build/Dockerfile-authserver", "FROM scratch\n"+
		"ARG MYSQL_PASSWORD\n"+
		"ENV GOIABADA_AES_ENCRYPTION_KEY=$KEY\n"+
		"ENV POSTGRES_PASSWORD ${POSTGRES_PASSWORD}\n")
	writeGoFile(t, root, "src/authserver/Makefile", "MYSQL_ROOT_PASSWORD ?= $(shell openssl rand -hex 16)\n")
	writeGoFile(t, root, "e2e/.env.example", "GOIABADA_DB_PASSWORD=<your database password>\n")
	writeGoFile(t, root, "src/.devcontainer/.env", "MYSQL_ROOT_PASSWORD=drawnbygenerateenv\n")
	writeGoFile(t, root, "src/.vscode/launch.json", "{\n"+
		"\t\"env\": {\"GOIABADA_AES_ENCRYPTION_KEY\": \"${env:GOIABADA_AES_ENCRYPTION_KEY}\"}\n}\n")
	writeGoFile(t, root, "deploy/k8s/deployment.yaml", "env:\n"+
		"  - name: GOIABADA_DB_PASSWORD\n"+
		"    valueFrom:\n"+
		"      secretKeyRef: {name: goiabada, key: db-password}\n"+
		"  - name: GOIABADA_DB_HOST\n"+
		"    value: db\n")
	writeGoFile(t, root, "site/Dockerfile.dockerignore", "MYSQL_PASSWORD=devpass\n")
	writeGoFile(t, root, "src/tool/cmd/dump/main.go", "package main\n\n"+
		"import \"os\"\n\n"+
		"var engines = []struct{ password string }{{password: os.Getenv(\"MYSQL_ROOT_PASSWORD\")}}\n\n"+
		"func init() { os.Setenv(\"GOIABADA_DB_PASSWORD\", \"\"); os.Setenv(\"GOIABADA_DB_HOST\", \"db\") }\n")
	writeGoFile(t, root, "site/docs/page.mdx", "Prose may say `GOIABADA_AES_ENCRYPTION_KEY: the data key`.\n\n"+
		"```yaml\n"+
		"- \"GOIABADA_AES_ENCRYPTION_KEY=<new, openssl rand -hex 32>\"\n"+
		"- \"GOIABADA_AES_ENCRYPTION_KEY_PREVIOUS=<its value before>\"\n"+
		"```\n")
	writeGoFile(t, root, "src/authserver/internal/config/config.go", "package config\n\n"+
		"const k = \""+publishedDataKey+"\"\n")
	writeGoFile(t, root, "src/internal/fixture_test.go", "package p\n\n"+
		"var env = []string{\"GOIABADA_DB_PASSWORD=devpass\"}\n")
	writeGoFile(t, root, "src/cmd/setup/testdata/docker-compose.yml", "services:\n"+
		"  db:\n"+
		"    environment:\n"+
		"      POSTGRES_PASSWORD: "+publishedPasswords[1]+"\n")

	findings, files, err := findLiteralStackSecrets(root)
	require.NoError(t, err)
	assert.Equal(t, 10, files, "the bare .env and the .dockerignore are not read")
	assert.Empty(t, findings)

	report := Run(func(r Reporter) { assertNoLiteralStackSecrets(r, root) })
	assert.False(t, report.Failed(), "an environment-drawn tree failed the guard: %s", report.Text())
}

// TestLiteralStackSecrets_ALiteralTreeFails drives the reporting half on the failing tree.
func TestLiteralStackSecrets_ALiteralTreeFails(t *testing.T) {
	root := literalStackTree(t)

	report := Run(func(r Reporter) { assertNoLiteralStackSecrets(r, root) })

	require.True(t, report.Failed())
	assert.False(t, report.Stopped, "a literal is an Errorf, not a Fatalf")
	assert.Contains(t, report.Text(), "26 lines supply a data key or a database password by literal")
	assert.Contains(t, report.Text(), "src/run.sh:5: PGPASSWORD set to a literal")
}

// TestLiteralStackSecrets_AnEmptyWalkIsFatal is the walk that reached nothing: a tree holding no
// runnable file, a Go source outside any cmd/ directory among them.
func TestLiteralStackSecrets_AnEmptyWalkIsFatal(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "src/internal/p.go", "package p\n")

	report := Run(func(r Reporter) { assertNoLiteralStackSecrets(r, root) })

	assert.True(t, report.Stopped)
	assert.Contains(t, report.Fatal, "walked no runnable files")
}
