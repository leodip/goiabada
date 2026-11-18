# Test development

Write tests that exercise the behavior and preserve isolation between cases.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

For setup, test tiers and committed generators, use the [contributing
guide](../../site/src/content/docs/about/contributing.mdx).

## Test locations

| Test subject | Location |
|---|---|
| Auth server handlers | `src/authserver/internal/handlers/*_test.go` and child packages |
| Ceremony, issuance and signing keys | `src/authserver/internal/{ceremony,issuance,signingkeys}/*_test.go` |
| Ceremony step decisions | `src/authserver/internal/authflow/*_test.go` |
| Shared logic | Tests beside the source in `src/core/` |
| Protocol and account validation | `src/authserver/internal/{protocol,account}validation/*_test.go` |
| Database operations and migrations | `src/authserver/tests/data/` |
| API integration | `src/authserver/tests/integration/` |
| Browser and rate-limit e2e | `e2e/playwright/tests/` and `e2e/playwright/rate-limits/` |

The handler tests build each ceremony operation through one builder per handler in
`ceremony_handler_builders_test.go`, using the doubles declared in `handlers/doubled_services.go`.
The operation package also checks its decision tables, completion-plan constructors and imports.
The integration tier covers OAuth2 flows, DCR, the admin API and user management; `run-tests.sh`
builds, starts and stops its server per database.

**Test fixtures**: tests draw random values from `authserver/internal/fake`, a test-only package
over `crypto/rand` that replaced a third-party faker in #272 and left `internal/testutil` in #442.
Reach for it rather than adding a dependency the next time a test needs a random string. Beside it,
a test that sends a one-time code gets it from `authserver/internal/otp/otptest`, test support like
`fake`, whose `Code` computes what an authenticator shows for a base32 secret at an instant with an
RFC 6238 implementation of its own, importing nothing from `otp`, so the verifier is checked against
an answer it did not compute. A secret or key URL in the server's own shape comes from the
production generator, `otp.KeyGenerator.GenerateKeyURL` and then `otp.SecretFromKeyURL`; `otptest`'s
`NewSecret` is for a test that only needs a random one (#646). The server accepts the previous and
the current step's code and refuses the next step's as a clock running ahead (#142): `NextStepCode`
is that refused code, and `PreviousStepCode` the oldest accepted one, which a test spends to leave
the current step's code unspent for a second sign-in. Both wait out the last two seconds of a step,
so the step cannot turn before the server checks the code.

A unit test that needs a real SQLite database at the head of the migration set takes one from
`authserver/internal/data/sqlitedb/sqlitedbtest`, test support like `otptest`: `NewMigrated` opens a
copy of its own in the test's temporary directory, and `WriteMigrated` writes one at a path the test
hands to the code it runs. Each test binary migrates one database the first time a test asks and
copies its bytes for every test after it, because migrating every test's database from empty cost
seconds per test under the race detector. A test whose subject is a migration, or a start that
migrates, still builds its database from empty.

A test that sends a DPoP proof builds it with `authserver/internal/dpop/dpoptest`, test support like
`otptest`: ES256 over RFC 7517's and RFC 7515's published P-256 keys, signed with the standard
library and importing nothing from `dpop`, each key's `Thumbprint` a literal worked out apart from
Go, so an assertion on `cnf.jkt` does not recompute what the server computes (#42).

**Settings row in the integration tier**: every integration test runs against one server and one
settings row, which the server reads on every request, so a value a test leaves there is what every
later test runs against. A test that changes the row, through the admin API or directly, calls
`restoreSettings(t)` or `changeSettings(t, edit)` from `tests/integration/settings_helpers_test.go`
before its first change; each registers a `t.Cleanup` that writes the whole row back except
`last_cleanup_at`, which the background worker owns. `TestMain` compares the row at the end of the
run with the row at its start and fails the tier naming each changed field, so a test that forgets
fails the run instead of the tests after it (#433).

**Integration halves**: CI runs the integration tier in two halves, each against a server and
database of its own. `run-tests.sh --shard 1/2` runs every other top-level test in name order and
`--shard 2/2` the rest, which also takes in any test the dealing missed. So an integration test sets
up every record it relies on rather than finding one an earlier test left, which may have run in the
other half. Either flag reproduces its half locally.

**Fresh test databases**: every data and integration run starts from an empty database, as CI's
fresh service containers always did. `run-tests.sh` removes the SQLite files, and on mysql, postgres
and mssql it drops `goiabada_data` or `goiabada_integration` through `cmd/droptestdb`, which refuses
every other name, so the server or the data tier recreates and migrates it and the integration
server seeds it. The drop itself is each engine package's `DropDatabase`, the one spelling
`schemadump` and the data tier's fixtures use too (#433).

**Parallel data tests**: a data test whose every database is its own, from `newIsolatedDB` or a
helper over it, calls `t.Parallel()`, since the database's name is the test's and each engine names
its migration lock after the database. A data test that also reaches the shared database, captures
the global logger, holds a lock or package fixture another test takes, or asserts how long
something took stays serial, whether it does so in its own body or in a subtest. Go runs every
serial top-level test before the parallel ones resume, so the two never overlap, but a parallel
test's subtests run beside the other parallel tests.

**Dev stack secrets**: the dev stack's data key and its MySQL, PostgreSQL and SQL Server passwords
come from `src/.devcontainer/.env`, which `src/.devcontainer/generate-env.sh` writes with fresh
values (and fills in when one is missing) and `.gitignore` keeps out of git; Compose hands them to
the databases and the devcontainer. `run-tests.sh` and `schemadump` read them from the environment
and refuse with one line naming a missing one, so outside the devcontainer, or in a container
created before #627, run the script and recreate the stack with its volumes (#501).

**Transaction stub**: a unit test that needs the mock database to answer `RunInTransaction` uses
`datamocks.ExpectRunInTransaction`, hand-written beside the generated mock in
`authserver/internal/data/mocks` and reachable from every caller without a new import, with
`ExpectRunInTransactionThenFail` for a commit the engine refuses and `ExpectRunInTransactionRefused`
for a transaction that never opens. It hands the body the transaction the caller names and refuses a
nil one: every `Database` method takes the transaction it runs under and a call made outside any
transaction passes nil, so a stub handing over nil makes a write inside the transaction
indistinguishable from one moved back outside it, and the test passes either way. That was seven
divergent copies of the same 58 lines, two of them handing over nil, until they were merged into one
here, folded into #387 (PR #422).

## Race detector

`./run-tests.sh --type modules --race` runs the three module tiers under `go test -race`, and CI's
three `Unit / race` jobs do the same beside the plain unit jobs, one job per tier so the quick ones
stop queueing behind the auth server leg (#691). A race build running under `go test` also hashes
passwords, and compares refusals against its dummy hash, at bcrypt's minimum cost, so bcrypt does not
dominate the tier. Production builds, every other tier and a race binary run outside `go test` keep
the default cost for both; `passwordhash`'s `TestCostOutsideGoTest` runs a probe binary outside the
test harness, in the test's own build, to hold that. The detector needs cgo, so the dev
container ships gcc and pins `CGO_ENABLED=0` for everything except the race runs, each of which sets
it to 1 for itself. Code whose correctness is a locking argument (`authserver/internal/ratelimit`,
whose failures-only limiter holds the in-flight count since #439, the concurrent transactions
of #301) is covered there and nowhere else; the setup tier also accepts `--race`; the data and
integration tiers do not run under it.

A `*_lint_test.go` file checks source text: it parses files and runs none of the code it reads, so a
race the detector could find there would be in the guard or its harness, never in the code under
check. Every one starts with `//go:build !race` and runs once, in the plain tier.
What another test file uses, a finder its rule tests drive over fixtures or a reader of the served
scripts, lives in a file of its own beside it, which both builds read.

## Browser e2e tests

The Playwright suites in `e2e/` need the maintainer's VPS and SSH access, which external
contributors do not have. Test contributions are welcome. Check their types locally and report that
execution needs a maintainer; see [Contribute tests](../../e2e/README.md#contribute-tests). These
are separate from the Go integration tier, which runs in the dev container.
