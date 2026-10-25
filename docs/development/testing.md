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
`NewSecret` is for a test that only needs a random one (#646).

**Settings row in the integration tier**: every integration test runs against one server and one
settings row, which the server reads on every request, so a value a test leaves there is what every
later test runs against. A test that changes the row, through the admin API or directly, calls
`restoreSettings(t)` or `changeSettings(t, edit)` from `tests/integration/settings_helpers_test.go`
before its first change; each registers a `t.Cleanup` that writes the whole row back except
`last_cleanup_at`, which the background worker owns. `TestMain` compares the row at the end of the
run with the row at its start and fails the tier naming each changed field, so a test that forgets
fails the run instead of the tests after it (#433).

**Fresh test databases**: every data and integration run starts from an empty database, as CI's
fresh service containers always did. `run-tests.sh` removes the SQLite files, and on mysql, postgres
and mssql it drops `goiabada_data` or `goiabada_integration` through `cmd/droptestdb`, which refuses
every other name, so the server or the data tier recreates and migrates it and the integration
server seeds it. The drop itself is each engine package's `DropDatabase`, the one spelling
`schemadump` and the data tier's fixtures use too (#433).

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
`Unit / race` job does the same beside the plain unit jobs. The detector needs cgo, so the dev
container ships gcc and pins `CGO_ENABLED=0` for everything except that leg, which sets it to 1 for
itself. Code whose correctness is a locking argument (`authserver/internal/ratelimit`, whose
failures-only limiter holds the in-flight count since #439, the concurrent transactions of #301) is
covered there and nowhere else; the setup tier also accepts `--race`; the data and integration tiers
do not run under it.

## Browser e2e tests

The Playwright suites in `e2e/` need the maintainer's VPS and SSH access, which external
contributors do not have. Test contributions are welcome. Check their types locally and report that
execution needs a maintainer; see [Contribute tests](../../e2e/README.md#contribute-tests). These
are separate from the Go integration tier, which runs in the dev container.
