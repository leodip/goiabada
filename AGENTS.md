# Goiabada development instructions

Goiabada is an OAuth2/OIDC authentication server in Go, with an admin console and setup wizard.
Paths below are relative to the repository root. `AGENTS.md` is the canonical instruction file;
`CLAUDE.md` is its checked copy. Read the references for the task you are doing.

## Build and verify

Use the dev container defined in `src/.devcontainer` for Go builds, database tests and generators.
Open `src/` in the editor to discover it. Setup and all test tiers are in the
[contributing guide](site/src/content/docs/about/contributing.mdx).

Run these commands from `src/authserver/` inside that container:

| Purpose | Command |
|---|---|
| Auth server unit tests | `./run-tests.sh --type internal --no-build` |
| Core unit tests | `./run-tests.sh --type core --no-build` |
| Admin console unit tests | `./run-tests.sh --type adminconsole --no-build` |
| Setup wizard tests | `./run-tests.sh --type setup --no-build` |
| One test or group | Add `--run 'TestNameOrPattern'` to the relevant tier |
| Three server/core unit tiers | `./run-tests.sh --type modules --no-build` |
| Race checks for those tiers | `./run-tests.sh --type modules --race --no-build` |
| Data tests on all engines | `./run-tests.sh --type data` |
| Integration tests on SQLite | `./run-tests.sh --type integration --db sqlite` |
| Integration tests on all engines | `./run-tests.sh --type integration` |
| Linters and generated-file checks | `./run-tests.sh --type lint` |
| Full suite, including setup and lint | `./run-tests.sh` |

Start with the affected tests; run the affected module tier and applicable lint before finishing.
For SQL or migration changes, run the data tier across all four engines. For protocol or API
behavior, run the relevant integration tests. Use the race detector for concurrent Go code.
The integration tier builds and starts its server; do not use `--no-build` without a prior build.
Data and integration runs reset their dedicated test databases and free the dev server ports;
see the contributing guide before sharing a running dev stack with another task.

The Playwright browser suites in `e2e/` require the maintainer's VPS and SSH access, which external
contributors do not have. E2e test contributions are welcome; validate their types locally and
report that execution needs a maintainer. See the [e2e README](e2e/README.md) for the test conventions.

The unit tiers need Node on `PATH` for static-script guards. Go and tool versions are pinned in
`src/authserver/versions.yaml`; the mock generator refuses incompatible versions. The dev stack's generated
credentials are in the gitignored `src/.devcontainer/.env` and passed through its environment.

## Read for the change

Read the relevant sections before changing the behavior they describe. Use package entries as
needed to locate an owner; a full repository briefing is unnecessary for a small edit.

| When changing | Reference |
|---|---|
| Module boundaries, package placement, shared contracts | [Architecture](ARCHITECTURE.md) |
| A core package's exported symbols | [Symbol ownership](src/core/OWNERSHIP.md) |
| Authorization, tokens, sessions, OTP, consent or rate limiting | [Authentication](docs/development/authentication.md) |
| SQL, transactions, locking, list saves or migrations | [Data](docs/development/data.md) |
| Handlers, credentials, errors, logging or metrics | [Application conventions](docs/development/conventions.md) |
| Templates, scripts, themes, accessibility or UI wording | [UI development](docs/development/ui.md) |
| Fixtures, transaction mocks or integration isolation | [Test development](docs/development/testing.md) |
| A repository guard or lint assertion | [Guard development](docs/development/guards.md) |
| Playwright browser or rate-limit tests | [E2e contribution and running instructions](e2e/README.md) |
| Package responsibilities or configuration ownership | [Package responsibilities](docs/development/packages.md) |
| Documentation site pages | [Docs style](site/STYLE.md) and the [glossary](site/src/content/docs/concepts/glossary.mdx) |

When changing standards-defined behavior, read the relevant official section at `rfc-editor.org`
or `openid.net` and follow its MUST and SHOULD requirements. The authentication guide lists the
implemented standards. Verify descriptions against the code and update the relevant guide when
the behavior changes.

## Boundaries and conventions

- Four Go modules live under `src/`: `core`, `authserver`, `adminconsole` and
  `cmd/goiabada-setup`. The three applications may import core; core imports none of them,
  and the applications do not import each other. The console talks to the auth server over HTTP.
- Core holds shared contracts and reference vocabularies. Persistence records belong to
  `authserver/internal/record`; admin API DTOs belong to `core/api`, mapping to the auth server's
  `internal/apimapping`. Check `ARCHITECTURE.md` before introducing a shared abstraction.
- A caller declares its narrow dependency port beside the function using it. Keep the complete
  `data.Database` interface at composition boundaries. Console handler fakes implement their
  port directly; embedding an interface would hide a missing method until runtime.
- Ceremony handlers read requests and write responses. Their operations in `internal/authflow`
  take plain values and browser-session ports, and cannot import HTTP or request-context packages.
- Construct errors with `core/errs`. Package-level sentinels use standard-library `errors.New`.
  Match errors with `errors.Is`/`errors.As`; preserve causes when returning failures.
- Read submitted credentials and ceremony/continuation form markers with `r.PostFormValue`.
  `r.FormValue` accepts query-string fallbacks, which can leak credentials into request targets.
- Open transactions through `RunInTransaction`. Its body can run again after a deadlock: keep
  responses and external effects out of it, and emit audit events after commit. Preserve the
  existing security row locks; read the data guide before changing lock or retry behavior.
- Request context values go through each application's typed `internal/reqctx` accessors.
  Pass context and settings explicitly to services. Keep stored session-key spellings stable.
- Log with lowercase literal messages and snake_case attributes; use context-aware calls on
  request paths. `core/logging` supplies `request_id`. Use `error` for error attributes and
  `logtest.CaptureSlog` in tests. Record security events through the audit logger.
- Metric labels have declared closed value sets. Map request/database values into those sets;
  user IDs, emails, client identifiers and other unbounded values are not label values.
- Use the existing page or JSON response helpers consistently. Console API failures go through
  the `HandleAPIError*` classifier appropriate to the response format.
- Tests use independent expected results and preserve transaction identity. Use
  `datamocks.ExpectRunInTransaction`, `internal/fake` and `internal/otp/otptest` where applicable;
  restore the shared settings row in integration tests. The test guide names the helpers.

## Regenerate committed files

Run the relevant command inside the dev container and include its output in the change.

| When you change | Command | Working directory |
|---|---|---|
| A database migration | `go run ./cmd/schemadump` (all four goldens) | `src/authserver` |
| A core exported symbol | `go run ./cmd/ownershipdump` | `src/core` |
| A mocked interface or its generator config | `./generate-mocks.sh` | `src/authserver` |
| Template CSS classes or UI CSS | `./build.sh` | The affected server module |
| A version pin | `./version-manager.sh update` | `src/authserver` |

The two servers' `web/tailwindcss/ui.css` files must match; a shared CSS change updates both and
regenerates both outputs. Built-in translations change together. Keep message IDs stable;
renames require release notes because operator overrides use those IDs.

## Maintain these instructions

Keep root guidance under 10 KiB and 200 lines. Edit `AGENTS.md`, then run
`cp AGENTS.md CLAUDE.md` from the repository root to update the checked copy. Add concise instructions for important constraints
or recurring project-specific mistakes; put detailed rationale and issue references in the relevant
development guide. Update existing guidance instead of appending another version of the rule.
`AssertAgentDocs` enforces the root budget, identical Claude copy, reference files and authentication-state
roster. Run its tests when changing the instruction layout or state table.

The checked copy loads from module directories without an external-import approval and works on
Windows without symlink setup. Keep the detailed guides as ordinary links so they load by task.
