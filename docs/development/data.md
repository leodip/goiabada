# Database changes

Change SQL, migrations and transactional writes across SQLite, MySQL, PostgreSQL and SQL Server.

Paths in backticks are relative to the repository root unless a module directory is named. Read the
sections relevant to the change; [AGENTS.md](../../AGENTS.md) lists the common commands.

## Database Pattern

`data.Database` (`src/authserver/internal/data/database.go`) is the composition interface. The four
engine adapters embed `commondb.Database`; common resource files hold each engine's SQL side by
side. An adapter overrides only operations that need it. A call on `commondb.Database`'s own
receiver cannot dispatch to an adapter override; `TestDatabase_NoSelfCallToAnOverriddenMethod`
refuses such calls.
- All methods accept `ctx context.Context` then `tx *sql.Tx` (nil = no transaction); the context
  reaches `BeginTx`, `QueryContext` and `ExecContext` (#386)
- Every statement is plain SQL in each engine's own form, with no query builder: a `statement`
  (`commondb/statement.go`) holds its SQLite, MySQL, PostgreSQL and SQL Server text side by side in
  the shared implementation's file for its resource, and the handle's `Dialect` field
  (`data.Dialect`) picks the version that runs, so the text in the source is the text the engine
  receives. `TestStatements_EveryEngineHasItsVersion` refuses one missing a version; an IN list is
  written by `inList`, inside `forEachIdBatch` (#644)
- Each record's read column list and whole-row INSERT and UPDATE are written out per engine in
  `commondb/`, with a shared explicit scan function. The `db`, `fieldtag` and `fieldopt` tags stay
  on the records as the column contract: a `dont-update` column is protected by its absence from the
  UPDATE's text, and `TestRecordMapping_EveryRecordMatchesItsTagsOnEveryEngine` holds the SQL to the
  tags on all four engines through the scripted driver (#644)
- Nothing above the data layer takes the whole interface: each handler, middleware and service
  declares an unexported port beside the function that takes it, naming only what that file calls
  (#386)
- Schema in `src/authserver/internal/data/sqlitedb/schema.golden` (generated; see [Schema golden
  files](#schema-golden-files))
- Migrations are applied by Goiabada's own runner in `src/authserver/internal/data/migrator/`, built
  per engine by each `NewMigrator()`

**Supported**: SQLite, MySQL, PostgreSQL, SQL Server

## Transactions

Open every transaction through `RunInTransaction`; the data package's
`begin_transaction_lint_test.go` refuses a bare `BeginTransaction` in production code. The common
implementation in `src/authserver/internal/data/commondb/db.go` makes at most three attempts when
the engine aborts a transaction as a deadlock victim, including a deadlock reported at commit.
Keep attempt-local state inside the callback, return failures, and write the response and external
effects after it succeeds. Audit events describe the committed outcome.

Preserve the row locks that make security decisions atomic:

- A termination deletes the session row first. Issuance takes that row before inserting its code
  or signing implicit tokens in the same transaction, so neither slips past a termination's sweep
  before its commit (#139).
- Refresh rotation takes the user's row first (`AcquireUserRow`), as credential changes do through
  their write and generation increment. A rotation cannot stamp a child from a token a revocation
  already moved past, and the revocation's sweep cannot miss that child (#131).
- An OTP claim is rechecked under the user's row (`otpcredential.OTPClaim.Recheck`) before binding
  it to a session or issuing it. Authenticator removal takes that row first and lowers sessions in
  the same transaction, so a removed authenticator's code cannot subsequently be bound or issued
  (#542).

There is no additional global lock order. Concurrent transactions on the same account can still
deadlock on MySQL, PostgreSQL or SQL Server; the loser rolls back and is retried. Add a test that
forces a suspected deadlock and proves the retry resolves it, rather than changing the locking
policy to hide it (#301). SQLite's pool has one connection and cannot deadlock this way.

A commit failure other than a classified deadlock is never retried: the server may have committed
before the failure reached the caller. It carries `data.ErrCommitOutcomeUnknown`; the refresh
rotation endpoint answers 409 `ROTATION_OUTCOME_UNKNOWN`. Cancellation before the driver is asked
to commit rolls back without that tag. Cancellation while COMMIT is in flight carries it, even
when the driver returns the context's own error, as pgx and go-mssqldb do (#371).

## Multi-row writes and list saves

A request that writes more than one row validates the whole request first, bounds and duplicates
included, so a refusal writes nothing; then writes in one `RunInTransaction` whose body reads what
it needs on the transaction, returns each failure through `errs.Wrap` and writes no response, since
a deadlock victim's body is rerun; then answers, audit events after the commit. A save replacing a
whole list is the common case, and there are nine: a client's redirect URIs, sign-out redirect URIs,
web origins and introspection resources, user, group, client and resource permissions, and a user's
groups. Each requires the list as its caller loaded it (`expectedRedirectURIs` and its siblings;
absent or `null` is a 400, `[]` means an empty list was loaded), reads the stored rows on the
transaction, and answers 409 `CONCURRENT_UPDATE` with nothing written when they differ from it as a
set; otherwise it applies `replaceSet`'s plan, which deletes every row whose key is not wanted and
every extra copy of one that is, so a duplicate left by an overlap is repaired by the next save. A
unique-key race answers the same 409, through the one failure writer `writeListSaveFailure`. No list
save locks its list: overlapping saves merge item by item, and the data tier's `list_save_test.go`
shows it on MySQL, PostgreSQL and SQL Server. A row lock is for one row read, decided on and written
back with a security consequence, which today means #245's public/confidential switch
(`AcquireClientRow`), #139's issuance (`AcquireUserSessionRow`), #131's refresh rotation
(`AcquireUserRow`), #542's session writes (`AcquireUserSessionRow`) and one-time code claims
(`AcquireUserRow`), #407's settings section saves (`AcquireSettingsRow`), each of which reads
the settings row again under it and writes its own section onto what it read, through
`apihandlers.saveSettingsSection`, so a save of another section committed meanwhile is not written
back over (#428), and #622's legal document lifecycle writes (`AcquireLegalDocumentRow`): a draft
save, publish, retire, restore, delete and a change of apps each read the document again under its
row and decide on that, so a publish clears only the draft it froze, a save cannot rename a document
published meanwhile or undo a retirement, and the data tier's `legal_document_lifecycle_test.go`
shows each order on every engine. One list save also takes a row for that reason: a save adding to a client's
introspection resources takes the client's row (`AcquireClientRow`) and refuses a client it then
finds public, because making a client public takes that row first and clears the list in the same
transaction (#676)

## Schema golden files

Each engine's fully migrated catalog is recorded in
`src/authserver/internal/data/<engine>db/schema.golden`, and the data tier compares a freshly
migrated database against the file for the engine it is running on. A migration therefore has one
more step: `cd src/authserver && go run ./cmd/schemadump` inside the dev container, which
regenerates all four files at once, and commit them. Skip it and CI goes red on every database job.

## Migration source rules

The authserver internal tier runs `TestMigrationSource_TheFourCommittedDirectories` in
`src/authserver/internal/data`, which holds the four `migrations/` directories to the rules
decidable from the text alone: naming, pairing, one number meaning one change, the collation pins on
MySQL and SQL Server, a named `CONSTRAINT` on every added SQL Server `DEFAULT` and a spelled-out
`NULL` or `NOT NULL` on every `ALTER COLUMN`, and each `schema.golden`'s recorded version. A
migration landing on fewer than four engines therefore owes a `-- parity: <engines> only. <why>`
line in every up.sql carrying it, and a `.down.sql` with no statement in it owes `-- Migration
NNNNNN down: intentional no-op.`
