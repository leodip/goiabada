# Goiabada CI/CD v2

**Status:** revision 5, simplified
**Author:** drafted with Claude, 2026-08-08
**Baseline commit:** `8b69223`
**Repository:** `leodip/goiabada` (public, default branch `main`)

> **Stages 4 to 7 implemented, 2026-08-09.** The git tag now owns the product version, and `release.yml` / `publish.yml` / `docs.yml` replace the four manual workflows, which are deleted. Verified with a `v1.5.3-rc1` dry run: **8 of 9 checks passed**, and it found a real defect in 5.2's attestation specification (see stage 5 and 5.2). Outstanding: check 9 (publish-time retag skip), branch protection, and issue #155.

> **Stage 2 implemented, 2026-08-08.** `check.yml` runs alongside `run-tests.yml`, both green on the same commit: **251s against 541s**, with the wall-clock claim in 4.2 confirmed exactly. Fixed a defect in `run-tests.sh` found on the way (the module tiers could report green from Go's test cache without executing). `Vulnerabilities` is advisory-only pending #155. See stage 2 for the measurements and for four things 5.1 left unspecified.

> **Stage 0 implemented, 2026-08-08.** 4.4 resolved to **option A**. Stage 0 landed on branch `ci-v2-stage-0-lint-baseline`: the lint backlog is **0** across all four modules, `.golangci.yml` is checked in, and `staticcheck`, `unparam` and `govulncheck` are pinned. Two of the plan's assumptions proved wrong while implementing it and are corrected in place — see stage 0's **Correction 1** (`--fix` did nothing) and **Correction 2** (the `QF1001` rewrite taken). 5.8's open question is resolved: `.golangci.yml` is the single definition of lint-clean. Issue #155 remains open and still gates the `Vulnerabilities` required check.

> **Measurement correction, applied after revision 5.** The baseline was re-stamped from `ac4ffac` (the tip of an unrelated feature branch in a different working copy) to this repository's `main` HEAD, and the lint backlog in 1.4 D was re-measured with golangci-lint's issue caps disabled. **The backlog is 81 findings plus 2 unformatted files, not 11.** No design decision changed, but 4.4's "nearly free" rationale no longer follows from the numbers and now presents three options instead of asserting one. See 1.4 D, 4.4, 5.8 and stage 0.

### Revision 3 changelog (second code review)

A second review found four material issues, five further corrections, and seven passages left stale by revision 2. All were verified and all were valid, including one claim about GitHub's attestation actions that I checked upstream expecting to refute.

| # | Finding | Where fixed |
|---|---|---|
| 16 | **The release job DAG was never specified.** GitHub runs jobs concurrently by default, so `Images` could have pushed to both registries while `Checks` was still running, or after it failed. Registry tags cannot be un-pulled | 5.2, explicit `needs:` plus `concurrency` |
| 17 | **The docs prerelease guard did the opposite of the stated behavior.** A job-level `if` skipped the whole job for an rc, so it would have pushed *nothing*, while the text beneath promised `docs-$VERSION` | 5.4, job always runs, tag list computed |
| 18 | **`update_file` still could not see partial pattern loss.** Requiring "at least one match" means 3 pins with 1 stale still passes both conditions. Also `grep -c` counts lines, not occurrences | 5.7.4, exact occurrence count enforced before and after, via `grep -oE \| wc -l` |
| 19 | **Blocking tools stayed unpinned while the gate was live.** Lint blocks from stage 2, but the pins sat in optional stage 8, leaving stages 2 to 7 nondeterministic | Moved to stage 0 |
| 20 | Target map wrongly expected Tailwind in `release.yml`. **Verified:** `main.css` is committed for both modules and only `Dockerfile-test` fetches the Tailwind CLI | 5.7.3, `release.yml` = go only |
| 21 | The tag regex was not SemVer: accepted `v01.0.0`, `-01`, and `-rc..1` | 5.2, official grammar minus build metadata |
| 22 | One attestation with `subject-name: docker.io/...` does not bind the GHCR copy. **And `attest-build-provenance` is now a wrapper**: upstream says new implementations should use `actions/attest` | 5.2 |
| 23 | Always tagging both registries breaks the retained legacy workflow, which logs into Docker Hub only, falsifying stage 5's rollback claim | 5.6.2, `GOIABADA_REGISTRIES` with a Docker Hub only default |
| 24 | The `/health` secrecy rationale was wrong: every rendered page already carries the version in an HTML comment | 9 stage 5, rationale replaced with separation of concerns |

Stale revision-2 passages corrected: the overview and release diagram (both had `publish.yml` triggering docs), 4.6, the risk table (still recommended the rejected before/after comparison), stage 6 (still targeted all four workflows), the branch-protection note (still said "matrix jobs"), and stage 0's verification (omitted `unparam`, and relied on `gofmt -l` failing when **it exits 0 and only prints filenames**).

#### Revision 5 (third code review)

Eight findings, all valid; three verified by direct check. Fixed the simple way wherever a simpler route existed than the one proposed.

| # | Finding | Fix taken |
|---|---|---|
| 29 | **A `Versions` failure could bypass branch protection.** Every test job `needs: Versions`, and GitHub counts a **skipped** job as successful for required checks, so a `Versions` failure would skip all four `Tests /` checks and leave the PR mergeable with nothing run | Added `Versions` to both required-check lists. Took this over the proposed `if: always()` aggregator job: one line versus a new job |
| 30 | **Only 3 of the 6 blocking tools were propagated.** `staticcheck`, `unparam` and `govulncheck` are pinned in `versions.yaml` by stage 0 but their CI install path was unspecified, so the gate would have run `@latest`. And `release.yml` claimed to read `versions.yaml` while having no `Versions` job | Six outputs, and `release.yml` carries the same 6-line job. Duplicated rather than shared, which is simpler than a sharing mechanism |
| 31 | **"Drift impossible" covered only workflows.** Nothing checked that a PR editing `versions.yaml` had run `update`, so CI could use a new Go while the Dockerfiles stayed stale | One CI step: run `update`, require a clean `git diff`. Took this over a new non-mutating verify command: 6 lines of YAML, no script code |
| 32 | **`verify_versions` had the very hole it was meant to close.** `grep -qF` asks only whether a literal appears *somewhere*, and **verified: the devcontainer Dockerfile contains the Go archive literal 3 times** (lines 41 to 43), so two stale copies would pass | **Deleted it unimplemented.** Finding 31's one step is strictly stronger and needs no script code. Also removes the stage-6 decoy test, which could not have failed as written |
| 33 | **The attestation example was invalid.** **Verified upstream:** passing `predicate-type` selects *custom* mode and then requires `predicate`/`predicate-path`; provenance is the default only when those are omitted. The glob also covered 5 zips, not the promised 11 assets | Dropped `predicate-type`; `subject-path: dist/*` over the validated manifest directory |
| 34 | **`publish.yml` could not push to GHCR.** It declared `environment: prod` but no `packages: write`, and no logins. **Verified with `gh api`: this repo's `default_workflow_permissions` is `read`** | Added the permission block and both login steps |
| 35 | **The "matrix is impossible" rationale was factually wrong.** `matrix` *is* available to `jobs.<job_id>.services`, so a service image can vary per leg | Rationale rewritten as a readability choice, with the real reason (per-database `env`, `options` and health-cmd would each need conditional expressions). Four explicit jobs kept |
| 36 | **Stage 0's verification exited 0 after failures.** `\|\| echo "FAILED: $m"` swallows the subshell status because **`echo` returns 0** | `rc` accumulator and explicit `exit $rc` |

Rollout fixes: stage 6's `git checkout .` (destructive to unrelated work, and reset only the `src/authserver` subtree) now requires a clean tree and resets from the repo root; stage 5's rollback note no longer claims the old workflows "never stopped working", since stage 4 makes them emit `dev` artifacts. Stale revision-3 text cleaned up in 4.10, 4.11, the overview, the `Images` table, the risk table, the file list and the stage summary.

**Not taken, with reasons.** Asserting Docker Hub and GHCR manifest digests are equal after pushing: one `buildx build` with two `-t` flags pushes the same manifest, so equality holds by construction and a check would test the platform, not this design. The strict SemVer grammar and per-registry attestation stay simplified per revision 4.

#### Simplification pass (revision 4)

Revision 3 built a "pin contract" to keep `sed`-maintained copies of tool versions honest in the workflow files: per-file occurrence counts, an inventory check for unmapped files, a `verify` subcommand, and load-bearing marker comments. It worked, but it was scaffolding around a copy that need not exist.

**Replaced by having the workflows read `versions.yaml` at run time** (5.7.3). Confirmed against GitHub's context reference: `needs` is available for `container.image` and `services`, so container-based jobs can consume the value too. Drift becomes impossible rather than detectable, and the whole apparatus is deleted.

| Removed | Replaced by |
|---|---|
| `PIN_PATTERNS`, `WORKFLOW_PINS`, occurrence counts | a `versions` job whose outputs every other job consumes |
| `inventory_check`, `verify` subcommand and its `Lint` step | nothing needed |
| load-bearing `# golangci-lint` marker comments | nothing needed |
| a second Go pattern for `container:` image tags | nothing needed |
| per-call precondition/postcondition regexes on `update_file`, and the `verify_versions` pass that briefly replaced them | one CI step: run `update`, require a clean `git diff` (5.7.4). No script changes at all |

Three further trims in the same pass:

| Was | Now | Why |
|---|---|---|
| Full SemVer grammar, 4 lines of regex | one-line pattern that still rejects `+` | the strict grammar excludes only inputs that must be typed deliberately; `+` is the one that actually breaks a Docker tag |
| Image attestation for both registries, 4 calls | Docker Hub only, 2 calls; GHCR documented as an unattested mirror with identical digests | halves the wiring for no practical loss, widenable later |
| Occurrence-count maintenance chore | none | was the price of the copy, and there is no copy |

The standing maintenance obligation listed in earlier revisions is gone.

### Revision 2 changelog

A code review of revision 1 found three release-blocking defects and several inconsistencies. All were verified against the repository and all were valid. What changed:

| # | Finding | Where fixed |
|---|---|---|
| 1 | `VERSION="${1:-...}"` collides with the existing `$1 == --push` check. Worse than reported: `--push` alone would set `VERSION=--push` and publish tags named `authserver---push` | 5.6.1, now `--version X --push` option parsing |
| 2 | GHCR publishing was claimed in 5.2 but never specified; the script hardcodes one registry prefix in six places | 5.6.2 |
| 3 | No job declared `environment: prod`. **Verified: repo-scope secrets are empty**, both Docker credentials exist only in `prod`, so every push job would have failed | 5.2, 5.3, 5.4 |
| 4 | Neither binary script sets `-e`; a failed cross-compile exits 0 with a success message and uploads stale artifacts | 5.6.3, plus manifest validation and `if-no-files-found: error` |
| 5 | The before/after `update_file` check cannot distinguish "already correct" from "pattern stale", making the stage 4 verification criterion unsatisfiable | 5.7.4, now precondition/postcondition regexes |
| 6 | The workflow loop applied all three tool patterns to all four workflows, 9 of 12 combinations meaningless | 5.7.3, explicit target map |
| 7 | `/health` does not expose the version. **Verified: it returns the literal string `healthy`** | 4.1, 8, 9 stage 5, now uses startup logs or the rendered HTML comment |
| 8 | `.golangci.yml` without `default: none` pins nothing. **Verified empirically**: `enable: [errcheck]` still ran `unused` | 5.8 |
| 9 | `staticcheck` and `unparam` are installed `@latest` in the devcontainer, so a blocking lint gate can redden on an upstream release | 5.8 |
| 10 | Docs had two triggers, so a stable release built them twice; and an rc would move `docs-latest` | 5.4, single topology plus prerelease guard |
| 11 | SemVer `+build` metadata is invalid in Docker tags | 5.2, rejected at validation |
| 12 | A matrix boots all services for every leg: 12 DB starts, and the SQLite leg blocks on MSSQL health | 5.1, four explicit jobs |
| 13 | SHA pinning was deferred to stage 8, leaving credential-bearing workflows on mutable tags | 9, moved into stage 5 |
| 14 | Image attestation needs a digest the script does not emit | 5.2, buildx `--metadata-file` |
| 15 | *Not in the review, found while fixing it:* the tag-on-main guard needs `fetch-depth: 0`. With checkout's default depth of 1 there are no remote refs, so the guard rejects every tag | 5.2 |

Two claims in revision 1 were overstated and are now corrected in place: inline PR-diff annotations (5.5.3) and "never ships stale docs" (4.9).

---

## 1. Context

### 1.1 What exists today

Five workflows in `.github/workflows/`, all written to get the job done rather than to be lived with:

| Workflow | Trigger | Does |
|---|---|---|
| `run-tests.yml` | push + PR to `main` | One job: `docker compose run goiabada-test`, which runs the entire suite across all four databases serially |
| `build-binaries.yml` | manual | Cross-compiles authserver + adminconsole for 5 platforms, uploads zips as workflow artifacts |
| `build-setup-binaries.yml` | manual | Cross-compiles `goiabada-setup` for 5 platforms, uploads as workflow artifacts |
| `build-and-push-docker-images.yml` | manual | `build-docker-images.sh --push`, multi-arch to Docker Hub |
| `publish-documentation.yml` | manual | Builds `site/` and pushes `leodip/goiabada:docs-latest` |

Only `run-tests.yml` runs automatically. The other four are `workflow_dispatch` only.

### 1.2 The release process today

Reconstructed from the workflows and from release `v1.5.2`:

1. Edit `project.goiabada` in `src/authserver/versions.yaml`
2. Run `./version-manager.sh update`, which rewrites the two build scripts, the setup module's version constant and build script, and the four image tags embedded in the setup wizard
3. Review the diff, commit, push, tag
4. Dispatch `build-binaries.yml`, wait, download the artifact zip, unzip it
5. Dispatch `build-setup-binaries.yml`, wait, download, unzip
6. Dispatch `build-and-push-docker-images.yml`
7. Create the GitHub release by hand, write the notes
8. Upload 10 assets by hand
9. Dispatch `publish-documentation.yml` if the docs changed

Roughly nine manual steps, three of which are "download an artifact and re-upload it somewhere else".

To be fair to what exists: `version-manager.sh` already solves the hard part of step 2. The numbers do not drift *within* a commit, because they are generated from one file. The remaining problem is that a release still requires a source-editing commit before the tag exists, so the tag and the code it points at agree only because the procedure was followed in the right order. Section 4.1 removes the ordering requirement rather than the tool.

### 1.3 Measured pain

Not asserted, measured on this repository:

- **`run-tests.yml` takes ~9 minutes** and is a single opaque check. Last 15 runs: 8.3 to 9.2 minutes for successes. When it fails you get one log containing every tier and every database, and you must read it to learn what broke.
- **Runner minutes are free** (public repository), so serializing work buys nothing. The 9 minutes is pure wall clock loss.
- **No lint, no vet, no vulnerability scanning runs in CI at all.** `make check` exists in `src/authserver/Makefile` and is never invoked by any workflow.
- **Nothing validates the release path until release time.** A PR that breaks `Dockerfile-authserver` or the `darwin/arm64` cross-compile is invisible until a tag is pushed and the release job fails.

### 1.4 Constraints discovered during design

These are facts verified against the repository and against live containers, and they constrain the solution.

**A. The docs link to release assets at stable, unversioned URLs.**

`site/src/content/docs/getting-started/setup-wizard.mdx` and `quick-local-test.mdx` both contain links of the form:

```
https://github.com/leodip/goiabada/releases/latest/download/goiabada-setup-linux-amd64
```

Two consequences:

- The setup binaries **must keep unversioned filenames**. Adding a version would break every download link in the docs.
- A prerelease tag **must** be marked as a GitHub prerelease. `/releases/latest/` skips prereleases, so a `v1.6.0-rc1` published as a normal release would silently retarget every docs download link at a release candidate.
- Draft releases are also skipped by `/releases/latest/`, so the draft-first flow in this design is safe by construction.

**B. All three database servers can be port-configured by environment variable alone.**

This matters because GitHub Actions service containers cannot override a container's `command`, and `docker-compose-test.yml` currently sets non-default ports that way (`command: --port=13306` for MySQL, `-p 15432` for Postgres).

Verified by running the images directly:

| Image | Mechanism | Verified |
|---|---|---|
| `mysql:latest` | `MYSQL_TCP_PORT=13306` | Yes, `mysqladmin ping --port=13306` succeeded |
| `postgres:18` | `PGPORT=15432` | Yes, `pg_isready -p 15432` returned "accepting connections" |
| `mssql/server:2022` | `MSSQL_TCP_PORT=11433` | Already env-based in the current compose file |

Therefore CI service containers can present the **exact same hostnames and ports as the devcontainer** (`mysql-server:13306`, `postgres-server:15432`, `mssql-server:11433`), and `run-tests.sh` needs no changes to its database configuration to run in CI.

**C. `run-tests.sh` already supports the slicing this design needs.**

It accepts `--type internal|core|adminconsole|data|integration|modules|all`, `--db mysql|postgres|mssql|sqlite|all`, and `--run <pattern>`. CI can therefore reuse the exact script the developer runs locally rather than reimplementing the test invocation in YAML.

Its one CI-hostile behavior: it invokes `./build.sh` unconditionally at the top of every run, so calling it twice within a job builds twice.

**D. The lint backlog is 81 findings plus 2 unformatted files, and 75 of them are one mechanical rewrite in one file.**

Re-measured on this repository at commit `8b69223`, across all four Go modules, with golangci-lint's issue caps **disabled**:

```bash
golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./...
```

| Module | `go vet` | `staticcheck` | `golangci-lint` (stock) | `unparam -exported` | `gofmt -l` |
|---|---|---|---|---|---|
| `core` | clean | 0 | 1 | 0 | 2 files |
| `authserver` | clean | 0 | 0 | 0 | 0 |
| `adminconsole` | clean | 0 | 0 | 0 | 0 |
| `cmd/goiabada-setup` | clean | 0 | **80** | 0 | 0 |

**An earlier revision of this table reported 8 for the setup module and 11 findings overall. That measurement was truncated, and the numbers above supersede it.** golangci-lint defaults to `max-same-issues=3`, which collapsed 75 `QF1012` findings to 3 and produced exactly the 8 recorded before. `max-issues-per-linter=50` would have bound as well, since staticcheck's real total in that module is 78, so **both** flags are required to see the backlog at all. Any future re-measurement must pass both.

There is **no `.golangci.yml` anywhere in the repository**, so those numbers reflect golangci-lint 2.12.2's default linter set, confirmed with `golangci-lint linters` to be `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`.

The complete backlog is 81 golangci-lint findings across 2 files, plus 2 files that need formatting:

| Where | Finding | Count |
|---|---|---|
| `cmd/goiabada-setup/main.go` | `QF1012`, `WriteString(fmt.Sprintf(...))` → `fmt.Fprintf` | 75 |
| `cmd/goiabada-setup/main.go` | `QF1001`, De Morgan's law | 3 |
| `cmd/goiabada-setup/main.go` | `errcheck`, unchecked `rl.Close` and `db.Close` | 2 |
| `core/urlutil/redirect_uri.go` | `QF1001`, De Morgan's law in the host-suffix check | 1 |
| `core/i18n/error_codes.go`, `core/i18n/middleware_test.go` | need a `gofmt -w` pass | 2 files |

**All of the above was cleared in stage 0.** The numbers in this constraint describe the baseline at `8b69223`; they are kept as the measurement that drove the 4.4 decision, not as a description of the current tree.

**What changed is the scale, not the difficulty.** Every finding is still individually trivial and none is a real defect. But 75 of the 81 are the same rewrite in a single ~2100-line file, `cmd/goiabada-setup/main.go`, which assembles docker-compose and k8s manifests through a long run of `sb.WriteString(fmt.Sprintf(...))` calls. That concentration is what makes the cleanup a reviewable chunk of work rather than an afterthought, and it is what section 4.4 now has to weigh.

Verbatim linter output for the setup module, line numbers **re-verified at `8b69223`**, where all eight are still exact. This is the head of the report, not the whole of it: the three `QF1012` entries shown are the first of 75, which run from `main.go:1513` to `main.go:2084`.

```
main.go:158:16:  Error return value of `rl.Close` is not checked (errcheck)
main.go:1404:16: Error return value of `db.Close` is not checked (errcheck)
main.go:1188:6:  QF1001: could apply De Morgan's law (staticcheck)
main.go:1250:6:  QF1001: could apply De Morgan's law (staticcheck)
main.go:1274:6:  QF1001: could apply De Morgan's law (staticcheck)
main.go:1513:3:  QF1012: Use fmt.Fprintf(...) instead of WriteString(fmt.Sprintf(...)) (staticcheck)
main.go:1515:3:  QF1012: Use fmt.Fprintf(...) instead of WriteString(fmt.Sprintf(...)) (staticcheck)
main.go:1529:3:  QF1012: Use fmt.Fprintf(...) instead of WriteString(fmt.Sprintf(...)) (staticcheck)
   ... 72 further QF1012, through main.go:2084
```

The `staticcheck` column reading 0 while `golangci-lint` reads 80 is **not a contradiction**: the standalone binary does not ship the `QF` checks at all. See 5.8, which also has to settle which of the two sets `make check` is supposed to enforce.

**Separately, `govulncheck` is not clean.** It sits in section 4.4's blocking set but had never been measured. At `8b69223` it reports `GO-2025-3884` (`github.com/gorilla/csrf@v1.7.3`, improper validation of `TrustedOrigins` allowing CSRF) as **called** from `core`, `authserver` and `adminconsole`, exiting 3 in all three:

```
core:         middleware/middleware_csrf.go:225:22: middleware.MiddlewareCsrf calls csrf.TrustedOrigins
authserver:   internal/server/server.go:270:47: Server.initMiddleware → MiddlewareCsrf → csrf.TrustedOrigins
adminconsole: internal/server/server.go:212:47: Server.initMiddleware → MiddlewareCsrf → csrf.TrustedOrigins
```

**`Fixed in: N/A`** — the advisory has no fixed version, so this cannot be cleared by upgrading. A second advisory, `GO-2026-5932` (`golang.org/x/crypto/openpgp` unmaintained), is present in the module graph of all four modules but is not reachable, so it does not fail the scan.

**Tracked as issue #155**, which carries the analysis and the remediation options (`net/http.CrossOriginProtection` on Go 1.25+, or the `filippo.io/csrf/gorilla` drop-in). Dependabot has it open as alerts #47, #48 and #49. Section 4.4 covers what it means for making the gate blocking.

**E. `versions.yaml` is the actual source of truth for versions, not the build scripts.**

`src/authserver/versions.yaml` plus `src/authserver/version-manager.sh` already exist and already solve part of this problem. The `VERSION=` lines in the build scripts are *generated*, not authored. `cmd_update` propagates `versions.yaml` into every file that mentions a version.

`project.goiabada` (currently `1.5.2`) is written into:

| Target | Pattern |
|---|---|
| `src/build/build-binaries.sh` | `VERSION="1.5.2"` |
| `src/build/build-docker-images.sh` | `VERSION="1.5.2"` |
| `src/cmd/goiabada-setup/main.go` | `leodip/goiabada:authserver-1.5.2` (×2) and `leodip/goiabada:adminconsole-1.5.2` (×2) |

`project.goiabada-setup` (currently `1.0.0`) is written into the setup module's `Makefile` (`VERSION ?=`), its `build-binaries.sh` (`VERSION=`), and `const version` in its `main.go`.

`tools.*` and `cdn.*` are written into the devcontainer Dockerfile, `Dockerfile-authserver`, `Dockerfile-adminconsole`, `Dockerfile-test`, all four `go.mod` files, four HTML templates, and `go-version:` in `build-binaries.yml` and `build-setup-binaries.yml`.

**The sharp edge.** The setup wizard writes docker-compose and k8s manifests for users, with the image tag hardcoded in the generated string:

```go
sb.WriteString("    image: leodip/goiabada:authserver-1.5.2\n")   // ×2
sb.WriteString("    image: leodip/goiabada:adminconsole-1.5.2\n") // ×2
```

So the setup binary ships pinned to a specific release. Tagging `v1.6.0` on a commit whose `main.go` still reads `1.5.2` would produce a setup wizard that hands users manifests pointing at the *previous* release. Silent, and precisely the drift that tag-as-truth exists to eliminate. Section 4.1 resolves this.

Separately, `cmd_update` writes `go-version:` into two workflow files that this design deletes, so it needs repointing regardless of any other decision.

---

## 2. Goal

1. **A PR check that tells you what happened without opening a log.** Distinct, named jobs and steps in the GitHub UI, so a red run identifies the tier and the database at a glance.
2. **A release that is one command.** `git push origin v1.6.0`, then write the notes and click Publish.
3. **One source of truth per kind of version.** The git tag owns the product version. `versions.yaml` keeps owning toolchain and CDN pins, which is a separate job it already does well.
4. **Catch the things that currently escape**: lint regressions, vulnerable dependencies, and breakage in the release path itself.

Non-goals: changing the test harness itself, changing how tests are written, or altering the devcontainer workflow.

---

## 3. Proposed solution

Four workflows replace the five that exist.

```
check.yml     PR to main, push to main, and callable by release.yml
release.yml   push of a v* tag       →  builds everything, leaves a DRAFT
publish.yml   release published      →  moves "latest" (images only, never docs)
docs.yml      push to main touching site/**, release published, manual
```

Plus `.github/dependabot.yml` and a checked-in `.golangci.yml`.

### At a glance: a PR run

```
✓ Lint                  38s
✓ Vulnerabilities       41s
✓ Unit / core          1m10s
✓ Unit / authserver    1m48s
✓ Unit / adminconsole    41s
✓ Tests / sqlite       1m52s
✓ Tests / mysql        3m40s
✗ Tests / postgres     2m15s        ← you already know what broke
✓ Tests / mssql        4m30s

  └─ Tests / postgres
     ✓ Start services            22s
     ✓ Build                     18s
     ✓ Data tests                48s
     ✗ Integration tests         47s
```

### At a glance: a release

```
git push origin v1.6.0
  ↓
release.yml            (strict job DAG, see 5.2)
  ✓ Verify             semver, tag is on main, derive version, detect prerelease
      ↓
  ✓ Checks             calls check.yml, full matrix against the tagged commit
      ↓
    ┌────────────────┴────────────────┐
  ✓ Binaries                        ✓ Images
    5 zips + 5 setup binaries         multi-arch push, VERSION TAG ONLY,
    + checksums.txt + attestation     Docker Hub + GHCR; Docker Hub attested
    └────────────────┬────────────────┘
      ↓
  ✓ Draft              draft release with all 11 assets attached
  ↓
  you write the notes, click Publish
  ↓
  ├─ publish.yml   ✓ Retag latest   imagetools manifest retag, images only,
  │                                 skipped entirely for a prerelease
  └─ docs.yml      ✓ Docs           docs-1.6.0, plus docs-latest if stable
```

Nothing builds until `Checks` is green, and nothing is published until both build jobs are. `publish.yml` and `docs.yml` are independent consumers of the same `release: published` event; neither dispatches the other.

---

## 4. Decisions and rationale

### 4.1 Tag-driven releases, and the split with `versions.yaml`

**Decision.** Pushing `v1.6.0` is the entire release procedure. Ownership of version numbers splits in two:

| Kind | Examples | Owner in v2 | Mechanism |
|---|---|---|---|
| **Product version** | the number in `authserver-1.6.0`, in the zip filenames, in `core/constants.Version` | **The git tag** | `ldflags` at build time |
| **Toolchain and CDN pins** | `tools.go`, `tools.tailwind`, `tools.golangci-lint`, `tools.mockery`, `cdn.daisyui`, `cdn.humanize-duration` | **`versions.yaml`, unchanged** | `version-manager.sh update`, as today |

`project.goiabada` and `project.goiabada-setup` are removed from `versions.yaml`. Everything else in that file stays exactly as it is.

**Rationale for the split.** These are two different activities that happen at two different times, and merging them is why releasing currently requires editing files.

Bumping Tailwind or mockery is *maintenance*: you do it when upstream ships something, it wants a human reviewing a diff, and it belongs in a commit. `version-manager.sh check` is genuinely good at this, and nothing replaces it. Dependabot covers none of these: not the Go toolchain version, not the Tailwind CLI binary, not mockery, not CDN script tags embedded in HTML templates. So `versions.yaml` keeps that job.

Cutting a release is *not* maintenance. It should assert "ship what is on main right now", and asking a human to first edit six generated files, review the diff, and commit is how the image tag and the version compiled into the binary end up disagreeing. The tag is already the thing everyone treats as the release identity, so it should be the thing the build reads.

**Rationale for `ldflags` over editing files.** The authserver and adminconsole *already* get their version this way, injected into `core/constants.Version` at build time. Extending the same pattern to `goiabada-setup` makes the whole project consistent and resolves the constraint E sharp edge structurally: the four hardcoded image tags become a variable, so the setup binary and the release it ships in are physically incapable of disagreeing, because both derive from one tag.

```go
// src/cmd/goiabada-setup/main.go
var version  = "dev"      // was: const version = "1.0.0"
var imageTag = "latest"   // overridden at build time

sb.WriteString("    image: leodip/goiabada:authserver-" + imageTag + "\n")
```

Dev builds default to `latest`, which is the sensible thing for someone running the wizard from a source checkout.

**Rejected: keep `version-manager.sh update` and add a mismatch guard.** CI would fail the release when the tag and `versions.yaml` disagree. This detects the problem rather than preventing it, and preserves a multi-step release ritual whose only purpose is feeding a number to a build that could simply read the tag.

**Rejected: manual dispatch with a version input.** Keeps a human typing the version, reintroducing typos, and the tag only comes into existence after CI succeeds, so a failed release leaves no record of what was attempted.

**Rejected: hybrid, with generated image pins still managed in `versions.yaml`.** Only useful if you want to deliberately ship a wizard pinning users to an older known-good release. Absent that need, it retains a manual step for no benefit.

### 4.1a The setup tool adopts the product version

**Decision.** `project.goiabada-setup` is dropped. `goiabada-setup --version` reports the release it shipped in.

**Rationale.** It ships in every release regardless, and constraint A requires its filename stay unversioned, so `--version` is the only way anyone can identify which build they have. Today it answers `1.0.0` permanently, which identifies nothing. Answering `1.6.0` tells you exactly which release a user downloaded, which is what you actually want when someone reports a problem.

Reversible: if you would rather it version independently, it goes back into `versions.yaml` and keeps its own `ldflags` value.

### 4.2 A job per database, named steps per tier

**Decision.** Four `Tests / <db>` jobs, each with `Build`, `Data tests`, `Integration tests` as separate steps. Three separate `Unit /` jobs.

**Rationale.** The primary complaint is visibility, not speed. GitHub only renders two levels: jobs in the sidebar and steps within a job. Putting the database on the job axis means the sidebar answers "which database broke" without a click, and putting the tier on the step axis answers "which tier" with one click. Speed is a free side effect: wall clock drops from ~9 minutes to roughly the slowest single leg.

**Rejected: a job per database *and* tier** (12+ jobs). Every job re-boots its own database service container, and MSSQL takes 30 to 60 seconds to pass a health check. Roughly doubles runner time for a marginal visibility gain over putting tiers on steps.

**Rejected: one job with many steps.** Cheapest, but the sidebar stays a single line, which is the status quo complaint.

### 4.3 CI runs inside a container with named service containers

**Decision.** The test jobs use `container: golang:1.26.5-bookworm` with `mysql-server`, `postgres-server`, `mssql-server` and `mailpit` as service containers, using the same hostnames and ports as the devcontainer.

**Rationale.** This is what lets CI call `./run-tests.sh` unchanged. When a job specifies `container:`, GitHub places the job and its services on a shared network where services are addressable by their label, exactly like Compose service names. Constraint B above confirms the ports can be set by env alone. The alternative, running bare on the runner with services on `localhost`, would require `run-tests.sh` to learn a CI-specific host configuration, permanently splitting "what CI runs" from "what I run locally".

**Why bookworm and not alpine**, despite `Dockerfile-test` using alpine: GitHub injects its own glibc-linked Node.js runtime into container jobs to execute actions, which does not run on musl. Debian sidesteps a known class of breakage for no real cost.

**Accepted cost.** The service definitions live in the workflow and must stay in step with `docker-compose-test.yml`. This is genuine duplication. It is accepted because the alternative (Compose inside CI) is what produces the single opaque 9-minute check this design exists to eliminate.

### 4.4 Lint, vet and govulncheck block PRs

**Decision.** `gofmt`, `go vet`, `staticcheck`, `golangci-lint` and `unparam` block, as does `govulncheck`. A `.golangci.yml` is checked in pinning the linter set explicitly.

**The rationale this section used to give no longer holds, and the decision is reopened.** It argued from constraint D that the entire backlog was 11 trivial findings in 4 files, so a blocking gate was "a one-commit cleanup, not a project". **That premise was a truncated measurement.** The real backlog is 81 golangci-lint findings plus 2 unformatted files (1.4 D). The general argument survives — gates are worth far more before a codebase accumulates debt than after, and the marginal cost will never again be as low as it is now — but "nearly free" is no longer a fact you can read off the numbers, so making lint blocking from stage 2 should be re-decided rather than inherited.

What changed is less alarming than 11 → 81 sounds. 75 of the 81 are a single mechanical rewrite (`QF1012`) in one file, `gofmt -w` disposes of 2 more, and nothing found is a defect. The question is therefore how much churn to accept in one commit, and in which file — not whether the codebase is hiding quality problems.

**Three options. Decided: A.** The options are kept below as the record of what was weighed. Stage 0 has since been implemented against option A and the backlog is 0; see stage 0 for what the work actually involved, which differed from the estimate in one material way.

| | Option | Stage 0 becomes | Risk |
|---|---|---|---|
| **A** | ***Chosen.*** **Fix everything first**, gate blocks from stage 2 as originally designed | 81 fixes plus 2 `gofmt -w`, of which 75 are one pattern in `cmd/goiabada-setup/main.go`. ~~`golangci-lint run --fix` applies `QF1001` and `QF1012` automatically~~ — **this turned out to be false in this repository; see stage 0** | A ~75-line churn commit in the file that generates users' deployment manifests. Mechanical, but it wants real review, and an auto-applied rewrite in exactly that file is the kind of diff that gets skimmed |
| **B** | **Narrow the enabled linter set** so the backlog is small by construction | Exclude the `QF` (quickfix) family in `.golangci.yml`; backlog drops to 2 `errcheck` + 2 `gofmt`, near the original scope | Depends entirely on how narrow the cut is — see below. Also permanently forgoes two genuine readability checks |
| **C** | **Start advisory, promote to blocking** | Stage 0 adds `.golangci.yml` and the tool pins but no fixes; stage 2's `Lint` job carries `continue-on-error: true`; a named later stage removes it | The standard failure mode: the advisory gate stays advisory forever. Only worth taking with a specific stage that flips it, or it is "no gate" with extra steps |

Option B has a sub-choice that matters more than the option itself: **excluding the `QF` family is very different from excluding `staticcheck`.** Dropping `staticcheck` wholesale would give up the `SA*` bug-finding checks, which are the part most worth having in an authentication server. Excluding only `QF*` keeps every `SA*` check and costs only the two style rules — and, per 5.8, it has the side benefit of making golangci-lint and the standalone `staticcheck` binary agree on what "clean" means, which they currently do not.

Whichever is chosen, the rest of this section is unaffected: `.golangci.yml` with `default: none` is required either way, and the tool pins in stage 0 are required from the moment the gate blocks anything.

**Consequence of choosing A:** `QF*` stays enabled, so golangci-lint remains strictly wider than the standalone `staticcheck` binary, and 5.8's question resolves in the same direction — `.golangci.yml` is now the single definition of lint-clean.

**`govulncheck` is a separate and harder call.** It is **not clean today** (1.4 D): `GO-2025-3884` in `github.com/gorilla/csrf@v1.7.3` is reachable from three of the four modules and **has no fixed version**, so it cannot be cleared by upgrading. Making `govulncheck` blocking in stage 2 therefore requires deciding what to do about that one advisory — suppress it explicitly, replace the CSRF middleware, or run `govulncheck` advisory-only until it is resolved. **That decision now lives in issue #155**, which is a prerequisite for requiring the `Vulnerabilities` check rather than something to settle in this document. It does not weaken the argument that follows for `govulncheck` over a generic CVE scanner; it is a question about one specific unfixed finding, and the fact that the tool surfaced a reachable one on its first run is an argument *for* the tool.

`govulncheck` specifically, rather than a generic CVE scanner: it does reachability analysis and only reports advisories actually invoked from your call graph, so it stays quiet instead of producing the noise that trains people to ignore it. For software whose entire purpose is being trusted with authentication, shipping a known-vulnerable dependency is the failure mode most worth automating away.

**The `.golangci.yml` matters.** Without a config, golangci-lint runs whatever its current default set is. A new golangci-lint release that enables an additional linter would redden every PR opened that week, through no change of yours. Pinning the set makes linter changes an explicit, reviewable commit.

### 4.5 Build validation on main only, not on PRs

**Decision.** Cross-compiling all five targets and building both Docker images runs on push to `main`, not on pull requests.

**Rationale.** Your call, and a reasonable trade. It still moves discovery of a broken Dockerfile or cross-compile from "when I tag a release" to "right after the merge", which is the important shift, while keeping PR feedback lean. The residual risk is a few hours between merge and detection, during which `main` is briefly unreleasable.

**Refinement available if you want it later:** run build validation on PRs only when the PR touches `src/build/**`, `Dockerfile*` or any `go.mod`. That gets PR-time coverage for the changes that can actually break it, at near-zero cost for the Go-only PRs that are the majority. Left out of v1 to avoid a third-party paths-filter action.

### 4.6 Two-phase release: draft, then publish

**Decision.** The tag push builds everything and pushes **version-tagged images only**, then stops at a draft release. Publishing the release fires two independent workflows: `publish.yml` moves the `latest` image tags, and `docs.yml` rebuilds the docs image. Neither triggers the other (5.4).

**Rationale.** Your release notes are hand-written and substantial (the `v1.5.2` body cites issue numbers and OAuth/OIDC spec sections), so a draft to edit is required regardless. The question was whether `latest` should move before or after you write them.

Moving it after is strictly better and nearly free: `docker buildx imagetools create -t <repo>:authserver-latest <repo>:authserver-1.6.0` retags an existing manifest server-side without rebuilding or re-pushing any layers, so the second phase takes seconds. The payoff is that `latest`, the tag every unpinned `docker compose` deployment follows, moves at the moment you consciously decide to release, not at the moment CI happens to go green. It also gives you a real abort: if the draft looks wrong, delete it, and no user-visible tag ever moved.

**Rejected: fully automatic publication.** Loses the curated notes and removes the abort.

### 4.7 The release re-runs the full test matrix

**Decision.** `release.yml` calls `check.yml` via `workflow_call` against the tagged commit before building anything.

**Rationale.** Roughly 5 minutes of redundancy when the tagged commit already passed on `main`, and it buys the difference between "main was green at some point" and "this exact tag is green". Tags get pushed at the wrong commit; this catches it before anything reaches a registry. `workflow_call` means the definition is not duplicated, so the release path can never drift from the PR path.

### 4.8 The release fails if the tag is not on main

**Decision.** A `Verify` job rejects a tag whose commit is not reachable from `origin/main`.

**Rationale.** Cheap guard against shipping from a feature branch by accident. Given your workflow puts issue work on `issue-<n>-<slug>` branches, tagging while checked out on one is a plausible slip.

**Note:** this is my judgment call, not something you asked for. Easy to drop if you ever want to ship a hotfix tag from a branch.

### 4.9 Docs deploy on merge to main when `site/**` changes

**Decision.** Path-filtered trigger, plus a rebuild on release publication.

**Rationale.** Decoupling docs from releases means a typo fix ships when merged rather than waiting for the next release or a remembered manual dispatch. The path filter means Go-only PRs, the large majority, never pay for it. Rebuilding on release means the docs are refreshed promptly after publication.

**Correction to an earlier claim.** This originally said the release rebuild "keeps a release from ever shipping alongside stale docs". It does not: `release: published` fires *after* publication, so the docs lag the release by one build. `docs.yml` also owns this trigger exclusively, and prereleases do not move `docs-latest`. See 5.4.

### 4.10 Supply-chain extras

| Addition | Rationale |
|---|---|
| `checksums.txt` on releases | Lets anyone deploying the auth server verify the artifact they downloaded is the one you built. Standard for security-sensitive Go projects, costs one step. |
| Build provenance attestations | `actions/attest` produces signed, GitHub-native provenance for the binaries and the Docker Hub images, verifiable via `gh attestation verify`. No key management, no cost. For software whose job is being trusted, being able to prove which commit and workflow produced an artifact is proportionate. |
| Actions pinned by commit SHA | These workflows hold Docker Hub credentials. A moving tag like `@v6` means whoever controls that tag can change what executes next to your registry secrets. SHA pins remove that. |
| Dependabot | Pins go stale and unattended stale pins are worse than tags. Dependabot bumps both the pinned actions and all four Go modules, and its PRs run the same check suite. |
| GHCR alongside Docker Hub | Gives users a registry not subject to Docker Hub's anonymous pull rate limits, and keeps images reachable if Docker Hub credentials lapse. Authenticates with the built-in `GITHUB_TOKEN`, so no new secret. |

### 4.11 Prefer first-party actions and the `gh` CLI

**Decision.** Use `gh release create --draft` rather than a third-party release action, and keep the third-party surface to Docker's official actions.

**Rationale.** Every third-party action in a workflow that can push to your registries is supply-chain surface. `gh` is preinstalled on GitHub-hosted runners and does the job. Planned action inventory: `actions/checkout`, `actions/setup-go`, `actions/upload-artifact`, `actions/download-artifact`, `actions/attest` (all first-party), plus `docker/login-action`, `docker/setup-buildx-action`, `docker/setup-qemu-action` and `golangci/golangci-lint-action` (vendor-official).

---

## 5. Details

### 5.1 `check.yml`

```yaml
on:
  pull_request:    { branches: [main] }
  push:            { branches: [main] }
  workflow_call:
    inputs:
      full:        { type: boolean, default: false }   # release passes true

concurrency:
  group: check-${{ github.ref }}
  cancel-in-progress: true      # superseded PR pushes stop burning runners

permissions:
  contents: read                # minimal by default
```

| Job | Runs on | Steps |
|---|---|---|
| `Lint` | ubuntu + Go | `test -z "$(gofmt -l .)"`, `go vet`, `staticcheck`, `golangci-lint`, `unparam -exported`, each across all four modules |
| `Vulnerabilities` | ubuntu + Go | `govulncheck ./...` across all four modules |
| `Unit / core` | container | `./run-tests.sh --type core --no-build` |
| `Unit / authserver` | container | `./run-tests.sh --type internal --no-build` |
| `Unit / adminconsole` | container | `./run-tests.sh --type adminconsole --no-build` |
| `Tests / sqlite` | container + mailpit only | steps: `Build` (`./build.sh`), `Data tests` (`--type data --db sqlite --no-build`), `Integration tests` (`--type integration --db sqlite --no-build`) |
| `Tests / mysql` | container + mysql-server + mailpit | same three steps, `--db mysql` |
| `Tests / postgres` | container + postgres-server + mailpit | same three steps, `--db postgres` |
| `Tests / mssql` | container + mssql-server + mailpit | same three steps, `--db mssql` |
| `Build validation` | ubuntu, no registry credentials | only when `github.event_name == 'push'` or `inputs.full`; 5 platform binaries + both images, `--load` not `--push` |

#### Four explicit jobs rather than a matrix

An earlier draft of this design used `matrix: [sqlite, mysql, postgres, mssql]` for these four jobs. That is wrong, and the reason is worth recording so nobody "simplifies" it back.

A naive matrix gives every leg *all* the services: 12 database boots across 4 jobs, including MSSQL and MySQL for the SQLite leg, which uses neither. And GitHub **waits for every service health check before running any step**, so the SQLite leg (the fastest, the one you want quick feedback from) would sit blocked on an MSSQL container it never touches.

**Correcting an overstated claim.** An earlier revision said `services:` "cannot be conditioned on a matrix value". That is wrong: GitHub's context reference lists `matrix` as available to `jobs.<job_id>.services`, so a service's `image` **can** vary per leg. It has also been reported that an empty `image` skips the service outright, which would make a conditional matrix viable, though I could not find that behavior in GitHub's documentation to confirm it.

So four explicit jobs is a **readability choice, not a platform limitation**, and the honest reason is this: each database needs its own `env` block, its own `--health-cmd` and its own port. Expressing all of that through per-key conditional expressions produces something like

```yaml
image: ${{ matrix.db == 'mysql' && 'mysql:latest' || '' }}
options: ${{ matrix.db == 'mysql' && '--health-cmd "mysqladmin ping ..."' || '' }}
```

repeated for three databases across three keys. That trades 40 lines of obvious duplication for a dozen lines of conditional expressions that are harder to read and harder to debug when a health check misbehaves. Four plain jobs win on clarity.

Service containers per job, mirroring `docker-compose-test.yml`. Each job includes `mailpit` plus only its own database:

```yaml
services:
  mysql-server:
    image: mysql:latest
    env: { MYSQL_ROOT_PASSWORD: mySqlPass123, MYSQL_TCP_PORT: 13306 }
    options: >-
      --health-cmd "mysqladmin ping -uroot -pmySqlPass123 --port=13306 --protocol=tcp"
      --health-interval 3s --health-timeout 3s --health-retries 30
  postgres-server:
    image: postgres:18
    env: { POSTGRES_PASSWORD: myPostgresPass123, POSTGRES_DB: goiabada, PGPORT: 15432 }
    options: >-
      --health-cmd "pg_isready -U postgres -p 15432"
      --health-interval 3s --health-timeout 3s --health-retries 30
  mssql-server:
    image: mcr.microsoft.com/mssql/server:2022-latest
    env: { ACCEPT_EULA: Y, MSSQL_SA_PASSWORD: "YourStr0ngPassw0rd!", MSSQL_PID: Express, MSSQL_TCP_PORT: 11433 }
    options: >-
      --health-cmd "/opt/mssql-tools18/bin/sqlcmd -C -S localhost,11433 -U sa -P 'YourStr0ngPassw0rd!' -Q 'SELECT 1'"
      --health-interval 5s --health-timeout 5s --health-retries 40
  mailpit:
    image: axllent/mailpit
```

The container needs `net-tools` (`run-tests.sh` uses `netstat` in `kill_processes_on_ports`), `curl`, `zip`, and the Tailwind CLI. Installed in a cached setup step.

Test-only environment values (session keys, the AES key, admin credentials) are copied from `docker-compose-test.yml` as literals. They are fixed test values, not secrets, and keeping them literal in the workflow keeps CI reproducible locally.

### 5.2 `release.yml`

```yaml
on:
  push:
    tags: ['v*']

permissions:
  contents: write        # create the draft release
  packages: write        # push to GHCR
  id-token: write        # attestations
  attestations: write
```

| Job | `needs:` | Environment | Does |
|---|---|---|---|
| `Verify` | — | none | Validates the tag (see below); fails if the commit is not reachable from `origin/main`; outputs `version` (tag minus `v`) and `prerelease` |
| `Checks` | `Verify` | none | `uses: ./.github/workflows/check.yml` with `full: true` |
| `Binaries` | `Verify, Checks` | none | `build-binaries.sh --version $VERSION` and the setup script; produces 5 zips + 5 unversioned setup binaries; validates the artifact manifest; generates `checksums.txt`; attests all of it |
| `Images` | `Verify, Checks` | **`prod`** | QEMU + buildx, multi-arch `linux/amd64,linux/arm64`, pushes `authserver-$VERSION` and `adminconsole-$VERSION` to Docker Hub **and** GHCR. **No `latest` tag.** Attests the Docker Hub copy by digest (5.2) |
| `Draft` | `Binaries, Images` | none | `gh release create v$VERSION --draft --title "Release $VERSION"`, `--prerelease` when applicable, attaches all 11 assets |

#### The DAG is load-bearing

**GitHub runs jobs concurrently unless `needs:` says otherwise.** Revision 1 and 2 of this document described `Checks` as running "before building anything" but never specified the dependencies, which would have meant `Images` pushing to Docker Hub and GHCR while the test matrix was still running, and possibly failing. A release that publishes images for a commit whose tests then fail is worse than no automation at all, because the registry tags cannot be un-pulled.

```
Verify ──→ Checks ──┬──→ Binaries ──┐
                    └──→ Images ────┴──→ Draft
```

Three properties this must guarantee, worth asserting during implementation rather than assuming:

1. `Binaries` and `Images` depend on **both** `Verify` and `Checks`. Depending on `Checks` alone would technically imply `Verify` transitively, but naming both makes the intent explicit and survives someone editing `Checks`.
2. `Draft` depends on both build jobs, so a partial release cannot produce a draft with missing assets.
3. `Images` is the only job with registry credentials, so a failure anywhere upstream means nothing was ever pushed.

`concurrency: { group: release-${{ github.ref }} }` prevents two pushes of the same tag racing.

#### `environment: prod` is mandatory, not decorative

**Verified against the repository:** `gh secret list` at repo scope returns **nothing**. `DOCKER_USERNAME` and `DOCKER_PASSWORD` exist only in the `prod` environment. GitHub exposes environment secrets **only to jobs that declare that environment**, so a job without `environment: prod` receives empty strings and `docker/login-action` fails, or worse, succeeds anonymously and fails later at push.

Every credential-bearing job must declare it. The old `build-and-push-docker-images.yml` and `publish-documentation.yml` both already did; the replacements must not lose it.

`Verify`, `Checks`, `Binaries` and `Draft` need no environment. `Draft` uses the built-in `GITHUB_TOKEN`.

#### Tag validation

`Verify` accepts `v<major>.<minor>.<patch>` with an optional prerelease suffix, and **rejects SemVer build metadata**:

```bash
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
    echo "::error::tag '$TAG' must be v<major>.<minor>.<patch>[-prerelease], with no build metadata"
    exit 1
}
```

This is not the full SemVer grammar. It accepts a few things SemVer forbids: leading zeros (`v01.0.0`), and empty prerelease identifiers (`v1.6.0-rc..1`). The strict grammar takes three more lines of regex to exclude inputs that would have to be typed deliberately, on a repository with one maintainer who has tagged 20 releases in the conventional form. Not worth it. What **is** worth enforcing is the absence of `+`, which the pattern does, because that one fails at the registry rather than at validation.

`+` is legal in SemVer but **invalid in a Docker tag**, so `v1.6.0+build.3` would pass a naive SemVer check and then fail at push, or silently produce a mangled tag. Rejecting it up front is cheaper than defining a `+` to `_` mapping nobody will remember.

#### `Verify` needs full history

The "tag is on main" check (4.8) is `git branch -r --contains "$GITHUB_SHA" | grep -q origin/main`. **`actions/checkout` defaults to `fetch-depth: 1`**, which on a tag push fetches the tagged commit alone with no remote-tracking refs. The check would then find nothing and reject every tag, including correct ones: a guard that fails closed on all input is just an outage.

```yaml
- uses: actions/checkout@<sha>
  with:
    fetch-depth: 0        # required: the tag-on-main check needs refs
```

Worth a comment in the workflow, because `fetch-depth: 0` otherwise looks like a gratuitous slowdown and invites removal.

#### Image attestation needs a digest

`actions/attest` requires `subject-digest` for an image, and `build-docker-images.sh` does not currently emit one: `docker buildx build --push` prints the digest to its log but exposes it nowhere consumable.

The script must write buildx metadata to a file and the workflow must read the digest from it:

```bash
docker buildx build ... --metadata-file /tmp/authserver-meta.json --push .
```
```yaml
- id: digest
  run: echo "value=$(jq -r '."containerimage.digest"' /tmp/authserver-meta.json)" >> "$GITHUB_OUTPUT"
```

Without this, the attestation step has nothing to attest. Noted because it is easy to write the workflow, watch it go green, and never notice the attestation covers nothing.

**~~Use `actions/attest`, not `actions/attest-build-provenance`.~~ Wrong, and it broke the first release run.** The upstream README does say *"new implementations should use `actions/attest` instead"*, and finding 22 recorded that faithfully. But that advice is about **custom** predicates. `actions/attest` is the generic action: it attests a predicate you supply, and has no provenance default. Used as specified here it fails outright with:

```
Error: predicate-type must be provided
```

Its input documentation is what makes this easy to get wrong. `predicate-type` is described as *"required when using `predicate` or `predicate-path` for custom attestations"*, which reads as though omitting all three yields provenance. It does not. Build provenance keeps a dedicated action precisely because assembling that predicate is not trivial.

**Corrected: use `actions/attest-build-provenance`,** for both the binaries and the images. It takes the same `subject-path` / `subject-name` + `subject-digest` inputs, so nothing else in this section changes.

Caught by the `v1.5.3-rc1` dry run, which is exactly the class of error a dry run exists to find: `actionlint` passes, the YAML is valid, the inputs are all real, and it fails only when the step actually runs — at release time.

**Scope: Docker Hub only.** `subject-name` binds an attestation to a fully qualified image name, so covering GHCR too would mean four attest calls per release (two images × two registries) rather than two.

Docker Hub is the canonical location that every doc and compose file points at, so it gets the attestation. **GHCR is documented as an unattested convenience mirror** whose digests are identical to Docker Hub's, so anyone who wants a verified image can verify the Docker Hub reference and pull either. This halves the attestation wiring for no practical loss, and can be widened later by adding two steps.

Binary attestation is one call, pointed at the staging directory holding the validated asset set:

```yaml
- uses: actions/attest@<sha>
  with:
    subject-path: 'dist/*'      # all 11 validated assets, not just the 5 zips
```

**No `predicate-type`.** Checked against the upstream README: mode is inferred from the inputs, and supplying `predicate-type` selects *custom* mode, which then requires exactly one of `predicate` or `predicate-path`. Provenance is the default precisely when those inputs are **omitted**, so an earlier draft that passed `predicate-type: https://slsa.dev/provenance/v1` alone would have failed outright.

The `dist/` staging directory also fixes a scope error in that draft: `src/build/*.zip` covers only the 5 zips, while the `Binaries` job promises to attest all 11 assets. Having `build-binaries.sh` assemble the validated manifest (5.6.3) into `dist/` gives the attestation, the checksums and the release upload one identical source of truth.

### 5.3 `publish.yml`

```yaml
on:
  release: { types: [published] }

permissions:
  contents: read
  packages: write            # REQUIRED: GHCR push. Verified the repo default is `read`

jobs:
  retag:
    environment: prod                                  # required, see 5.2
    if: ${{ !github.event.release.prerelease }}        # an rc never moves latest
    steps:
      - uses: docker/login-action@<sha>                # Docker Hub
        with: { username: "${{ secrets.DOCKER_USERNAME }}", password: "${{ secrets.DOCKER_PASSWORD }}" }
      - uses: docker/login-action@<sha>                # GHCR
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
```

**Both the permission block and both logins are mandatory.** Verified with `gh api`: this repository's `default_workflow_permissions` is `read`, so without `packages: write` the GHCR `imagetools create` push fails. An earlier draft declared only `environment: prod` and neither login.

```bash
for img in authserver adminconsole; do
  for reg in leodip/goiabada ghcr.io/leodip/goiabada; do
    docker buildx imagetools create -t $reg:$img-latest $reg:$img-$VERSION
  done
done
```

A manifest retag. No rebuild, no layer re-upload, and byte-identical to what was tested.

**This workflow does not touch the docs.** See 5.4 for why.

### 5.4 `docs.yml`

```yaml
on:
  push:
    branches: [main]
    paths: ['site/**']
  release: { types: [published] }
  workflow_dispatch:

jobs:
  build-and-push:
    environment: prod                                  # required, see 5.2
```

Builds `site/Dockerfile` and pushes `docs-latest`, plus `docs-<version>` when the trigger is a release.

#### One docs trigger, not two

An earlier draft had `publish.yml` dispatch the docs build **and** `docs.yml` listening for `release: published`. A stable release would then build and push the docs image twice, concurrently, racing on the same tag.

**Resolved:** `docs.yml` owns every docs build. `publish.yml` never dispatches it.

#### Prereleases and `docs-latest`

The `release: published` trigger fires for prereleases too, so publishing `v1.6.0-rc1` would push `docs-latest` while the image `latest` tags deliberately stay put. That is inconsistent, and it means an rc can change what users read.

**A job-level guard is the wrong tool here**, and an earlier draft of this section got it wrong. This expression:

```yaml
if: ${{ github.event_name != 'release' || !github.event.release.prerelease }}
```

skips the **entire job** for a prerelease, so an rc would push nothing at all, contradicting the sentence directly beneath it that promised `docs-<version>`. Skipping the job and pushing a version-only tag are different behaviors, and the guard implemented the wrong one.

**Fix: the job always runs for a published release, and the tag list is computed.** The condition belongs on the tags, not on the job:

```bash
TAGS=()
case "$GITHUB_EVENT_NAME" in
  push)         TAGS+=("docs-latest") ;;                       # site/** merged to main
  workflow_dispatch) TAGS+=("docs-latest") ;;
  release)
    TAGS+=("docs-${VERSION}")
    [ "$PRERELEASE" = "true" ] || TAGS+=("docs-latest")        # stable only
    ;;
esac
```

| Trigger | Tags pushed |
|---|---|
| merge to `main` touching `site/**` | `docs-latest` |
| stable release published | `docs-latest`, `docs-$VERSION` |
| **prerelease** published | `docs-$VERSION` **only** |

This keeps the intent (an rc never changes what users read) while still producing a versioned docs image for the rc, which is what makes an rc reviewable.

#### Correcting an overstatement

Section 4.9 previously claimed this arrangement means "a release never ships stale docs". It cannot: `release: published` fires *after* publication, so there is a window of a couple of minutes where the release is live and the docs image is the previous build. The accurate claim is that the docs are refreshed promptly after publication, and that the window is bounded by one docs build. If you want a genuinely stale-free release, the docs image has to be built and pushed in `release.yml` before the draft is created, which is a change worth considering but not made here.

### 5.5 `run-tests.sh` changes

Five changes. Local behavior is unchanged in every case: everything CI-specific is gated on `$GITHUB_ACTIONS`, which is unset on a workstation.

#### 5.5.1 `--no-build` flag

`./build.sh` runs unconditionally before the type dispatch. A `Tests / <db>` job invokes the script twice (data, then integration), so it would build twice, and the three `Unit /` jobs would each run a Tailwind build for tests that never serve a page.

Argument parsing:

```diff
 TYPE="all"
 DB="all"
 RUN_PATTERN=""
+BUILD=true

 while [ $# -gt 0 ]; do
     case "$1" in
         -t|--type)
             TYPE="${2:-}"; shift 2 ;;
+        -n|--no-build)
+            BUILD=false; shift ;;
```

Build phase:

```diff
-build_log="$LOG_DIR/00-build.log"
-echo "Building the project before running tests... (log: $build_log)"
-if ! ./build.sh 2>&1 | tee "$build_log"; then
-    fail_with "Build" "$build_log"
-fi
+if [ "$BUILD" = true ]; then
+    build_log="$LOG_DIR/00-build.log"
+    echo "Building the project before running tests... (log: $build_log)"
+    if ! ./build.sh 2>&1 | tee "$build_log"; then
+        fail_with "Build" "$build_log"
+    fi
+fi
```

**Guard required.** `start_server_and_wait` execs `./tmp/goiabada-authserver`, so `--no-build` combined with `--type integration` fails obscurely if no prior build exists. Add an explicit precondition:

```bash
if [ "$BUILD" = false ] && should_run_integration && [ ! -x ./tmp/goiabada-authserver ]; then
    echo "--no-build requires a prior build: ./tmp/goiabada-authserver not found"
    exit 2
fi
```

#### 5.5.2 GitHub Actions log grouping

Helpers defined once near the top, no-ops outside CI:

```bash
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    gha_group()    { echo "::group::$1"; }
    gha_endgroup() { echo "::endgroup::"; }
    gha_error()    { echo "::error title=$1::$2"; }
    gha_summary()  { echo "$1" >> "$GITHUB_STEP_SUMMARY"; }
else
    gha_group()    { :; }
    gha_endgroup() { :; }
    gha_error()    { :; }
    gha_summary()  { :; }
fi
```

Wrapped around each phase in `run_tests` and the three module-test blocks, so a step's log becomes navigable sections instead of one continuous wall of `PASS` lines.

#### 5.5.3 Failure annotations

`fail_with` already parses failures out of the log (`--- FAIL:` lines, panics, final package status). It gains a loop emitting one `::error::` per failed test, which puts every failure in the **annotation list at the top of the job page**, readable without opening the log at all.

```bash
while IFS= read -r t; do
    gha_error "$t" "see $label log"
done < <(grep -oE '^(    )*--- FAIL: [^ ]+' "$log" | sed 's/.*--- FAIL: //')
```

**Correcting something I overstated earlier:** I previously said this would annotate failures **inline on the PR diff**. That requires `file=` and `line=` on the annotation, and Go prints only a basename (`handler_auth_otp_test.go:118`), which has to be resolved to a repo-relative path to be usable. That resolution is ambiguous whenever a basename is not unique across modules. So the reliable win is the job-level annotation list; inline diff annotation is a best-effort extra, applied only where a basename resolves to exactly one tracked file.

#### 5.5.4 Step summary

Each invocation appends a row to `$GITHUB_STEP_SUMMARY` recording tier, database, result and duration.

**Scope, stated precisely:** GitHub scopes step summaries **per job**, not per run. So `Tests / postgres` gets its own two-row table (data, integration) on its job page. There is no single cross-database table unless a final aggregation job collects the four results and writes one. That aggregation is worth doing later if you want it, and is deliberately out of scope for v1.

```
| Tier        | DB       | Result | Duration |
|-------------|----------|--------|----------|
| Data        | postgres | pass   | 48s      |
| Integration | postgres | FAIL   | 47s      |
```

#### 5.5.5 `print_help` line range

`print_help` is `sed -n '2,46p' "$0"`, a hardcoded range into the script's own header comment. Documenting `--no-build` in that header shifts every line below it and silently truncates or over-runs the help output. Either update the range in the same commit, or make it robust:

```diff
-print_help() { sed -n '2,46p' "$0"; }
+print_help() { sed -n '2,/^# ===*$/p' "$0" | sed '$d'; }
```

Flagged because it is exactly the kind of coupling that breaks without failing.

#### 5.5.6 Considered and rejected

**`--no-cleanup-ports`.** `kill_processes_on_ports` guards against a stale local server on 19090, which cannot happen in a fresh CI container. Skipping it would remove the `net-tools` dependency and a few seconds per invocation. Not worth a new flag and a new code path for that; `net-tools` installs in about a second.

#### 5.5.7 Explicitly not changed

`configure_database` stays byte-for-byte as it is. Constraint B established that CI service containers can present the same hostnames and ports as the devcontainer, so the hardcoded `mysql-server:13306`, `postgres-server:15432` and `mssql-server:11433` are correct in both environments. This is the single most important reason CI can reuse this script rather than reimplementing it in YAML.

### 5.6 Build script changes

#### 5.6.1 Option parsing, not `$1`

An earlier draft of this section proposed `VERSION="${1:-${GOIABADA_VERSION:-dev}}"`. **That is broken**, because `build-docker-images.sh` already reserves `$1`:

```bash
PUSH=false
if [[ "${1:-}" == "--push" ]]; then
    PUSH=true
fi
```

The two readings of `$1` collide in every direction:

| Invocation | Result under the broken proposal |
|---|---|
| `build-docker-images.sh 1.6.0 --push` | `VERSION=1.6.0`, `PUSH=false`. Builds, **does not push**, job goes green |
| `build-docker-images.sh --push 1.6.0` | `VERSION=--push`, `PUSH=true`. Pushes images tagged `authserver---push` |
| `GOIABADA_VERSION=1.6.0 ... --push` | `$1` wins, so the env var is ignored entirely |

The second row is the worst case: `--push` is a legal Docker tag substring, so this succeeds and publishes garbage tags to both registries.

**Fix:** proper long-option parsing in all three scripts, with the environment variable as fallback:

```bash
VERSION="${GOIABADA_VERSION:-dev}"
PUSH=false
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --push)    PUSH=true; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
```

Callers become `build-docker-images.sh --version 1.6.0 --push`. The `*)` arm matters: it turns a future typo into a failure instead of a silently ignored argument.

#### 5.6.2 GHCR tagging

Section 5.2 claims images publish to Docker Hub **and** GHCR, but the script hardcodes a single registry prefix in six places (`-t leodip/goiabada:...`). The dual-registry claim was never actually specified. It needs a registry list:

The registry list must be **configurable with a Docker Hub only default**, not hardcoded to both:

```bash
# space-separated; defaults to Docker Hub alone so the script stays usable
# by anything that is not authenticated to GHCR
IFS=' ' read -r -a REGISTRIES <<< "${GOIABADA_REGISTRIES:-leodip/goiabada}"

TAGS=()
for reg in "${REGISTRIES[@]}"; do
    TAGS+=(-t "$reg:authserver-$VERSION")
done
docker buildx build --platform "$PLATFORMS" "${TAGS[@]}" ...
```

`release.yml` sets `GOIABADA_REGISTRIES="leodip/goiabada ghcr.io/leodip/goiabada"`.

One `buildx build` invocation pushes to every listed registry in a single pass, so this costs no extra build time, only a second `docker/login-action` step for GHCR (using `GITHUB_TOKEN`, no new secret).

**Why the default matters.** An earlier draft had the script always tag both registries. That silently breaks the *retained* legacy workflow, which logs into Docker Hub only: dispatching it after stage 4 would fail at the GHCR push. The env-var default keeps that workflow working unchanged.

It does **not** make the legacy path fully equivalent, and stage 5's rollback note says so: stage 4 also moves the version to an argument, so a dispatched legacy workflow now produces `dev`-versioned artifacts. Registries are fixed here; versioning is not, and a real rollback from stage 5 must revert stage 4 too.

The `latest` tags are **not** generated here at all; they move in `publish.yml` (4.6).

#### 5.6.3 The binary scripts must fail on failure

Neither binary script sets `-e`:

- `src/build/build-binaries.sh` starts `#!/bin/bash` then `VERSION="1.5.2"`
- `src/cmd/goiabada-setup/build-binaries.sh` likewise

`build_platform` runs `cd`, `go build` and `zip` with no status checks, the loop continues across all five platforms regardless, and both scripts end on an `echo` (and an `ls`). **So a failed cross-compile exits 0 with a cheerful success message**, and `upload-artifact` then uploads whatever happens to be on disk, including stale zips from a previous run.

This one matters more than it looks: today it means a broken `darwin/arm64` build can produce a release whose macOS asset is missing or is the previous version's binary, with every job green.

Required in both scripts:

```bash
set -euo pipefail
```

Plus four things `set -e` alone does not give you:

1. **Clean the output directory first**, so nothing stale can survive into the upload:
   ```bash
   rm -f "$BUILD_DIR"/goiabada-*.zip "$BUILD_DIR"/goiabada-setup-*
   ```
2. **An explicit manifest of the expected artifacts**, checked before checksums are generated:
   ```bash
   EXPECTED=(
     "goiabada-${VERSION}-linux-amd64.zip"   "goiabada-${VERSION}-linux-arm64.zip"
     "goiabada-${VERSION}-darwin-amd64.zip"  "goiabada-${VERSION}-darwin-arm64.zip"
     "goiabada-${VERSION}-windows-amd64.zip"
   )
   for f in "${EXPECTED[@]}"; do
       [ -s "$f" ] || { echo "missing or empty artifact: $f" >&2; exit 1; }
   done
   ```
3. **`if-no-files-found: error`** on every `actions/upload-artifact` step. The default is `warn`, which is how an empty upload reaches a green job.
4. **Checksums generated only after the manifest check passes**, so `checksums.txt` can never describe a partial set.

`set -euo pipefail` interacts with one existing pattern worth checking during implementation: `build-docker-images.sh` already sets it and works, but the binary scripts use `$?` checks and `cd` sequences that assume continuation. Each needs a read-through rather than a blind one-line addition.

#### 5.6.4 Setup script and `main.go`

`src/cmd/goiabada-setup/build-binaries.sh` takes the same option parsing, and gains the `ldflags` injection the other two already have:

```diff
 GOOS=$os GOARCH=$arch go build -v \
-    -ldflags "-s -w" \
+    -ldflags "-s -w -X main.version=${VERSION} -X main.imageTag=${VERSION}" \
     -o "./build/goiabada-setup-${os}-${arch}${extension}"
```

`src/cmd/goiabada-setup/main.go`:

```diff
-const version = "1.0.0"
+var version  = "dev"
+var imageTag = "latest"

-sb.WriteString("    image: leodip/goiabada:authserver-1.5.2\n")
+sb.WriteString("    image: leodip/goiabada:authserver-" + imageTag + "\n")
```

Four call sites, at the compose and k8s manifest generators for authserver and adminconsole.

`src/cmd/goiabada-setup/Makefile` drops its `VERSION ?= 1.0.0` default in favor of the same `${GOIABADA_VERSION:-dev}` convention, so a local `make` build is clearly marked `dev`.

`build-docker-images.sh` also loses its `latest` tagging, which moves to `publish.yml`. Its existing prerelease detection (`[[ "$VERSION" == *-* ]]`) is preserved and reinforced at the release level.

### 5.7 `version-manager.sh` and `versions.yaml` changes

**Kept entirely:** `cmd_check`, `cmd_deps`, `cmd_generate`, the online-lookup helpers (`get_github_latest`, `get_go_latest`, `get_npm_latest`), `version_lt`, and the tools/CDN two-thirds of `cmd_update`. That machinery has no replacement and remains the only thing watching for Go, Tailwind, golangci-lint, mockery and CDN updates.

Six changes.

#### 5.7.1 `versions.yaml` loses the `project:` block

```diff
-# -----------------------------------------------------------------------------
-# Project Versions
-# -----------------------------------------------------------------------------
-# goiabada:       Main application version (authserver + adminconsole Docker images)
-# goiabada-setup: CLI setup tool version
-project:
-  goiabada: "1.5.2"
-  goiabada-setup: "1.0.0"
```

`tools:` and `cdn:` are untouched. The header comment changes from "single source of truth for all version numbers" to state that it owns toolchain and CDN pins, and that the product version comes from the git tag.

#### 5.7.2 `cmd_update` drops three sections

Removed from the top of the function:

```diff
-    local GOIABADA_VERSION=$(get_version 'project.goiabada')
-    local SETUP_VERSION=$(get_version 'project.goiabada-setup')
```

Then three blocks go away entirely, all superseded by `ldflags` (4.1):

| Block | What it wrote | Replaced by |
|---|---|---|
| `Build Scripts` loop | `VERSION="x.y.z"` into `build-binaries.sh` and `build-docker-images.sh` | `$1` / `$GOIABADA_VERSION` from the tag |
| `Goiabada Setup Tool`, version writes | setup `Makefile` `VERSION ?=`, `const version` in `main.go`, setup `build-binaries.sh` `VERSION=` | `-X main.version` |
| `Goiabada Setup Tool`, image writes | the four `leodip/goiabada:{authserver,adminconsole}-x.y.z` strings in `main.go` | `-X main.imageTag` |

Everything else in `cmd_update` (devcontainer Dockerfile, production Dockerfiles, `Dockerfile-test`, the four `go.mod` files, the HTML template CDN pins) stays exactly as-is.

#### 5.7.3 CI reads `versions.yaml` at runtime, so nothing is copied into workflows

`version-manager.sh` **does not touch the workflow files at all.** Its existing two `go-version:` writes (into files this design deletes) are simply removed, not repointed.

Instead, `check.yml` and `release.yml` read the values when they run:

```yaml
jobs:
  Versions:                                   # one small job, a few seconds
    runs-on: ubuntu-latest
    outputs:
      go:          ${{ steps.read.outputs.go }}
      golangci:    ${{ steps.read.outputs.golangci }}
      tailwind:    ${{ steps.read.outputs.tailwind }}
      staticcheck: ${{ steps.read.outputs.staticcheck }}
      unparam:     ${{ steps.read.outputs.unparam }}
      govulncheck: ${{ steps.read.outputs.govulncheck }}
    steps:
      - uses: actions/checkout@<sha>
      - id: read
        run: |
          f=src/authserver/versions.yaml
          for k in go tailwind staticcheck unparam govulncheck; do
            echo "$k=$(yq -r .tools.$k $f)" >> "$GITHUB_OUTPUT"
          done
          echo "golangci=$(yq -r '.tools."golangci-lint"' $f)" >> "$GITHUB_OUTPUT"

  Lint:
    needs: Versions
    steps:
      - uses: actions/setup-go@<sha>
        with: { go-version: "${{ needs.Versions.outputs.go }}" }
      - run: |                                # pinned, per stage 0
          go install honnef.co/go/tools/cmd/staticcheck@v${{ needs.Versions.outputs.staticcheck }}
          go install mvdan.cc/unparam@v${{ needs.Versions.outputs.unparam }}

  Tests / postgres:
    needs: Versions
    container: golang:${{ needs.Versions.outputs.go }}-bookworm
```

**All six blocking tools come from here.** Stage 0 pins `staticcheck`, `unparam` and `govulncheck` in `versions.yaml`, so CI must install those pinned versions rather than `@latest`, otherwise the pinning achieves nothing on the side that actually gates PRs. An earlier draft of this section listed only three outputs and left the other three unspecified.

**`release.yml` carries the same job.** Its `Binaries` job needs Go, and a reusable `Checks` call cannot hand values to sibling jobs. The six lines are duplicated rather than shared, which is simpler than inventing a mechanism to share them.

**`Versions` must be a required status check** (7). It is not optional: every test job depends on it, and **GitHub counts a skipped job as successful for required checks**. So if `Versions` failed and were not itself required, all four `Tests /` checks would be skipped, counted as passing, and the PR would be mergeable with nothing having run. Adding it to the required list is the whole fix.

**Confirmed against GitHub's context reference:** the `needs` context is available for both `jobs.<job_id>.container.image` and `jobs.<job_id>.services`, so container-based jobs can consume the value too.

`yq` is preinstalled on GitHub-hosted Ubuntu runners. If that ever changes, `versions.yaml` is flat enough that a one-line `sed` substitutes fine.

**Why this replaces the earlier design.** Revision 3 had `version-manager.sh` `sed` the versions into the workflows, which meant the number existed in two places and had to be kept in sync. Keeping a `sed`-maintained copy honest required counting occurrences per file, an inventory check for unmapped files, a `verify` subcommand, and load-bearing marker comments. All of that was scaffolding around a copy that does not need to exist.

Reading the file at runtime makes drift **impossible** rather than **detectable**, and deletes every piece of that scaffolding. The cost is one small job that the others depend on.

For the record, the discarded machinery was: `PIN_PATTERNS`, `WORKFLOW_PINS` with per-file occurrence counts, `inventory_check`, the `verify` subcommand and its `Lint` step, and a second Go pattern for `container:` image tags. None of it is needed now.

**What `cmd_update` still does, unchanged:** the devcontainer Dockerfile, the production Dockerfiles, `Dockerfile-test`, the four `go.mod` files, and the HTML CDN pins. Those are built or compiled rather than interpreted at run time, so they genuinely need the value written in.

#### 5.7.4 No new verifier: CI runs `update` and checks the diff

The remaining risk is that someone edits `versions.yaml` and forgets to run `update`, leaving the Dockerfiles, the four `go.mod` files and the template pins stale while CI (reading `versions.yaml` at run time) uses the new value.

Revision 4 proposed a `verify_versions` function asserting each expected literal is present. **That is deleted, unimplemented**, for two reasons. It had the same partial-drift hole it was meant to close: `grep -qF` only asks whether a literal appears *somewhere*, and the devcontainer Dockerfile contains `go1.26.5.linux-amd64.tar.gz` **three times** (`wget`, `tar`, `rm` on lines 41 to 43), so two stale copies and one correct one would pass. Fixing that properly means occurrence counts, which is the machinery revision 4 set out to remove.

**One CI step does the whole job with no script code at all:**

```yaml
# in check.yml's Lint job
- name: versions.yaml is applied
  run: |
    cd src/authserver && ./version-manager.sh update
    git diff --exit-code || {
      echo "::error::versions.yaml changed but ./version-manager.sh update was not run"
      exit 1
    }
```

`update` is pure `sed` and deterministic, and the CI checkout is disposable, so running it and requiring a clean diff is safe. Any stale target anywhere, in any number of occurrences, produces a diff and fails the PR. It is strictly stronger than the deleted function and costs six lines of YAML instead of twenty lines of shell.

**Residual gap, stated honestly:** if a sed pattern goes stale because the *surrounding syntax* changed (someone rewrites the Go download to a different URL form), `update` writes nothing, the diff is clean, and the check passes while an unmanaged version string sits in the file. That is a narrower failure than the one being fixed, it requires someone to restructure a Dockerfile line, and catching it needs the occurrence counting already rejected as disproportionate. Accepted.

Net effect on `version-manager.sh`: it gains nothing. It only loses the product-version writes (5.7.2) and the workflow writes (5.7.3).

#### 5.7.5 `cmd_show` reports the product version from git

The `Project:` section currently reads `versions.yaml`. It should read the tag, so `show` remains the one place that answers "what versions is this project on":

```diff
-    echo -e "\n${BOLD}Project:${NC}"
-    printf "  %-23s ${GREEN}%s${NC}\n" "goiabada" "$(get_version 'project.goiabada')"
-    printf "  %-23s ${GREEN}%s${NC}\n" "goiabada-setup" "$(get_version 'project.goiabada-setup')"
+    echo -e "\n${BOLD}Product (from git tags, not this file):${NC}"
+    printf "  %-23s ${GREEN}%s${NC}\n" "latest tag" "$(git describe --tags --abbrev=0 2>/dev/null || echo 'none')"
+    printf "  %-23s ${GREEN}%s${NC}\n" "working tree" "$(git describe --tags --dirty 2>/dev/null || echo 'unknown')"
```

`get_all_versions` drops its two `project.*` fallback lines and the `.project | to_entries` clause of its `yq` expression.

#### 5.7.6 Header and help text

The header comment's `Workflow:` block and `show_help` both describe editing `versions.yaml` to set versions. They should state that this covers tools and CDN pins only, and that releasing is `git tag vX.Y.Z && git push origin vX.Y.Z`. Cheap, and it is the first thing anyone reads when they come back to this in six months.

### 5.8 `.golangci.yml`

New, at the repository root. **`default: none` is required**, and an earlier draft of this section omitted it:

```yaml
version: "2"
linters:
  default: none          # without this, `enable` only ADDS to the standard set
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
```

**Verified empirically** with golangci-lint 2.12.2 in the devcontainer, on a throwaway module containing one unused private function:

| Config | Result |
|---|---|
| `linters: { enable: [errcheck] }` | **1 issue: `func unusedHelper is unused (unused)`** |
| `linters: { default: none, enable: [errcheck] }` | 0 issues |

`enable` augments `linters.default`, which is `standard` when unset. So the earlier config pinned nothing at all: it listed five linters that `standard` already includes, and left the gate free to widen whenever upstream changes what `standard` means. That is the precise failure mode section 4.4 claims to prevent, so the config has to actually do it.

#### The two staticchecks do not run the same checks, and `make check` runs both

1.4 D's table shows `staticcheck` at 0 and `golangci-lint` at 80 for the setup module. **That is a difference in what the two tools contain, not a contradiction and not a bug.**

Verified at `8b69223` with the pinned versions:

| | `staticcheck` v0.7.0 standalone | `staticcheck` inside golangci-lint 2.12.2 |
|---|---|---|
| Check families available | `S1`, `SA*`, `ST1`, `U1` — 149 checks | those, **plus the `QF` quickfix family** |
| `QF1012` reported on `cmd/goiabada-setup` | 0 | 75 |

The standalone binary does not merely leave `QF` off by default — **it does not contain those checks at all.** `staticcheck -list-checks` emits no `QF` entry, and both `-checks=QF1012` and `-checks='QF*'` match nothing and report 0. The `quickfix` analyzer group ships inside `honnef.co/go/tools` but is not registered by `cmd/staticcheck`; golangci-lint's integration registers it. No flag on the standalone binary can reach those checks.

(In the other direction, for completeness: `staticcheck -checks=all` on the setup module surfaces 1 `ST1021` that neither tool reports by default, because staticcheck's own default config excludes several `ST1*` checks. Nothing in the blocking set depends on it.)

**This needed a decision, because `make check` ran both tools and they disagree. Resolved in stage 0: `.golangci.yml` is the single definition of "lint-clean", and the standalone `staticcheck` is dropped from `make check`.**

The two candidates were:

- **Make `.golangci.yml` the single definition of "lint-clean"** and drop the standalone `staticcheck` from `make check`. ***Taken.*** The simplification note below already suggested this on redundancy grounds; the check-set divergence is a stronger reason, since keeping both means the answer to "is this clean?" depends on which binary ran.
- **Keep both**, and accept that golangci-lint is strictly the wider gate. In that case the 75 `QF` findings are unambiguously in scope, and 4.4's option B is off the table.

Since 4.4 chose option A, `QF*` stays enabled and golangci-lint is the wider gate regardless, which makes the standalone run pure redundancy rather than a second opinion. `make check` in `src/authserver`, `src/core` and `src/adminconsole` therefore lost its `staticcheck ./...` line.

**A related gap found while doing it:** `src/cmd/goiabada-setup` had no `check` target at all, which is plausibly why 80 of the 81 findings accumulated in that one module without anyone noticing. It now has one, matching the other three.

#### Standalone tool versions must be pinned too

`.golangci.yml` pins which linters run. `versions.yaml` pins the golangci-lint *binary* (`tools.golangci-lint`, currently `2.12.2`) and mockery. But the devcontainer installs the other two blocking tools **unpinned**:

```dockerfile
go install -v honnef.co/go/tools/cmd/staticcheck@latest   # line 55
go install -v mvdan.cc/unparam@latest                     # line 58
```

With lint blocking PRs, an upstream `staticcheck` release can turn every open PR red with no change on your side, and CI and the devcontainer can disagree about what "clean" means depending on when each image was built. `govulncheck` has the same exposure and is not in `versions.yaml` at all.

**Fix:** add `staticcheck`, `unparam` and `govulncheck` to `versions.yaml` under `tools:`, pin the devcontainer installs to those values, have `cmd_update` write them, and let `cmd_check` watch for upstream releases. That puts all four blocking tools under one deliberate bump. **Done in stage 0.**

Worth considering as a simplification: `staticcheck` is already bundled inside golangci-lint, so the standalone install is largely redundant. Dropping it would leave `unparam` and `govulncheck` as the only extra pins. **Not taken for the devcontainer**: `staticcheck` stays installed there because it is useful interactively and its editor integration is independent of golangci-lint. It is only `make check` that stopped invoking it.

#### `cmd_check` cannot use GitHub releases for these three

Found while implementing stage 0, and worth recording because it is not obvious. The existing `get_github_latest` helper compares `versions.yaml` against a repository's `releases/latest` tag. **For two of the three new pins that comparison is meaningless**, because the GitHub release tag and the Go module version are different numbering schemes:

| Tool | `releases/latest` tag | Go module version | A GitHub-based watcher would |
|---|---|---|---|
| `staticcheck` (`dominikh/go-tools`) | `2026.1` | `v0.7.0` | report an update **on every run**, forever |
| `govulncheck` (`golang/vuln`) | `v1.1.4` | `v1.6.0` | **never** report an update, being 5 minors behind |
| `unparam` (`mvdan/unparam`) | none — no releases at all | pseudo-version | find nothing to compare |

So `version-manager.sh` gains a second lookup helper, `get_goproxy_latest`, which queries `https://proxy.golang.org/<module>/@latest`. That is authoritative for what `go install` will actually fetch, which is precisely what is being pinned. `version_lt` needs no change: it sorts with `sort -V`, which orders timestamped pseudo-versions correctly.

`unparam` publishes no tags, so its pin is a pseudo-version and **any upstream commit shows as an available update**. That is the only signal the module offers, and it is noise worth accepting rather than leaving the tool unpinned. `versions.yaml` says so at the point of definition.

### 5.9 `.github/dependabot.yml`

Weekly, for `github-actions` and for `gomod` in each of `src/core`, `src/authserver`, `src/adminconsole`, `src/cmd/goiabada-setup`.

Deliberately **not** covering the Go toolchain version, the Tailwind CLI, mockery or the CDN pins. Those remain `version-manager.sh check` territory, since Dependabot cannot see them (they are shell downloads, Dockerfile pins and script tags in HTML, not package manifests). The two tools are complementary, not overlapping.

---

## 6. Files

**Added**

```
.github/workflows/check.yml
.github/workflows/release.yml
.github/workflows/publish.yml
.github/workflows/docs.yml
.github/dependabot.yml
.golangci.yml
```

**Removed**

```
.github/workflows/run-tests.yml
.github/workflows/build-binaries.yml
.github/workflows/build-setup-binaries.yml
.github/workflows/build-and-push-docker-images.yml
.github/workflows/publish-documentation.yml
```

**Modified**

```
src/authserver/run-tests.sh                    --no-build, GitHub Actions output
src/authserver/versions.yaml                   project: block removed;
                                               staticcheck/unparam/govulncheck pins added
src/authserver/version-manager.sh              product-version writes removed,
                                               workflow writes removed entirely
                                               (CI reads versions.yaml at run time),
                                               get_goproxy_latest added for the 3 new pins
src/.devcontainer/Dockerfile                   staticcheck + unparam pinned,
                                               govulncheck install added
src/authserver/Makefile                        redundant staticcheck dropped from check
src/core/Makefile                              redundant staticcheck dropped from check
src/adminconsole/Makefile                      redundant staticcheck dropped from check
src/cmd/goiabada-setup/Makefile                check target added (had none)
src/build/build-binaries.sh                    VERSION from argument
src/build/build-docker-images.sh               VERSION from argument, latest tagging removed
src/cmd/goiabada-setup/build-binaries.sh       VERSION from argument, ldflags injection
src/cmd/goiabada-setup/Makefile                VERSION default becomes dev
src/cmd/goiabada-setup/main.go                 version and imageTag become ldflags vars,
                                               4 hardcoded image tags parameterized,
                                               plus 80 lint fixes (stage 0)
src/core/i18n/error_codes.go                   gofmt
src/core/i18n/middleware_test.go               gofmt
src/core/urlutil/redirect_uri.go               one QF1001 fix
```

`src/build/docker-compose-test.yml` and `Dockerfile-test` stay, since they remain the way the suite runs locally.

---

## 7. Prerequisites

**Secrets.** `DOCKER_USERNAME` and `DOCKER_PASSWORD` already exist in the `prod` environment. Worth confirming `DOCKER_PASSWORD` is a scoped Docker Hub **access token** rather than an account password; if it is the password, this is a good moment to rotate it to a token with push-only scope. GHCR needs no new secret.

**Branch protection.** Not settable from here, it is a repository setting. The check names to require on PRs to `main`:

```
Versions
Lint
Vulnerabilities
Unit / core
Unit / authserver
Unit / adminconsole
Tests / sqlite
Tests / mysql
Tests / postgres
Tests / mssql
```

These are four separately declared jobs, not matrix legs (5.1), so each name is written literally in the workflow and is stable by construction. Renaming a job silently un-requires its check, since branch protection matches on name, so the names and this list must change together.

**One entry in that list is still contingent.** `Lint` was contingent on 4.4's open question; that is now discharged — 4.4 chose option A, stage 0 cleared the backlog to 0, and `Lint` can be required as soon as `check.yml` exists. `Vulnerabilities` **cannot** be required while `GO-2025-3884` is reachable and unfixed (1.4 D, issue #155); requiring it would block every PR on day one. Add it to the required list only once #155 is resolved.

---

## 8. Risks and open questions

| Risk | Assessment |
|---|---|
| Service definitions duplicate `docker-compose-test.yml` | Real and accepted, per 4.3. A drift here shows up as a CI-only failure. Mitigation: a comment in both files pointing at the other. |
| MSSQL memory on GitHub runners | Public-repo runners provide 16 GB, and MSSQL Express needs about 2 GB, so there is ample headroom. Worth noting because the known local failure mode is memory exhaustion of the MSSQL pool under repeated migration tests. Each CI run starts a fresh container, so the accumulation that causes it locally does not occur. |
| Tailwind CLI download in every test job | Adds a few seconds and an external dependency on a GitHub release URL. Mitigated with `actions/cache`. Could be removed entirely later by publishing a prebuilt CI image to GHCR. |
| First release under the new scheme | The version now comes from the tag rather than the scripts. The first tag must be verified end to end before the draft is published. **Note that `/health` cannot be used for this**: `HandleHealthCheckGet` returns the literal string `healthy` and nothing else. See 9, stage 5, for the two mechanisms that do expose the version. |
| `unparam` is slow | It re-typechecks whole packages. Measured clean on all four modules, so it stays, but it is the first candidate to drop from the blocking set if `Lint` becomes a bottleneck. |

Two further risks specific to the `versions.yaml` split:

| Risk | Assessment |
|---|---|
| The setup wizard's generated manifests are now only correct if `ldflags` are passed | A `go build` without them yields `latest`, which is a safe and sensible default for a source build, not a broken one. The release path always passes them. Worth one integration check: after the first tagged build, run `goiabada-setup` and confirm the emitted compose file pins the release version rather than `latest`. |
| A `sed` pattern that silently matches nothing | The existing failure mode of this script: `update_file` reports success as long as `sed` exits 0, whether or not it changed anything. `version-manager.sh` no longer writes to workflows at all (5.7.3), so CI's toolchain no longer depends on these writes. The remaining exposure is the Dockerfiles, `go.mod` files and template pins, covered by a single CI step that runs `update` and requires a clean `git diff` (5.7.4). Residual gap, accepted: a pattern whose surrounding syntax changed entirely. |

**Resolved open question.** Whether `goiabada-setup` should carry its own version: decided in 4.1a. It adopts the product version and `project.goiabada-setup` is dropped. Reversible.

---

## 9. Implementation plan

Nine stages, each a self-contained PR that leaves `main` releasable. The ordering is driven by three real dependencies: lint fixes must land before the lint gate, the new check workflow must be proven green before the old one is deleted, and `version-manager.sh` cannot target the new workflows until they exist.

Throughout stages 1 to 3, the existing `run-tests.yml` keeps gating every PR. Nothing is deleted until its replacement has demonstrated it works.

---

### Stage 0. Lint backlog, `.golangci.yml`, and tool pins

> **Implemented.** 4.4 resolved to **option A**, and this stage has been carried out on branch `ci-v2-stage-0-lint-baseline` against `8b69223`. All four modules now pass `gofmt`, `go vet`, `staticcheck`, `unparam -exported` and uncapped `golangci-lint`: **the backlog is 0**. Two of this section's assumptions proved wrong in practice and are corrected in place below, marked **Correction**.

**This stage's scope depended on a question 4.4 left open.** It was written against a backlog of 11 findings. The real backlog is 81 golangci-lint findings plus 2 unformatted files (1.4 D), and 4.4 offered three responses: **A** fix everything, **B** narrow the linter set, **C** start advisory and promote later. The changes below are written for **option A**, the largest of the three, which is the one taken. **The `.golangci.yml` and the tool pins belong here in all three cases**, and are the reason this stage exists at all.

**Changes (as scoped for option A)**

- `gofmt -w src/core/i18n/error_codes.go src/core/i18n/middleware_test.go` — 2 files
- `src/core/urlutil/redirect_uri.go:156`: apply the `QF1001` De Morgan rewrite in the host-suffix check — 1 finding
- `src/cmd/goiabada-setup/main.go`: **80 findings**, not 8 — 2 `errcheck` (`rl.Close` at 158, `db.Close` at 1404), 3 `QF1001` De Morgan (1188, 1250, 1274), and **75 `QF1012`** `WriteString(fmt.Sprintf(...))` → `fmt.Fprintf`, running from 1513 to 2084
- Add `.golangci.yml` at the repository root, **with `default: none`** (5.8). Confirmed that a config at the repository root is discovered from all four module directories, so one file governs every module
- Drop the now-redundant `staticcheck ./...` from `make check`, and give `src/cmd/goiabada-setup` the `check` target it never had (5.8)
- **Pin the blocking tools here, not in stage 8.** Add `staticcheck`, `unparam` and `govulncheck` to `versions.yaml` under `tools:`, and change the devcontainer's `@latest` installs (`src/.devcontainer/Dockerfile` lines 55 and 58) to those pinned values. **`govulncheck` is not installed in the devcontainer at all today**, so it needs a new install line rather than a pin of an existing one

Versions confirmed available on the module proxy and matching what the devcontainer currently resolves:

| Tool | Pin | Devcontainer today |
|---|---|---|
| `golangci-lint` | `v2.12.2` | already pinned, line 59 |
| `staticcheck` | `v0.7.0` | `@latest`, line 55 |
| `unparam` | `v0.0.0-20251027182757-5beb8c8f8f15` | `@latest`, line 58 |
| `govulncheck` | `v1.6.0` | **not installed**, so a new install line rather than a pin |

**The pinning was not theoretical.** On the day stage 0 landed, `mvdan.cc/unparam@latest` resolved to `v0.0.0-20260808223834-a64391f2ca86` — a build published that same day — while the running devcontainer still carried `v0.0.0-20251027182757-5beb8c8f8f15` from October. Two developers rebuilding their image a day apart would have been running different analyzers against the same gate. That is exactly the failure this pin exists to prevent, observed in the act.

`cmd_check` needed a new lookup helper to watch these three; see 5.8 for why GitHub releases cannot be used for them.

**Effort, corrected.** This stage is no longer "a one-commit cleanup". The three `core` items are minutes. The setup module is 80 fixes in one ~2100-line file, of which 75 are the same rewrite. Budget a working session, not a minute. Because that file generates the docker-compose and k8s manifests handed to users, diff the generated manifest output before and after and confirm the rewrite changed no bytes; `fmt.Fprintf` to a `strings.Builder` is byte-identical to `WriteString(fmt.Sprintf(...))`, but that is a property worth demonstrating once rather than assuming across 75 sites.

> **Correction 1: `golangci-lint run --fix` could not apply these fixes as claimed.** This section, and 4.4's option A, both asserted that `--fix` handles `QF1001` and `QF1012` mechanically. Run against `cmd/goiabada-setup`, it modified **nothing at all**. staticcheck offers *two different* rewrites for the same `QF1001` span (`!(c >= 'a' && c <= 'z') && …` and `(c < 'a' || c > 'z') && …`), golangci-lint detects the overlap as `conflicting edits from staticcheck and staticcheck`, and its response is to discard **every** staticcheck edit in that file — all 75 unrelated `QF1012` fixes included. It reports this as a `level=warning` line and still exits 0 on the fix pass, so it is easy to miss.
>
> **The order therefore matters:** resolve the `QF1001` sites by hand *first*, then `--fix` applies the 75 `QF1012` rewrites cleanly. Anyone re-running this stage from scratch should expect that sequence rather than a single mechanical pass.

> **Correction 2: the `QF1001` sites in the setup module were not given the De Morgan rewrite.** All three are character-class validators (`validateHostname`, `validateNamespace`, `validateDatabaseName`), where both mechanical forms staticcheck offers are materially harder to read than the original `!(is-valid)`. They were instead given two small predicates, `isASCIIAlphaNum` and `isASCIILowerAlphaNum`, leaving call sites like `if !isASCIIAlphaNum(c) && c != '_' {`. Same lint outcome, clearer result, and no `!(… || …)` for `QF1001` to flag. The single `core` site in `redirect_uri.go` *did* take the plain De Morgan rewrite, which reads fine there.

**How the byte-identical claim was actually demonstrated**, since asserting it is not the same as showing it: a throwaway test in package `main` called all six generator functions (`generateDockerCompose`, `generateDBService`, `generateAuthServerService`, `generateAdminConsoleService`, `generateEnvFile`, `generateKubernetesManifests`) across all 16 deployment-type × database combinations, dumping 262,236 bytes of output before and after the rewrite. Identical SHA256. A second throwaway test compared each rewritten validator condition against its original over every rune from 0 to 0x10FFFF, with no mismatch. Both harnesses were deleted before committing; they are worth recreating rather than trusting this paragraph if the file is ever rewritten again.

**Watch for one non-obvious side effect:** `src/cmd/goiabada-setup/goiabada-setup` is an 11 MB binary **committed to the repository**, and `go build ./...` inside that directory silently overwrites it. It must be restored (`git checkout --`) before committing, or the stage 0 diff carries an unrelated binary blob. Worth a `.gitignore` entry independently of this design.

**Not in this stage, and unresolved.** `govulncheck` is in 4.4's blocking set but is **not clean today**: `GO-2025-3884` (`gorilla/csrf@v1.7.3`) is reachable from `core`, `authserver` and `adminconsole` and has no fixed version (1.4 D). Pinning it here is still correct, but **stage 2 cannot turn it on as a blocking gate** until issue #155 is resolved. The verification block below pins and installs it without asserting it passes.

**Why the pins moved forward.** An earlier version of this plan deferred them to stage 8, which was wrong: lint becomes a **blocking** gate in stages 2 and 3, so stages 2 through 7 would have run a gate whose definition of "clean" could change under them on any upstream release. And because stage 8 is described as optional and slippable, the pins could have been deferred indefinitely, reproducing the exact problem they exist to fix. A blocking gate must be deterministic from the moment it starts blocking, which means before stage 2, which means here.

**Verify**

```bash
rc=0
for m in core authserver adminconsole cmd/goiabada-setup; do
  ( cd src/$m
    test -z "$(gofmt -l .)" || { echo "$m: gofmt"; exit 1; }
    go vet ./...            || exit 1
    staticcheck ./...       || exit 1
    unparam -exported ./... || exit 1
    golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./... || exit 1
  ) || { echo "FAILED: $m"; rc=1; }
done
exit $rc
```

Four corrections to earlier versions of this block, the first three of which made it report success while failing:

1. It omitted `unparam`, which is in the blocking set.
2. It relied on `gofmt -l .` failing. **`gofmt -l` exits 0 and merely prints filenames**, so the original `&&` chain sailed past unformatted files. `test -z "$(gofmt -l .)"` is what actually fails. The same construction is required in `check.yml`'s `Lint` job.
3. The failure was swallowed by `|| echo "FAILED: $m"`. **`echo` returns 0**, so the subshell's failure was discarded and the loop, and therefore the script, exited 0. Hence the `rc` accumulator and explicit `exit $rc`.
4. It ran `golangci-lint run` with the default issue caps. **This one never affected the exit code** — caps truncate a report but cannot turn a non-empty one into an empty one, so a clean run was always genuinely clean. The flags are here because a truncated *report* is what produced the 11-finding measurement this stage was originally scoped against, and a gate that fails should print everything it found rather than the first three of each kind.

Note that `staticcheck ./...` passing does **not** imply `golangci-lint run` passes: the standalone binary has no `QF` checks (5.8). Both lines stay in this block deliberately even though 5.8 has now resolved in favor of golangci-lint alone — for this one stage, running both is a useful cross-check that the two tools genuinely agree once the backlog is clear. It is `make check` that dropped the standalone binary, not this verification.

**Result:** the block above exits 0 on all four modules.

Existing `run-tests.yml` must stay green. **Not yet run against this branch**: the four-database suite needs the compose service network, and the modules' own test packages for every semantically changed file (`core/urlutil`, `core/i18n`) pass. The setup module has no tests, which is why the two throwaway harnesses described above were written instead.

**Rollback** Trivial for the lint fixes. The tool pins are also trivial but should not be reverted, since stage 2 depends on them.

---

### Stage 1. `run-tests.sh` capabilities

**Changes** All of 5.5: `--no-build` plus its integration guard, the `gha_*` helpers, `fail_with` annotations, step-summary rows, and the `print_help` range fix.

**Verify** Locally, in the devcontainer:

```bash
./run-tests.sh --help                                  # help output intact after the range fix
./run-tests.sh --type core --no-build                  # no Tailwind build runs
./run-tests.sh --type integration --db sqlite --no-build   # guard fires if no prior build
./run-tests.sh                                         # full suite still passes unchanged
```

The `gha_*` helpers must be inert: local output should be byte-identical to before apart from the new flag.

**Rollback** Revert. No workflow depends on it yet.

---

### Stage 2. Add `check.yml` alongside the old workflow

The critical de-risking step. Both workflows run on every PR for a while.

**Changes** Add `.github/workflows/check.yml` per 5.1. Do **not** touch `run-tests.yml`.

**Verify** On this stage's own PR, confirm:

- all nine jobs appear as separate entries in the sidebar
- each `Tests / <db>` job shows `Build`, `Data tests`, `Integration tests` as distinct steps
- the four databases are genuinely reachable at the devcontainer hostnames and ports
- results match `run-tests.yml` running beside it
- record actual per-job timings, to confirm the wall-clock claim in section 3

Leave both workflows in place for at least two more merged PRs.

**Rollback** Delete `check.yml`. `run-tests.yml` never stopped gating.

> **Implemented and measured.** Every criterion above was met on the stage 2 PR. Eleven jobs rather than the nine this list anticipated, because `Versions` and `Build validation` were added by later revisions and never folded into this count.

**Measured on the stage 2 PR, both workflows against the same commit:**

| Job | Result | Duration |
|---|---|---|
| `Tests / mssql` | pass | 236s |
| `Tests / mysql` | pass | 229s |
| `Tests / postgres` | pass | 202s |
| `Tests / sqlite` | pass | 199s |
| `Lint` | pass | 182s |
| `Unit / core` | pass | 93s |
| `Unit / authserver` | pass | 80s |
| `Unit / adminconsole` | pass | 79s |
| `Vulnerabilities` | **fail, tolerated** | 68s |
| `Versions` | pass | 8s |
| `Build validation` | skipped, correctly | — |

| Workflow | Wall clock |
|---|---|
| `run-tests.yml`, one opaque job | **541s** |
| `check.yml`, eleven jobs | **251s** |

541s sits inside the 8.3 to 9.2 minute band recorded in 1.3, so this is a like-for-like comparison rather than a lucky run. **4.2's claim holds exactly**: 251s is the slowest leg (`mssql`, 236s) plus about 15s of scheduling, which is what "wall clock drops to roughly the slowest single leg" predicts. Total runner time rises to roughly 23 minutes across all jobs, which is free on a public repository and is precisely the trade 1.3 identified.

**Four things this stage had to resolve that 5.1 did not specify.**

1. **The container jobs need about 40 `GOIABADA_*` environment variables**, copied as literals from `docker-compose-test.yml`. 5.1 mentions only "session keys, the AES key, admin credentials". Without the full set the auth server starts on its default port while `run-tests.sh` polls 19090, and `GOIABADA_AUTHSERVER_BASEURL` is unbound under `set -u`. Discovered by hitting it. They are declared once at workflow level, because GitHub does not support YAML anchors in workflow files. `GOIABADA_AUTHSERVER_INTERNALBASEURL` becomes `http://localhost:19090`, since the server and the tests share one container rather than living in separate compose services.
2. **The database variables must stay absent** from that block, so `configure_database` remains authoritative (5.5.7).
3. **`Dockerfile-test` fetches the musl Tailwind binary** for alpine; a bookworm container needs `tailwindcss-linux-x64`.
4. **Services are declared only where they are needed**, established by running each tier with every service unreachable rather than by assumption: `core` needs `mailpit` (`TestSendEmail` hardcodes `SMTPHost: "mailpit"`, port 1025), while the `authserver` and `adminconsole` tiers need nothing.

The repeated container setup lives in a local composite action, `.github/actions/setup-test-container`, rather than being duplicated across seven jobs.

**A defect in `run-tests.sh` found while doing point 4, and fixed in the same PR.** The three module tiers ran `go test -v ./...` **without `-count=1`**, unlike the data and integration tiers, which have always had it. Go's test cache keys on source and flags but has no notion of whether a network service is reachable, so with `mailpit` gone the core tier still exits 0 reporting `ok ... (cached)` for all 29 packages: **green having executed nothing**. The container jobs cache `GOCACHE` between runs, so stale passes would have been replayed in CI as well. Verified both ways: exit 0 when cached, exit 1 once caching is defeated.

**Deferred, with reasons.**

- **`Lint` takes 182s, nearly as long as a database leg**, and almost none of it is linting: `golangci-lint` and `unparam` are compiled from source by `go install` on every run, and `actions/setup-go`'s cache covers module downloads rather than built binaries. **Done in stage 8**: the binaries are cached under a key containing their pinned versions, so a bump in `versions.yaml` misses the cache and rebuilds exactly once, and the cache cannot serve a stale linter because the version is part of the key rather than only of the install command.
- **`Vulnerabilities` will show red on every PR** until issue #155 is resolved, which is the failure mode 4.4 warned about under option C: a permanently red check is one nobody reads, and it also masks any *new* advisory. The alternative worth considering is `govulncheck -format json` filtered against a small allowlist naming `GO-2025-3884` with its reason, so the gate goes green now and red the moment a *different* advisory becomes reachable. Not built, because it is a judgment call about how the gate should read rather than something this document specifies.

---

### Stage 3. Retire `run-tests.yml`, set branch protection

**Preconditions** `check.yml` green on at least three PRs, with no result disagreeing with `run-tests.yml`.

**Changes** Delete `.github/workflows/run-tests.yml`.

**Manual step, yours** In repository settings, require these checks on PRs to `main`:

```
Versions
Lint
Vulnerabilities
Unit / core
Unit / authserver
Unit / adminconsole
Tests / sqlite
Tests / mysql
Tests / postgres
Tests / mssql
```

**Rollback** Restore the file from git history.

---

### Stage 4. Version ownership moves to the tag

Everything that changes who owns the product version, landing atomically so no intermediate commit has two owners.

**Changes**

- `src/cmd/goiabada-setup/main.go`: `const version` becomes `var version = "dev"`, add `var imageTag = "latest"`, parameterize the four hardcoded image tags
- `src/cmd/goiabada-setup/build-binaries.sh`: `VERSION` from argument, add `-X main.version` and `-X main.imageTag`
- `src/cmd/goiabada-setup/Makefile`: `VERSION` default becomes `dev`
- `src/build/build-binaries.sh` and `build-docker-images.sh`: `VERSION` from argument; remove `latest` tagging from the latter
- `src/authserver/versions.yaml`: remove the `project:` block
- `version-manager.sh`: 5.7.2 (drop three sections), 5.7.4 (`update_file` no-op detection), 5.7.5 (`cmd_show` reads git), 5.7.6 (header and help text)

**Why these land together:** stage 4 removes `const version` from `main.go`. If `cmd_update` still carried its `const version = "[0-9.]*"` pattern, it would match nothing. Splitting this across two PRs leaves a window where `version-manager.sh update` silently half-works.

**Verify**

```bash
cd src/cmd/goiabada-setup
go build -o /tmp/setup-dev ./main.go
/tmp/setup-dev --version                    # expect: dev
# generate a compose file, confirm it pins :authserver-latest

go build -ldflags "-X main.version=9.9.9 -X main.imageTag=9.9.9" -o /tmp/setup-tag ./main.go
/tmp/setup-tag --version                    # expect: 9.9.9
# generate a compose file, confirm it pins :authserver-9.9.9

cd src/authserver
./version-manager.sh show                   # product version from git, tools from yaml
./version-manager.sh update                 # idempotent: no diff, no "Unchanged" warnings
git diff --exit-code                        # must be clean
```

That last check is the important one: `update` on an unchanged `versions.yaml` must produce zero diff and zero `Unchanged` warnings. Any warning means a sed pattern went stale.

**Release freeze** From here until stage 5 merges, do not dispatch the old build workflows. They would now build with `VERSION=dev`. If a release is genuinely needed in this window, complete stage 5 first.

**Rollback** Revert. Old workflows still exist but would produce `dev`-versioned artifacts, so revert must be complete rather than partial.

---

### Stage 5. Release, publish and docs workflows

**Changes** Add `release.yml`, `publish.yml`, `docs.yml` per 5.2, 5.3 and 5.4. Old build/publish workflows stay for now.

**Verify with a throwaway prerelease.** This is the only way to exercise the release path without shipping anything:

```bash
git tag v1.5.3-rc1 && git push origin v1.5.3-rc1
```

Confirm, in order:

1. `Verify` derives version `1.5.3-rc1` and flags it as a prerelease
2. the full matrix re-runs against the tagged commit
3. five zips, five setup binaries and `checksums.txt` are produced, and `sha256sum -c checksums.txt` passes on a downloaded asset
4. images appear as `authserver-1.5.3-rc1` on both Docker Hub and GHCR
5. **`authserver-latest` has not moved** (`docker buildx imagetools inspect` the digest before and after)
6. a **draft** release exists, marked prerelease, with 11 assets
7. `docker run` the built image and confirm the version it reports is `1.5.3-rc1`, using one of the two mechanisms that actually expose it (see below)
8. extract the setup binary from the release and confirm its generated compose pins `1.5.3-rc1`, not `latest`
9. publish the draft, then confirm `publish.yml` **skipped** the retag because it is a prerelease

**How to check the version in a built image.** `/health` will not tell you. `HandleHealthCheckGet` writes the literal string `healthy` and nothing else. Two mechanisms do expose `core/constants.Version`:

```bash
# 1. Startup logs (main.go logs version, build date and git commit via slog)
docker run --rm leodip/goiabada:authserver-1.5.3-rc1 2>&1 | grep 'goiabada version'

# 2. An HTML comment on any rendered page, emitted by template_funcs.go
curl -s http://localhost:8080/auth/authorize | grep '<!-- version:'
```

The second yields `<!-- version: 1.5.3-rc1; build date: ...; git commit: ...-->`. The bind map also carries `goiabadaVersion` (`http_helper.go`), so it is visible in the admin console footer.

**Not adding the version to `/health`**, but for a weaker reason than an earlier draft claimed. That draft argued it would avoid handing an attacker precise CVE targeting. **That argument does not hold:** `template_funcs.go` already emits `<!-- version: ...; build date: ...; git commit: ...-->` into every rendered page, unauthenticated, and `http_helper.go` exposes `goiabadaVersion` to templates. The version is already public to anyone who views source.

The honest reason to leave `/health` alone is separation of concerns: it is a liveness probe consumed by orchestrators, and probes should stay minimal and cheap to parse. If version disclosure is genuinely a concern, the thing to remove is the HTML comment, which is a product decision outside the scope of this document, and one worth raising separately rather than deciding here.

**Cleanup** Delete the release, delete the tag, delete the `1.5.3-rc1` image tags from both registries.

> **Dry run performed. 8 of 9 checks passed; the ninth is deferred.**

**It found a real defect, which is the point.** The first run failed in `Binaries` with `Error: predicate-type must be provided`: `actions/attest` does not produce provenance, contrary to what finding 22 recorded and 5.2 specified. Corrected to `actions/attest-build-provenance` (see 5.2), and the second run went green end to end. `actionlint` passed on the broken version, and every input used was real — this could only surface at release time.

| # | Check | Result |
|---|---|---|
| 1 | Version derived, prerelease flagged | `version=1.5.3-rc1`, `prerelease=true` |
| 2 | Full matrix re-run against the tagged commit | all 11 jobs, including `Build validation` |
| 3 | `sha256sum -c checksums.txt` on downloaded assets | OK |
| 4 | Images on Docker Hub **and** GHCR | both, digests identical |
| 5 | **`authserver-latest` has not moved** | byte-identical before and after |
| 6 | Draft, marked prerelease, 11 assets | confirmed, setup binaries unversioned |
| 7 | Built image reports the version | `1.5.3-rc1`, commit `b896ead` |
| 8 | **Setup binary's compose pins the version** | `authserver-1.5.3-rc1`, not `latest` |
| 9 | Publishing skips the retag | **deferred**: publishing also fires `docs.yml`, leaving a `docs-1.5.3-rc1` tag that cannot be deleted without registry credentials |

**Check 8 is the one that matters most.** A setup binary downloaded from the actual release, run non-interactively, emitted `image: leodip/goiabada:authserver-1.5.3-rc1`. Before stage 4 that same binary would have handed users manifests pinning the *previous* release. Constraint E's sharp edge, closed and demonstrated with a shipped artifact rather than a test harness.

**Two claims this design declined to verify, confirmed for free.** The Docker Hub and GHCR digests came out identical (`sha256:c1b0f734…` for authserver), which is what 5.2 asserts holds by construction from one `buildx` invocation with two `-t` flags. And the digest read from `--metadata-file` matched the registry exactly, so the attestation had a real subject rather than going green while covering nothing.

**The attestations are usable, not merely created.** `gh attestation verify` exits 0, and the signing certificate binds each artifact to the workflow path, the tag ref, the commit `b896ead796645dfc…`, the run ID, and `environment: prod`. The certificate is valid for ten minutes — long enough to sign, with no key to store or leak, which is what makes 4.10's "no key management" claim real. Later verification still works because Rekor records when the signature was made.

**Cleanup performed:** draft release deleted, tag deleted locally and remotely. The `1.5.3-rc1` image tags in both registries need registry credentials to remove and were left for manual deletion. Attestations were left in place: they remain accurate statements about artifacts that did exist, they assert nothing about current existence, and the Sigstore transparency-log entries are append-only regardless.

**Rollback** Delete the three files. Note this is **not** a complete rollback on its own: stage 4 already made the build scripts take the version as an argument, so the retained legacy workflows now produce `dev`-versioned artifacts. A real rollback from here reverts stage 4 as well. (The registry list is not a problem, since `GOIABADA_REGISTRIES` defaults to Docker Hub alone per 5.6.2.)

---

### Stage 6. Remove `version-manager.sh`'s workflow writes

Small, because the workflows read `versions.yaml` themselves (5.7.3). No map, no counts, no marker comments, and no new verifier.

**Changes**

- Delete the `GitHub Actions Workflows` section of `cmd_update` outright. It targets `build-binaries.yml` and `build-setup-binaries.yml`, both gone by stage 7, and nothing replaces it
- Add the "versions.yaml is applied" step to `check.yml`'s `Lint` job (5.7.4)

**Verify.** Run this on a clean working tree, from the repository root, so the reset at the end cannot discard unrelated work:

```bash
git status --porcelain          # must be empty before starting

( cd src/authserver && ./version-manager.sh update )
git diff --exit-code            # idempotent: exits 0, no changes

# a real bump reaches the sed-managed files and nothing else
yq -i '.tools.go = "1.26.6"' src/authserver/versions.yaml
( cd src/authserver && ./version-manager.sh update )
git diff --name-only            # Dockerfiles + 4 go.mod; NO .github/workflows/
git checkout -- .               # safe: tree was clean at the start
```

An earlier draft ran `git checkout .` from inside `src/authserver`, which both discards unrelated authserver changes and resets only that subtree, leaving generated edits in the devcontainer and build Dockerfiles behind. Hence the clean-tree precondition and the repo-root reset.

**Then confirm the CI guard fires**, since it is the only thing standing between a forgotten `update` and a stale Dockerfile:

```bash
# on a throwaway branch: bump versions.yaml WITHOUT running update
yq -i '.tools.go = "1.26.6"' src/authserver/versions.yaml
git commit -am "probe: bump go without running update" && git push
# expect: Lint fails with "versions.yaml changed but ./version-manager.sh update was not run"
```

**And confirm a bump reaches CI**, this being where the two mechanisms meet: on the same branch, run `update`, push, and check that the `Versions` job output flows into both `setup-go` and the `container:` image tag.

**Rollback** Revert. The workflows keep working either way, since they no longer depend on this script.

---

### Stage 7. Delete the superseded workflows

**Preconditions** Stage 5 verified end to end.

**Changes** Delete `build-binaries.yml`, `build-setup-binaries.yml`, `build-and-push-docker-images.yml`, `publish-documentation.yml`.

**Rollback** Restore from git history.

> **Done.** The precondition was met by the `v1.5.3-rc1` dry run recorded under stage 5, 8 of whose 9 checks passed; only the publish-time check is outstanding, and it does not bear on these four files.

**Worth noting that these were no longer usable fallbacks anyway.** Stage 4 made the build scripts take the version as an argument, so a dispatched `build-binaries.yml` produced `dev`-versioned artifacts, and `build-docker-images.sh` no longer tags `latest` at all. Keeping them past this point would have preserved the *appearance* of a fallback rather than a working one — which is worse than having none, because it is the sort of thing someone reaches for in a hurry.

Five workflows remain, not the four this design targets: `run-tests.yml` is still there until stage 3 retires it.

---

### Stage 8. Dependabot and remaining hardening

**SHA pinning does not live here.** An earlier version of this plan deferred all pinning to stage 8, which was wrong: stage 5 introduces the first workflows that hold Docker Hub credentials, and leaving them on mutable tags like `docker/login-action@v3` for several stages is exactly the window worth closing. **Credential-bearing workflows are SHA-pinned in stage 5, as they are written.** Attestations likewise land in stage 5, since 5.2 requires the buildx `--metadata-file` digest plumbing to exist in the same job that pushes.

That leaves stage 8 with what genuinely can come later:

**Changes**

- SHA-pin the remaining non-credential workflows (`check.yml`) with a trailing `# vX.Y.Z` comment on each
- Add `.github/dependabot.yml` per 5.9, which is also what keeps the stage 5 pins from going stale

The lint-tool pins that an earlier version of this plan put here have **moved to stage 0**, because a blocking gate cannot be allowed to run nondeterministically for five stages while waiting on an optional one.

**Verify** A PR run stays green. `gh attestation verify <asset> --repo leodip/goiabada` succeeds against the stage 5 rc assets, and likewise for `oci://` image references.

---

### Stage 9. First real release

```bash
git tag v1.6.0 && git push origin v1.6.0
```

Run the same nine-point checklist from stage 5, with two differences: `publish.yml` **must** move `latest` this time, and `/releases/latest/download/goiabada-setup-linux-amd64` must resolve to the new asset after publishing. Check the docs links resolve before announcing.

---

### Summary

| Stage | Scope | Gated by | Reversible |
|---|---|---|---|
| 0 | **Done.** 81 lint fixes + 2 `gofmt` files (4.4 option A), `.golangci.yml`, 3 tool pins, `make check` aligned | existing CI | yes |
| 1 | `run-tests.sh` | local runs | yes |
| 2 | **Done.** add `check.yml` (11 jobs), `-count=1` fix | its own PR: 251s vs 541s, all agree | yes |
| 3 | delete `run-tests.yml`, branch protection | 3 green PRs | yes |
| 4 | **Done.** ldflags, `versions.yaml`, `version-manager.sh` | local build checks + release dry run | full revert only |
| 5 | **Done.** `release.yml`, `publish.yml`, `docs.yml`, SHA pins + attestations | `v1.5.3-rc1` dry run: 8/9 | yes |
| 6 | **Done.** remove `version-manager.sh` workflow writes, add the CI drift step | idempotency + guard fires | yes |
| 7 | **Done.** delete 4 old workflows | stage 5 verified | yes |
| 8 | **Done.** Dependabot, SHA pins for `check.yml`, linter binary cache | green PR | yes |
| 9 | first real release | full checklist | n/a |

Stages 0 through 3 deliver the PR-visibility goal on their own and are independently valuable. Stages 4 through 7 deliver the one-command release. Stage 8 is follow-up hardening that can slip without blocking anything, now that the credential-bearing workflows are pinned at birth in stage 5.
