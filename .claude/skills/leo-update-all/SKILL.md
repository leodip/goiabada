---
name: leo-update-all
description: Update everything src/authserver/version-manager.sh manages to its newest settled release, regenerate every committed generated file, and verify the result in a throwaway dev stack built from the new pins. That covers the toolchain and vendored pins in versions.yaml, the Go modules of all four modules, the npm packages of both e2e projects, every npm package of the docs site to its latest release (majors included), Playwright's browsers and the data generators' upstream sources.
disable-model-invocation: true
argument-hint: "[--dry-run] [--now]"
---

# Update all

Arguments: `$ARGUMENTS`
- `--dry-run`: run the check, show what would change, then stop. No file is touched.
- `--now`: pass `--now` to `check` and `deps`, which then take releases younger than the script's 3-day settle window. Use it only for an urgent fix.

Scope: every pin and dependency `version-manager.sh` manages, and every generator in the tree. The docs site (`site/`) goes further than `deps` does: each of its packages moves to its latest settled release, a new major version or a 0.x minor included. A package the site cannot take is held back alone. Out of scope: GitHub Actions versions (Dependabot updates those), the database and Mailpit images in the dev compose file, and the product version (the git tag).

Where things run:
- **Host**: `check`, `update` and `deps`, the script's own workflow. They edit files and fetch releases, and `deps` installs Playwright's browsers for the host, where the e2e suites run from. The npm projects' checks also run on the host (step 9).
- **A throwaway stack, `goiabada-update-all`**, built from the bumped dev container Dockerfile: every generator, the quick Go test tiers and govulncheck, so they run with exactly the new pins, as `CLAUDE.md` asks. The human stack (`goiabada`) is never touched.
- **CI**: the long tiers. CI runs every check on a push to `main` and on a pull request that is ready for review, so step 9 runs only the quick ones, and step 13 watches CI for the rest.

Do every step yourself. The user answers only the questions below and says whether to commit. Shell variables do not persist between Bash calls, so spell out absolute paths: `$ROOT` below is the repository root, `$ENVF` a file in your scratchpad directory, and `$X` the exec prefix from step 6. Before each step that takes more than a minute, tell the user in one line what is running and roughly how long it takes.

## 1. Preflight (host)

1. `ROOT=$(git rev-parse --show-toplevel)`. It must contain `src/authserver/version-manager.sh`. Outside a Goiabada checkout, use `~/code/goiabada`.
2. `git status --porcelain` must be empty, so that the diff holds only the update. If it is not empty, stop and ask.
3. On `main`, run `git fetch origin main`, then `git pull --ff-only`. On any other branch, leave it alone and say which branch the update lands on.
4. `yq --version` must name `mikefarah/yq`, because the script refuses any other yq. `go`, `node`, `npm`, `curl` and `docker` must be on `PATH`, and `docker compose version` must be 2.24 or later, which the worktree override's `!reset` needs.
5. If `docker compose ls --all` lists `goiabada-update-all`, it is left over from an earlier run of this skill. Take it down first, as in step 11.

## 2. Check (host)

```bash
cd "$ROOT/src/authserver" && ./version-manager.sh check [--now] 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
```

Read every section of the output:
- **Updates Available**: pins in `versions.yaml`. The name maps to its key: Go → `tools.go`, Tailwind CSS → `tools.tailwind`, Node.js → `tools.node`, Trivy → `tools.trivy`, Grype → `tools.grype`, cropperjs and acorn → `vendored.*`, and golangci-lint, mockery, staticcheck, unparam, govulncheck and npm-check-updates → `tools.<name>`. A name not in this list means the script has gained a dependency, so find its key in `versions.yaml`.
- **npm Package Updates**: what `deps` will apply, within each package's major version.
- **New Major Versions**: npm majors, which `deps` leaves alone. A row marked `(site)` is not a question: step 5 takes it.
- **Data Source Updates**: generator pins to move in step 7.
- **`Held back`** lines: a newer release younger than 3 days. Report it; it is not taken without `--now`.
- **`Check failed`** lines: the version is unknown, not up to date. Report each one.

Sort each pin into one of two kinds:
- **Routine**: the first number stays the same. staticcheck (0.x) and unparam (a pseudo-version that moves with every upstream commit) are always routine.
- **Major**: the first number changes. Hold it back, because a major version is a migration, not a pin change. golangci-lint and mockery carry their major in module paths (`golangci-lint/v2`, `mockery/v3`) that the dev container Dockerfile, `.github/workflows/check.yml`, `version-manager.sh`'s sed patterns and `generate-mocks.sh` spell out. A Tailwind major changes the generated CSS, and a Node major moves every Node in the tree along with `@types/node`. For each major, list the files that spell the old one (`git grep -n 'mockery/v3'`).

If there are majors (pins, or npm packages outside `site/`), ask once with AskUserQuestion (multiSelect) which to attempt after the routine update is green. Recommend attempting none.

The site's own list comes from the script's `run_ncu` with no target, which looks up to the newest release under the pinned npm-check-updates and the same 3-day cooldown. Read it without changing anything:

```bash
cd "$ROOT/src/authserver" && bash -c 'source ./version-manager.sh && run_ncu "$BASE_DIR/site" --jsonUpgraded'
```

With `--now`, put `RELEASE_MIN_AGE_DAYS=0 &&` after the `source`, here and in step 5.

With `--dry-run`, stop here. Report the routine pins (current → latest), the npm updates, the site's list, the majors, the data source moves, what was held back and what failed. Mention that `deps` also runs `go get -u` in all four modules, which `check` does not report.

With nothing reported, continue anyway: the Go modules and the npm packages' transitive dependencies can be behind while every pin is current.

## 3. Apply the pins (host)

Edit `versions.yaml` with the Edit tool. Change only the version line of each routine bump. Leave the comments alone, and leave every `*-sha256` line alone, because `update` writes those.

```bash
cd "$ROOT/src/authserver" && ./version-manager.sh update 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
```

The summary must show no `Failed updates`. Check that `git diff --stat` touched what the bumps imply:
- Go: the dev container Dockerfile, the two release Dockerfiles in `src/build/` and the four `go.mod` files.
- Node.js: the dev container Dockerfile, `site/Dockerfile` and `e2e/testapp/Dockerfile`.
- Tailwind, golangci-lint, staticcheck, unparam and govulncheck: the dev container Dockerfile.
- mockery: the dev container Dockerfile and `src/mockery-header.txt`.
- cropperjs and acorn: the vendored files and their digests in `versions.yaml`.
- Trivy, Grype and npm-check-updates: `versions.yaml` alone, which CI reads them from.

For each bumped key, `git grep -nF '<old version>' -- ':!*go.sum' ':!*package-lock.json'` finds anything else that still states the old pin. Fix a hit that states the current pin, such as a doc saying "requires Go X". Leave test fixtures and historical statements alone.

## 4. Start the stack (background)

The Dockerfile is final now, so build the stack while `deps` runs. Use `run_in_background`; a changed Dockerfile takes several minutes to build.

```bash
sh "$ROOT/src/.devcontainer/generate-env.sh" &&
BUILDX_BUILDER=default docker compose -p goiabada-update-all \
  --project-directory "$ROOT/src/.devcontainer" \
  -f "$ROOT/src/.devcontainer/docker-compose.yml" \
  -f "$ROOT/src/.devcontainer/docker-compose.worktree.yml" \
  up -d --build --wait --wait-timeout 600
```

`BUILDX_BUILDER=default` is needed because compose builds through the selected buildx builder. A stale `docker-container` builder, such as a multi-arch one left over from release work, fails at "booting buildkit", and `default` (the docker driver) exists in every install. `--build` rebuilds an image an earlier run left under this name.

## 5. Update the Go modules and npm packages (host)

First move every `site/package.json` range to its latest release. Then `deps` installs them, along with everything else, under its cutoff:

```bash
cd "$ROOT/src/authserver" && bash -c 'source ./version-manager.sh && run_ncu "$BASE_DIR/site" --upgrade'
cd "$ROOT/src/authserver" && ./version-manager.sh deps [--now] 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
```

If the site's update crosses an Astro major or a Starlight minor (Starlight is 0.x, so its minors are its breaking releases), read the upstream upgrade guide for each version crossed, and make the changes it requires to `site/astro.config.mjs`, `site/plugins/` and the components. If `npm install` fails on a peer dependency conflict (`ERESOLVE`), find the package whose peer range blocks it. Set that package back to its newest version that resolves, and run `npm install --before="$(date -u -d '3 days ago' +%Y-%m-%dT%H:%M:%SZ)"` in `site/` again (with `--now`, drop `--before`). Never pass `--force` or `--legacy-peer-deps`. Record every site package held back, and why.

The script exits 0 even when a step fails, so read its output. Any `✗` line is a failure: find the cause and fix it before going on. A warning that Playwright's browsers lack system libraries is not a failure. Report the command it prints, which needs sudo, so it is the user's to run. Then check:
- `grep -nE '^(go|toolchain) ' "$ROOT"/src/{core,authserver,adminconsole,cmd/goiabada-setup}/go.mod`: every `go` line must equal `tools.go`, with no `toolchain` line, because CI's versions gate rewrites them. If a dependency raised the line, find which one (its `go.mod` asks for the newer Go). If that Go release is settled, bump `tools.go` as a routine pin and go back to step 3. Otherwise hold the module back to its newest version whose `go` line fits, with `go get <module>@<version>` and `go mod tidy` in every module that requires it.
- The three modules that use core (authserver, adminconsole, cmd/goiabada-setup) must still require `github.com/leodip/goiabada/core v0.0.0` beside their `replace`.

Collect the upgrades for the report: `git diff -U0 -- 'src/**/go.mod'` per Go module (`go get -u` never crosses a major version), `git diff -U0 -- '*/package.json'` per npm project, and the `Held back` lines `deps` printed.

## 6. Prepare the stack

Wait for step 4's background task, then in one Bash call:
1. Check that `docker inspect goiabada-update-all-devcontainer-1 --format '{{range .Mounts}}{{.Source}} {{end}}'` names `$ROOT`.
2. Wait for the three databases with the `wait_for` probes in `src/.devcontainer/README.md` ("Wait for readiness"), with `NAME=goiabada-update-all`. A running database is not yet accepting logins, and step 8's `schemadump` reads all four engines.
3. Write the tests' environment. Compose never reads `containerEnv`, so take CI's: `yq -r '.env | to_entries | .[] | .key + "=" + .value' "$ROOT/.github/workflows/check.yml" > "$ENVF" && echo CGO_ENABLED=0 >> "$ENVF"`.

Every command in the stack then runs as:

```bash
docker exec -u vscode --env-file "$ENVF" -w /workspaces/goiabada/<dir> goiabada-update-all-devcontainer-1 <command>
```

Below, this prefix is `$X <dir>`. `-u vscode` (uid 1000) makes anything the command writes into the checkout belong to the host user. As root it would leave files the host cannot edit. In this stack Mailpit and all four databases resolve, so no test failure here is environmental.

## 7. Move the data sources (stack)

Only for the rows under "Data Source Updates". Follow the steps at the top of each generator's `main.go`: set the pin, run `$X src/authserver ./version-manager.sh generate <target>`, set the SHA-256 the refusal prints, and run it again.

| Target | Generator | Pins it moves |
|---|---|---|
| `timezones` | `src/core/timezones/generate/main.go` | `pinnedRelease`, `pinnedTarballSHA256` |
| `countries` | `src/core/countries/generate/main.go` | `pinnedCommit`, `pinnedCSVSHA256` |
| `passwordblocklist` | `src/core/passwordblocklist/generate/main.go` | `pinnedCommit`, each changed list's `sha256`, `expectedCount` |

The password generator stops at a count change for a human review. Before you set `expectedCount`, review the change: the count (old → new), a sample of the added and removed entries, and whether they look like passwords. Put that review in the report. For every target, say what changed in `data_generated.go` besides its provenance header.

## 8. Regenerate everything (stack)

Each generator is idempotent, so one whose inputs did not change leaves no diff. Run them all, every time:

```bash
$X src/authserver   ./build.sh                       # auth server CSS (and binary)
$X src/adminconsole ./build.sh                       # admin console CSS (and binary)
$X src/authserver   ./generate-mocks.sh              # mocks, header from mockery-header.txt
$X src/core         go run ./cmd/ownershipdump       # src/core/OWNERSHIP.md
$X src/authserver   go run ./cmd/schemadump          # the four schema goldens
$X src/authserver   ./version-manager.sh generate    # timezones, countries, passwordblocklist
```

Then check `git status --porcelain` against what the update explains: CSS after a Tailwind bump, the mock headers after a mockery bump, and the data tables for the sources step 7 moved. Investigate any other diff. A schema golden that moved with no migration change means an upstream database image changed: report it and ask before keeping it. Otherwise restore it with `git checkout`.

## 9. Verify (stack, then host)

Run the quick checks, each a few minutes at most. Give each call a 10-minute timeout. `run-tests.sh` stops at the first failing tier, and it prints its log directory and a failure summary.

1. `$X src/authserver ./run-tests.sh --type lint` runs `build.sh`, golangci-lint and unparam over the four modules, and checks that the CSS, the mocks and `OWNERSHIP.md` are what their generators produce.
2. `$X src/authserver ./run-tests.sh --type modules --no-build`, then `--type setup --no-build`.
3. `$X src sh -c 'for m in core authserver adminconsole cmd/goiabada-setup; do echo "== $m"; (cd $m && govulncheck ./...) || exit 1; done'`.
4. Each e2e project whose `package.json` or lock file changed, on the host, because the dev container installs Node's binary alone, without npm. `npm ci` first in each, so the check runs on exactly what the committed lock file installs: `cd "$ROOT/e2e/playwright" && npm ci && npm run typecheck`, and `cd "$ROOT/e2e/testapp" && npm ci && npm test && npm run build`. Never run the e2e suites; they run against the maintainer's VPS.
5. When the site crossed a major or a 0.x minor: `cd "$ROOT/site" && npm ci && npm test && npm run build` on the host. Step 5's hold-back decision has to be made before anything is pushed. If a site major fails and you cannot fix it with a contained change (config, imports, a renamed option the upgrade guide names), hold that package back to its newest release in its current major (in its current minor for a 0.x package), and rerun this check.

Left to CI (step 13), each several minutes or more:
- the data tier on all four engines, and the integration tier on all four;
- the race-detector runs of the module tiers;
- the docs job's image, nginx and browser checks;
- the release images' build validation.

CI's four database jobs skip while a pull request is a draft, so an update relies on them only on `main` or on a pull request that is ready for review.

Failures:
- **A new golangci-lint finding**: fix the code, or suppress a false positive inline with its reason, as `.golangci.yml` asks.
- **A dependency's API change**: adapt to it when the change is small and mechanical. Otherwise hold the dependency back (`go get <module>@<old>` and `go mod tidy` in every module that requires it, or the old range in its `package.json` and `npm install`) and put it to the user.
- **A govulncheck finding**: say whether a fixed version exists. If the settle window kept `deps` from taking it, say that `--now` would.
- **A bug the update exposes**: fix it in this run or put it to the user. Never leave it as a residual risk.

After a fix, rerun the check that failed and every local check the fix could affect.

## 10. The majors the user chose

Attempt them one at a time, after the routine update is green. For a pin, change it, update every file that spells the old major and run `update`. For an npm package, change its range in `package.json` and run `npm install`. Then rerun step 8 and the tiers the major affects. If it cannot be made green with a contained change, revert that major alone and report what blocked it. Each major becomes its own commit.

## 11. Tear down

```bash
docker compose -p goiabada-update-all \
  --project-directory "$ROOT/src/.devcontainer" \
  -f "$ROOT/src/.devcontainer/docker-compose.yml" \
  -f "$ROOT/src/.devcontainer/docker-compose.worktree.yml" \
  down -v
```

Then `find "$ROOT" -user root -not -path '*/.git/*' | head` must print nothing. The stack's image stays behind as the build cache for the next run.

## 12. Report, then commit if asked

Report in this order:
- **Pins**: each key, old → new. What was held back and why (age, or a major), and the checks that failed.
- **Go modules**: the upgrades per module, the notable direct ones by name and a count of the rest, and anything held back.
- **npm**: per project, the direct upgrades by name and a count of the transitive ones. For the site, mark the majors and 0.x minors, the changes they needed, and each package held back with its reason.
- **Data sources**: the moved pins, what changed in each table, and the password list review.
- **Regenerated**: CSS, mocks, `OWNERSHIP.md`, schema goldens and data tables, whichever changed.
- **Verification**: each local check and its result, including govulncheck's and the npm checks'. Name what was left to CI. Also print the e2e suites' command, `e2e/run.sh --source`, for the user to run from a clean checkout of `main` once the update is there.
- **Dev container**: if a pin it installs moved (go, tailwind, node, golangci-lint, mockery, staticcheck, unparam, govulncheck), the human dev container needs a rebuild before the next local work there.

Then ask with AskUserQuestion. The options are: commit and push to `main`, which is how earlier updates landed (`8a050570d`, `df94e5786`) and where CI runs every check; commit on a new branch; commit, push and open a pull request that is ready for review, never a draft; or leave it uncommitted. Add a question that accepts or drops any data source move or major the run made. For a branch or a pull request on `main`, first create `deps/update-<YYYY-MM-DD>`.

Write the commits in the repository's style (`git show 8a050570d` and `git show df94e5786` are examples):
- The routine pins and the Go and npm upgrades go in one commit. The subject is one plain sentence naming what moved, such as "Update Tailwind CSS, Grype, and the Go and npm dependencies". The body has a `versions.yaml:` paragraph and a `./version-manager.sh deps:` paragraph, naming what was held back.
- The data source moves go in a commit of their own, and so does each major from step 10. A site major that needed code or config changes goes in its own commit; one that needed none goes in the first commit.
- End each commit with the attribution trailer the session asks for.

A PR's title is the first commit's subject. Its body is the report, ending with the session's attribution line. Never merge.

## 13. Watch CI

After a push, find the `check.yml` run for the pushed commit: `gh run list --workflow check.yml --commit <sha> --json databaseId,status`. It can take a few seconds to appear. Watch it with `run_in_background` and `gh run watch <id> --exit-status`; a run takes roughly 10 minutes. Tell the user what is pending, then report the result per job.

Treat a failed job like a step 9 failure: read `gh run view <id> --log-failed`, then fix the cause, commit and push the fix the same way the update went, and watch the new run. A job that failed for a reason outside the update, such as a runner or network error, gets one `gh run rerun <id> --failed`. If it fails again, report it.
