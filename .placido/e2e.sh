#!/usr/bin/env bash
# placido's last gate for Goiabada: rebuild the e2e environment on the VPS from this
# worktree's src/, then run the e2e suite against it (e2e/run.sh --source). The
# rate-limits suite is not part of it: it runs by hand, before a release.
#
#   .placido/e2e.sh                  # the whole e2e suite
#   .placido/e2e.sh tests/oauth      # one area; any Playwright argument passes through
#
# When at most 20 tests fail in a run given no Playwright option, they run once more against
# the same environment, alone and one at a time, after the setup project's sweep. If they
# pass, the gate prints FLAKY with their names and passes.
#
# There is one environment, so a lock keeps two placido runs from rebuilding it at
# once, and the main checkout's suite lock keeps this run and a suite run by hand there
# apart. The machine's settings (e2e/.env) come from the main checkout, and what the
# run leaves in e2e/.state (the URLs, the admin password) goes back to it, so
# e2e/test.sh there runs against the environment this run built.
set -uo pipefail

case "${1:-}" in
  -h | --help) sed -n '2,17s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac

# The most failed tests the gate reruns. More than that is not the shared environment
# dropping a request here and there.
max_rerun=20

worktree="$(git rev-parse --show-toplevel)" || exit 1
main="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")" || exit 1
suite="$worktree/e2e/playwright"

[[ -f "$main/e2e/.env" ]] || { echo "no $main/e2e/.env: copy e2e/.env.example there and set E2E_VPS_HOST" >&2; exit 1; }
if [[ "$main" != "$worktree" ]]; then
  cp "$main/e2e/.env" "$worktree/e2e/.env"
fi

mkdir -p "$main/e2e/.state"
exec 9>"$main/e2e/.state/placido.lock"
if ! flock -n 9; then
  echo "Another run is using the e2e environment; waiting for it."
  flock 9
fi

# Each suite holds e2e/.state/suite.lock in its own checkout, and this run's checkout is
# the worktree: hold the main checkout's too, so a suite run by hand there never meets
# this one. In the main checkout itself, test.sh takes it.
if [[ "$main" != "$worktree" ]]; then
  exec 8>"$main/e2e/.state/suite.lock"
  if ! flock -n 8; then
    echo "A suite run by hand in $main holds its suite lock; waiting for it."
    flock 8
  fi
fi

# Playwright writes the IDs of the tests that failed or did not run to this file at the end
# of a suite, and the rerun reads them from it. It starts empty, so a run that stops before
# the suite ends, a failed build among them, leaves nothing to rerun.
last_run="$(mktemp)" || exit 1
trap 'rm -f "$last_run"' EXIT

# How many tests the file lists, or 0 unless the suite ran to its end with failed tests.
failed_count() {
  python3 -c 'import json, sys
run = json.load(open(sys.argv[1]))
print(len(run["failedTests"]) if run.get("status") == "failed" else 0)' "$last_run" 2>/dev/null || echo 0
}

# Renames a folder to a name nothing holds, so that it never lands inside another folder; fails,
# and moves nothing, when the name is taken or the folder is not there.
move_aside() { # from to
  [[ -d "$1" && ! -e "$2" ]] && mv "$1" "$2"
}

# The suite's failures here have come from the shared environment, not from the tests: a
# request the VPS leaves unanswered fails a test, a different one on each run. So the tests
# that did not pass run once more, and only they: --no-deps leaves out the setup project and
# the system tests Playwright would otherwise run in full beside them, and one worker keeps
# a system test's change to the whole instance from meeting any other test. The setup
# project's sweep runs first, on its own, and puts back what a failed test left. Prints
# FLAKY when the rerun passes; returns the gate's status.
rerun_failed_tests() { # first_status
  local count names
  count="$(failed_count)"
  if ((count == 0)); then
    echo "No rerun: the suite did not run to its end with failed tests."
    return "$1"
  fi
  if ((count > max_rerun)); then
    echo "No rerun: $count tests failed or did not run, more than the $max_rerun the gate reruns."
    return "$1"
  fi
  if ! names="$(cd "$suite" &&
    npx playwright test --list --last-failed --last-failed-file "$last_run" --no-deps | grep '^  \[')"; then
    echo "No rerun: Playwright could not list the tests that did not pass."
    return "$1"
  fi

  # Each Playwright run clears test-results/ and playwright-report/ when it starts, so the
  # first run's traces, screenshots and report move aside before the sweep's, and each is
  # announced only once it has moved.
  echo
  if move_aside "$suite/test-results" "$suite/test-results-first-run"; then
    echo "The first run's traces and screenshots are in e2e/playwright/test-results-first-run/."
  fi
  if move_aside "$suite/playwright-report" "$suite/playwright-report-first-run"; then
    echo "The first run's report: (cd e2e/playwright && npx playwright show-report playwright-report-first-run)"
  fi
  echo "Rerunning these tests once, after the setup project's sweep:"
  printf '%s\n' "$names"
  if ! "$worktree/e2e/test.sh" --project=setup --no-deps; then
    echo "No rerun: the setup project's sweep failed."
    return "$1"
  fi
  "$worktree/e2e/test.sh" --last-failed --last-failed-file "$last_run" --no-deps --workers=1 || return

  echo
  echo "FLAKY: these tests did not pass on the first run and passed on the rerun:"
  printf '%s\n' "$names"
}

# The rerun picks its tests by their IDs and runs them with options of its own, so it follows
# only a run given test locations alone, or nothing, as placido gives it. A Playwright option,
# such as --last-failed or --repeat-each, changes which tests run in a way the rerun would not
# repeat, and such a run goes as given, reading and writing Playwright's own last-run file.
rerunnable=1
for arg in "$@"; do
  [[ "$arg" == -* ]] && rerunnable=0
done

# What an earlier run's rerun kept of its first run, so that what this run leaves is its own.
rm -rf "$suite/test-results-first-run" "$suite/playwright-report-first-run"

if ((rerunnable)); then
  PLAYWRIGHT_LAST_RUN_OUTPUT_FILE="$last_run" "$worktree/e2e/run.sh" --source "$@"
else
  "$worktree/e2e/run.sh" --source "$@"
fi
status=$?
if ((status != 0 && rerunnable)); then
  rerun_failed_tests "$status"
  status=$?
elif ((status != 0)); then
  echo "No rerun: the gate reruns only a run given test locations alone, and this one was given a Playwright option."
fi

if [[ "$main" != "$worktree" && -d "$worktree/e2e/.state" ]]; then
  cp -a "$worktree/e2e/.state/." "$main/e2e/.state/"
fi
exit "$status"
