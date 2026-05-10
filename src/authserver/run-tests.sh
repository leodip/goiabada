#!/bin/bash
#
# run-tests.sh - Run Goiabada test suites with optional filtering.
#
# Usage:
#   ./run-tests.sh [options]
#
# Options:
#   -t, --type   <type>     Test category to run. One of:
#                             internal      - authserver internal/* unit tests
#                             core          - core module tests
#                             adminconsole  - adminconsole module tests
#                             data          - data-layer tests (per DB)
#                             integration   - end-to-end integration tests (per DB)
#                             modules       - shorthand for internal+core+adminconsole
#                             all           - everything (default)
#   -d, --db     <db>       Database to use for `data` and `integration` tests.
#                           One of: mysql | postgres | mssql | sqlite | all (default: all)
#   -r, --run    <pattern>  go test -run regex passed to data/integration runs
#                           (e.g. TestTemp_AccessTokenHasSidClaim or 'TestToken_.*Reuse')
#   -h, --help              Show this help and exit.
#
# Examples:
#   # Full suite, all DBs (the original behavior)
#   ./run-tests.sh
#
#   # Only integration tests, only sqlite
#   ./run-tests.sh --type integration --db sqlite
#
#   # Focus on a single integration test, sqlite only (fastest feedback loop)
#   ./run-tests.sh --type integration --db sqlite \
#                  --run TestTemp_AccessTokenHasSidClaim
#
#   # Run a name pattern across every DB
#   ./run-tests.sh --type integration --run 'TestToken_AuthCode_CodeReuse_'
#
#   # Just the internal authserver unit tests
#   ./run-tests.sh --type internal
#
# Notes:
#   * --run only affects `data` and `integration` runs (where go test is invoked
#     against ./tests/<type>/...). It is ignored for module-level test runs.
#   * `integration` requires a running authserver; this script starts/stops it
#     automatically per DB.
#   * Rate limiter is disabled via GOIABADA_AUTHSERVER_RATELIMITER_ENABLED=false.
#   * Per-phase output is also written to $LOG_DIR (printed at startup). On
#     failure the log path plus a FAIL/panic summary is printed at the bottom
#     so you don't have to scroll up through thousands of PASS lines.

set -uo pipefail

# ---- argument parsing -------------------------------------------------------
TYPE="all"
DB="all"
RUN_PATTERN=""

print_help() {
    sed -n '2,46p' "$0"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--type)
            TYPE="${2:-}"; shift 2 ;;
        -d|--db)
            DB="${2:-}"; shift 2 ;;
        -r|--run)
            RUN_PATTERN="${2:-}"; shift 2 ;;
        -h|--help)
            print_help; exit 0 ;;
        *)
            echo "Unknown argument: $1"
            echo "Run './run-tests.sh --help' for usage."
            exit 2 ;;
    esac
done

# Validate --type
case "$TYPE" in
    internal|core|adminconsole|data|integration|modules|all) ;;
    *)
        echo "Invalid --type '$TYPE'. Run './run-tests.sh --help'."
        exit 2 ;;
esac

# Validate --db and expand 'all'
case "$DB" in
    mysql|postgres|mssql|sqlite) databases=("$DB") ;;
    all) databases=("mysql" "postgres" "mssql" "sqlite") ;;
    *)
        echo "Invalid --db '$DB'. Run './run-tests.sh --help'."
        exit 2 ;;
esac

# Helpers to decide whether a section should run for the chosen --type.
should_run_internal()     { [ "$TYPE" = "all" ] || [ "$TYPE" = "modules" ] || [ "$TYPE" = "internal" ]; }
should_run_core()         { [ "$TYPE" = "all" ] || [ "$TYPE" = "modules" ] || [ "$TYPE" = "core" ]; }
should_run_adminconsole() { [ "$TYPE" = "all" ] || [ "$TYPE" = "modules" ] || [ "$TYPE" = "adminconsole" ]; }
should_run_data()         { [ "$TYPE" = "all" ] || [ "$TYPE" = "data" ]; }
should_run_integration()  { [ "$TYPE" = "all" ] || [ "$TYPE" = "integration" ]; }

# ---- output capture ---------------------------------------------------------
# Every phase writes its full output here so failures are inspectable without
# scrolling up through tens of thousands of PASS lines.
LOG_DIR="/tmp/goiabada-tests-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$LOG_DIR"

echo "==> type=$TYPE db=$DB run='${RUN_PATTERN:-<all>}'"
echo "==> log dir: $LOG_DIR"

# fail_with prints the phase that failed, the log path, every failure
# block (the lines around each `--- FAIL` and `panic:`), and a list of
# all failed test names — then exits 1. Output goes straight to the
# terminal so it can be selected and copied; no `less` paging.
# Args: <phase label> <log file>
fail_with() {
    local label="$1"
    local log="$2"
    echo
    echo "=========================================================="
    echo "FAILED: $label"
    echo "Log file: $log"
    echo "=========================================================="
    echo
    echo "---- Failed tests --------------------------------------"
    # The single-line list of every failed test name.
    grep -E '^(    )*--- FAIL:' "$log" | sed 's/^/  /' || true
    echo
    echo "---- Failure context (40 lines before each --- FAIL) ---"
    # Each Go test's assertion / mock-mismatch diagnostic prints BEFORE
    # the `--- FAIL` summary line. Capture that window so the actual
    # error text is visible inline.
    grep -B40 -A2 -E '^(    )*--- FAIL:' "$log" || true
    echo
    echo "---- Panics --------------------------------------------"
    grep -B5 -A30 'panic:' "$log" || true
    echo
    echo "---- Final package status ------------------------------"
    grep -E '^(FAIL|ok)\b' "$log" | tail -20 || true
    echo
    echo "=========================================================="
    echo "Full log: $log"
    echo "(open with: cat $log    or    code $log)"
    echo "=========================================================="
    exit 1
}

# ---- build ------------------------------------------------------------------
build_log="$LOG_DIR/00-build.log"
echo "Building the project before running tests... (log: $build_log)"
if ! ./build.sh 2>&1 | tee "$build_log"; then
    fail_with "Build" "$build_log"
fi

# Cleanup function to kill processes on exit
cleanup() {
    echo "Cleaning up processes..."
    kill_processes_on_ports
    echo "Cleaning up temporary SQLite databases..."
    rm -f /tmp/goiabada*.db
}

# Set trap to cleanup on script exit (normal or error)
trap cleanup EXIT

# Run go test for the given test sub-directory (data|integration).
# Honors $RUN_PATTERN when set so you can target a single test by name.
run_tests() {
    local test_type=$1
    local args=(-v -count=1 -p 1)
    if [ -n "$RUN_PATTERN" ]; then
        args+=(-run "$RUN_PATTERN")
        echo "Running $test_type tests (filter: -run '$RUN_PATTERN')..."
    else
        echo "Running $test_type tests..."
    fi
    local log="$LOG_DIR/${test_type}-${GOIABADA_DB_TYPE:-unknown}.log"
    echo "Log: $log"
    if ! go test "${args[@]}" "./tests/$test_type/..." 2>&1 | tee "$log"; then
        fail_with "$test_type tests (${GOIABADA_DB_TYPE:-unknown})" "$log"
    fi
}

# Function to start server and wait for it to be ready
start_server_and_wait() {
    # Start server and capture PID
    ./tmp/goiabada-authserver &
    server_pid=$!
    echo "Started server with PID: $server_pid"

    echo "Waiting for the server to start..."
    env -0 | sort -z | tr '\0' '\n'
    counter=0
    while true; do
        # Check if the server process is still running
        if ! kill -0 $server_pid 2>/dev/null; then
            echo "Server process died unexpectedly. Checking for port binding issues..."
            # Kill any processes that might be holding the ports
            kill_processes_on_ports
            echo "Retrying server start..."
            ./tmp/goiabada-authserver &
            server_pid=$!
            echo "Restarted server with PID: $server_pid"
        fi

        response=$(curl --write-out '%{http_code}' --silent --output /dev/null "${GOIABADA_AUTHSERVER_BASEURL}/health")
        if [ "$response" -eq 200 ]; then
            echo "Server is up and running"
            break
        else
            echo "Server is not ready yet. Retrying..."
            sleep 1
            counter=$((counter+1))
            if [ $counter -ge 40 ]; then
                echo "Server did not start within 40 seconds. Exiting..."
                exit 1
            fi
        fi
    done
}

# Function to stop the server
stop_server() {
    echo "Tests finished. Killing the server..."
    # Kill processes will be handled by the EXIT trap, but we can call it here for immediate cleanup
    kill_processes_on_ports
}

# Function to kill processes on specified ports
kill_processes_on_ports() {
    local ports=("19090" "19091")

    for port in "${ports[@]}"; do
        echo "Checking for processes on port $port..."
        pids=$(netstat -tulnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$' | sort -u)

        if [ -n "$pids" ]; then
            echo "Found processes listening on port $port: $pids"
            for pid in $pids; do
                if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                    echo "Killing process $pid on port $port"
                    kill -9 "$pid" 2>/dev/null || true
                fi
            done
        else
            echo "No processes found on port $port"
        fi
    done

    # Wait a moment for processes to be killed
    sleep 2

    # Verify ports are free
    for port in "${ports[@]}"; do
        if netstat -tulnp 2>/dev/null | grep -q ":$port "; then
            echo "Warning: Port $port is still in use after cleanup attempt"
        else
            echo "Port $port is now free"
        fi
    done
}

# Function to configure database environment
configure_database() {
    local db_type=$1
    local is_data_test=$2
    echo "Configuring for database: $db_type"

    # Set the database name suffix based on test type
    local db_name_suffix="integration"
    if [ "$is_data_test" = true ]; then
        db_name_suffix="data"
    fi

    case $db_type in
        "mysql")
            export GOIABADA_DB_TYPE=mysql
            export GOIABADA_DB_USERNAME=root
            export GOIABADA_DB_PASSWORD=mySqlPass123
            export GOIABADA_DB_HOST=mysql-server
            export GOIABADA_DB_PORT=13306
            export GOIABADA_DB_NAME="goiabada_${db_name_suffix}"
            export GOIABADA_DB_DSN=""
            ;;
        "postgres")
            export GOIABADA_DB_TYPE=postgres
            export GOIABADA_DB_USERNAME=postgres
            export GOIABADA_DB_PASSWORD=myPostgresPass123
            export GOIABADA_DB_HOST=postgres-server
            export GOIABADA_DB_PORT=15432
            export GOIABADA_DB_NAME="goiabada_${db_name_suffix}"
            export GOIABADA_DB_DSN=""
            ;;
        "mssql")
            export GOIABADA_DB_TYPE=mssql
            export GOIABADA_DB_USERNAME=sa
            export GOIABADA_DB_PASSWORD=YourStr0ngPassw0rd!
            export GOIABADA_DB_HOST=mssql-server
            export GOIABADA_DB_PORT=11433
            export GOIABADA_DB_NAME="goiabada_${db_name_suffix}"
            export GOIABADA_DB_DSN=""
            ;;
        "sqlite")
            export GOIABADA_DB_TYPE=sqlite
            export GOIABADA_DB_USERNAME=""
            export GOIABADA_DB_PASSWORD=""
            export GOIABADA_DB_HOST=""
            export GOIABADA_DB_PORT=""
            export GOIABADA_DB_NAME=""
            export GOIABADA_DB_DSN="/tmp/goiabada_${db_name_suffix}.db"
            ;;
        *)
            echo "Unsupported database type: $db_type"
            exit 1
            ;;
    esac

    # Disable rate limiter for tests
    export GOIABADA_AUTHSERVER_RATELIMITER_ENABLED=false
}

# ---- module test runs (no DB matrix) ----------------------------------------

if should_run_internal; then
    log="$LOG_DIR/01-internal.log"
    echo "Running internal tests... (log: $log)"
    if ! go test -v "./internal/..." 2>&1 | tee "$log"; then
        fail_with "Authserver internal tests" "$log"
    fi
fi

if should_run_core; then
    log="$LOG_DIR/02-core.log"
    echo "Running tests for core module... (log: $log)"
    if ! (cd ../core && go test -v ./...) 2>&1 | tee "$log"; then
        fail_with "Core module tests" "$log"
    fi
fi

if should_run_adminconsole; then
    log="$LOG_DIR/03-adminconsole.log"
    echo "Running tests for admin console module... (log: $log)"
    if ! (cd ../adminconsole && go test -v ./...) 2>&1 | tee "$log"; then
        fail_with "Admin console module tests" "$log"
    fi
fi

# ---- DB-matrix runs (data + integration) ------------------------------------

if should_run_data || should_run_integration; then
    # Kill any processes on ports 19090 and 19091 before starting tests
    kill_processes_on_ports
fi

if should_run_data; then
    for db in "${databases[@]}"; do
        echo "=== Running data tests with $db ==="
        configure_database "$db" true
        run_tests "data"
        echo "=== Completed data tests with $db ==="
        echo
    done
fi

if should_run_integration; then
    for db in "${databases[@]}"; do
        echo "=== Running integration tests with $db ==="
        configure_database "$db" false
        start_server_and_wait
        run_tests "integration"
        stop_server
        echo "=== Completed integration tests with $db ==="
        echo
    done
fi

echo
echo "All tests completed successfully."
echo "Logs in: $LOG_DIR"
