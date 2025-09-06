#!/bin/bash

# Build the project first
echo "Building the project before running tests..."
./build.sh
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
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

# Function to run tests
run_tests() {
    local test_type=$1
    echo "Running $test_type tests..."
    if ! go test -v -count=1 -p 1 "./tests/$test_type/..."; then
        echo "Tests failed. Exiting..."
        exit 1
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
    local ports=("9090" "9091")
    
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
            export GOIABADA_DB_PORT=3306
            export GOIABADA_DB_NAME="goiabada_${db_name_suffix}"
            export GOIABADA_DB_DSN=""
            ;;
        "postgres")
            export GOIABADA_DB_TYPE=postgres
            export GOIABADA_DB_USERNAME=postgres
            export GOIABADA_DB_PASSWORD=myPostgresPass123
            export GOIABADA_DB_HOST=postgres-server
            export GOIABADA_DB_PORT=5432
            export GOIABADA_DB_NAME="goiabada_${db_name_suffix}"
            export GOIABADA_DB_DSN=""
            ;;
        "mssql")
            export GOIABADA_DB_TYPE=mssql
            export GOIABADA_DB_USERNAME=sa
            export GOIABADA_DB_PASSWORD=YourStr0ngPassw0rd!
            export GOIABADA_DB_HOST=mssql-server
            export GOIABADA_DB_PORT=1433
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
}

# Run tests for internal modules
echo "Running internal tests..."
if ! go test -v "./internal/..."; then
    echo "Authserver internal tests failed. Exiting..."
    exit 1
fi

# Run tests for core module
echo "Running tests for core module..."
if ! (cd ../core && go test -v ./...); then
    echo "Core module tests failed. Exiting..."
    exit 1
fi

# Run tests for adminconsole module
echo "Running tests for admin console module..."
if ! (cd ../adminconsole && go test -v ./...); then
    echo "Admin console module tests failed. Exiting..."
    exit 1
fi

# Kill any processes on ports 9090 and 9091 before starting tests
kill_processes_on_ports

# Define database types
databases=("mysql" "postgres" "mssql" "sqlite")

# Run data tests for each database type
for db in "${databases[@]}"; do
    echo "=== Running data tests with $db ==="
    configure_database "$db" true
    run_tests "data"
    echo "=== Completed data tests with $db ==="
    echo
done

# Run integration tests for each database type
for db in "${databases[@]}"; do
    echo "=== Running integration tests with $db ==="
    configure_database "$db" false
    start_server_and_wait
    run_tests "integration"
    stop_server
    echo "=== Completed integration tests with $db ==="
    echo
done

echo "All tests completed successfully."