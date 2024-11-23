#!/bin/bash

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
    ./tmp/goiabada-authserver & echo $! > go_run_pid.txt
    echo "Waiting for the server to start..."
    env -0 | sort -z | tr '\0' '\n'
    counter=0
    while true; do
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
    kill -9 $(cat go_run_pid.txt)
    rm -f go_run_pid.txt
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