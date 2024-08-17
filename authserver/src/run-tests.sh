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
    ./tmp/goiabada_auth_server & echo $! > go_run_pid.txt
    echo "Waiting for the server to start..."
    env -0 | sort -z | tr '\0' '\n'

    counter=0
    while true; do
        response=$(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:8080/health)
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
}

# Run data tests
export GOIABADA_DB_NAME=goiabada_data
export GOIABADA_DB_DSN=/tmp/goiabada_data.db
run_tests "data"

# Run integration tests with MySQL
export GOIABADA_DB_TYPE=mysql
export GOIABADA_DB_NAME=goiabada_integration
start_server_and_wait
run_tests "integration"
stop_server

# Run integration tests with SQLite
export GOIABADA_DB_TYPE=sqlite
export GOIABADA_DB_DSN=/tmp/goiabada_integration.db
start_server_and_wait
run_tests "integration"
stop_server

echo "All tests completed successfully."