#!/bin/bash

# Start the web server in the background
./tmp/goiabada_auth_server & echo $! > go_run_pid.txt
echo "Waiting for the server to start..."

env -0 | sort -z | tr '\0' '\n'

# Loop until the server responds with a 200 status code
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

echo "Running tests..."

# Run the tests

if ! go test -v -count=1 -p 1 ./tests/data/...; then
  echo "Tests failed. Exiting..."
  exit 1
fi

if ! go test -v -count=1 -p 1 ./tests/integration/...; then
  echo "Tests failed. Exiting..."
  exit 1
fi

echo "Tests finished. Killing the server..."

# Kill the web server process
kill -9 $(cat go_run_pid.txt)

echo "Done. Bye!"
