#!/bin/bash

# Start the web server in the background
./tmp/goiabada & echo $! > go_run_pid.txt
echo "Waiting for the server to start..."

# Loop until the server responds with a 200 status code
while true; do
  response=$(curl --write-out '%{http_code}' --silent --output /dev/null http://localhost:8080/health)

  if [ "$response" -eq 200 ]; then
    echo "Server is up and running"
    break
  else
    echo "Server is not ready yet. Retrying..."
    sleep 1
  fi
done

# Run the tests
go test -v -count=1 -p 1 ./cmd/integration_tests/...

# Kill the web server process
kill -9 $(cat go_run_pid.txt)

