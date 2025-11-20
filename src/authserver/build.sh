#!/bin/bash

echo "Building Goiabada Auth Server..."

# Build Tailwind CSS
echo "Building Tailwind CSS..."
tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
if [ $? -ne 0 ]; then
    echo "Failed to build Tailwind CSS"
    exit 1
fi

# Clean previous build
echo "Cleaning previous build..."
rm -f ./tmp/goiabada-authserver

# Build Go binary
echo "Building Go binary..."
go build -o ./tmp/goiabada-authserver ./cmd/goiabada-authserver/main.go
if [ $? -ne 0 ]; then
    echo "Failed to build Go binary"
    exit 1
fi

echo "Build completed successfully!"