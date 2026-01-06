#!/bin/bash

# Detect if running inside a devcontainer/docker
if [ -f "/.dockerenv" ] || [ -n "$REMOTE_CONTAINERS" ] || [ -n "$CODESPACES" ]; then
    echo "Detected devcontainer - setting ownership to root"
    chown -R 0:0 .
else
    echo "Detected host - setting ownership to leodip (1000:1000)"
    sudo chown -R 1000:1000 .
fi
