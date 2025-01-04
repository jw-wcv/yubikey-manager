#!/bin/bash
# utilities/env_loader.sh - Load environment variables from .env

# Detect the project root dynamically
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)

# Export the project root so other scripts can use it
export PROJECT_ROOT

# Check for the .env file in the project root and load variables
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a  # Automatically export all sourced variables
    source "$PROJECT_ROOT/.env"
    set +a
    echo "✅ Environment variables loaded from $PROJECT_ROOT/.env"
else
    echo "⚠️  .env file not found in $PROJECT_ROOT. Some paths may be undefined."
fi
