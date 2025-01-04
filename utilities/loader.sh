#!/bin/bash
# utilities/loader.sh - Dynamically load all utility scripts and .env

# Detect the project root dynamically
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)

# Source the environment variables from .env
if [ -f "$PROJECT_ROOT/utilities/env_loader.sh" ]; then
    source "$PROJECT_ROOT/utilities/env_loader.sh"
else
    echo "⚠️  env_loader.sh not found. Ensure environment variables are loaded."
fi

# List all utility scripts to source in the correct order
UTILS=(
    "config.sh"
    "ssh.sh"
    "settings.sh"
    "keys.sh"
    "general.sh"
    "art.sh"
)

# Source each utility script explicitly
for util in "${UTILS[@]}"; do
    util_path="$PROJECT_ROOT/utilities/$util"
    if [[ -f "$util_path" ]]; then
        source "$util_path"
        echo "✅ Loaded utility: $util"
    else
        echo "⚠️  Missing utility script: $util_path"
    fi
done
