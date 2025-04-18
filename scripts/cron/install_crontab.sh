#!/bin/bash
# Install appropriate crontab based on environment

# Detect environment
if [ -z "$ENV" ]; then
    if [ -f "/.env" ]; then
        source "/.env"
    fi
    
    # Default to development if still not set
    ENV=${FLASK_ENV:-development}
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CRONTAB_DIR="$SCRIPT_DIR/crontabs"

# Select appropriate crontab file
case "$ENV" in
    production)
        CRONTAB_FILE="$CRONTAB_DIR/production.crontab"
        ;;
    staging)
        CRONTAB_FILE="$CRONTAB_DIR/staging.crontab"
        ;;
    *)
        CRONTAB_FILE="$CRONTAB_DIR/development.crontab"
        ;;
esac

# Check if file exists
if [ ! -f "$CRONTAB_FILE" ]; then
    echo "Error: Crontab file $CRONTAB_FILE not found!"
    exit 1
fi

# Process the crontab file to replace template variables
TEMP_CRONTAB=$(mktemp)
cat "$CRONTAB_FILE" | envsubst > "$TEMP_CRONTAB"

# Install crontab
echo "Installing crontab for $ENV environment from $CRONTAB_FILE"
crontab "$TEMP_CRONTAB"

# Clean up
rm "$TEMP_CRONTAB"

echo "Crontab installation completed"
