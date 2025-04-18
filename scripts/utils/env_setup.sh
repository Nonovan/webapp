#!/bin/bash

# Script to set up environment configuration

# Exit immediately if a command exits with a non-zero status
set -e

# Define environment variables
export APP_ENV="development"
export APP_PORT=3000
export DB_HOST="localhost"
export DB_PORT=5432
export DB_USER="user"
export DB_PASSWORD="password"

# Print environment variables for verification
echo "Environment configuration:"
echo "APP_ENV=$APP_ENV"
echo "APP_PORT=$APP_PORT"
echo "DB_HOST=$DB_HOST"
echo "DB_PORT=$DB_PORT"
echo "DB_USER=$DB_USER"

# Add any additional setup commands below
# Example: Creating necessary directories
mkdir -p /tmp/myproject/logs

echo "Environment setup complete."