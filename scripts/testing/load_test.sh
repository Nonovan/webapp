#!/bin/bash

# Load Testing Script
# This script performs a simple load test by sending multiple HTTP requests to a target URL.

# Configuration
TARGET_URL="http://localhost:8080" # Replace with your target URL
CONCURRENT_REQUESTS=10
TOTAL_REQUESTS=100

# Function to perform a single request
perform_request() {
    curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"
}

# Perform load test
echo "Starting load test on $TARGET_URL with $CONCURRENT_REQUESTS concurrent requests and $TOTAL_REQUESTS total requests..."

for ((i=1; i<=TOTAL_REQUESTS; i++)); do
    # Run requests in background to simulate concurrency
    ((j=j%CONCURRENT_REQUESTS)); ((j++==0)) && wait
    perform_request &
done

# Wait for all background jobs to finish
wait

echo "Load test completed."