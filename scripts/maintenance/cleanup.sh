#!/bin/bash

# Maintenance Script: General System Cleanup
# Author: Your Name
# Date: $(date)

# Exit immediately if a command exits with a non-zero status
set -e

echo "Starting system cleanup..."

# 1. Remove unused packages
echo "Removing unused packages..."
sudo apt-get autoremove -y

# 2. Clean up package cache
echo "Cleaning up package cache..."
sudo apt-get clean

# 3. Remove old log files
LOG_DIR="/var/log"
echo "Removing old log files in $LOG_DIR..."
find $LOG_DIR -type f -name "*.log" -mtime +7 -exec rm -f {} \;

# 4. Clear temporary files
TEMP_DIR="/tmp"
echo "Clearing temporary files in $TEMP_DIR..."
find $TEMP_DIR -type f -mtime +1 -exec rm -f {} \;

# 5. Free up disk space by clearing user cache
USER_CACHE_DIR="$HOME/.cache"
echo "Clearing user cache in $USER_CACHE_DIR..."
rm -rf $USER_CACHE_DIR/*

# 6. Check disk usage
echo "Disk usage after cleanup:"
df -h

echo "System cleanup completed successfully!"