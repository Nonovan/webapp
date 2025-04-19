#!/bin/bash
# Script to update monitoring and alerting for a new active region during disaster recovery failover
# Usage: ./update-monitoring.sh --primary-region [primary|secondary] [--force] [--quiet] [--dr-mode]

set -e

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="/var/log/cloud-platform/monitoring-update.log"
ENV_FILE="${PROJECT_ROOT}/deployment/environments/production.env"
MONITORING_CONFIG_PATH="/etc/monitoring/config"
ALERTING_CONFIG_PATH="/etc/alerting/config"
BACKUP_DIR="/backup/monitoring_alerting"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
NEW_ACTIVE_REGION=""
FORCE=false
QUIET=false
DR_MODE=false

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Load environment variables
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
fi

# Functions
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
    # Also log to stdout if not in quiet mode
    if [[ "${QUIET}" != "true" ]]; then
        echo "[$timestamp] $1"
    fi
}

backup_configs() {
    log "Backing up current configurations..."
    mkdir -p "$BACKUP_DIR"
    cp "$MONITORING_CONFIG_PATH" "$BACKUP_DIR/monitoring_config_$TIMESTAMP" || {
        log "WARNING: Failed to backup monitoring config"
    }
    cp "$ALERTING_CONFIG_PATH" "$BACKUP_DIR/alerting_config_$TIMESTAMP" || {
        log "WARNING: Failed to backup alerting config"
    }
    log "Backup completed: $BACKUP_DIR"
}

update_monitoring() {
    log "Updating monitoring configuration for region: $NEW_ACTIVE_REGION..."
    
    # Determine actual region ID based on primary/secondary designation
    local region_id
    if [[ "$NEW_ACTIVE_REGION" == "primary" ]]; then
        region_id="${PRIMARY_REGION:-us-west-2}"
    else
        region_id="${SECONDARY_REGION:-us-east-1}"
    fi
    
    # Update the configuration file
    if [ -f "$MONITORING_CONFIG_PATH" ]; then
        sed -i.bak "s/active_region=.*/active_region=$region_id/" "$MONITORING_CONFIG_PATH" || {
            log "ERROR: Failed to update monitoring configuration"
            return 1
        }
        log "Monitoring configuration updated to $region_id"
    else
        log "WARNING: Monitoring configuration file not found at $MONITORING_CONFIG_PATH"
        return 1
    fi
    
    return 0
}

update_alerting() {
    log "Updating alerting configuration for region: $NEW_ACTIVE_REGION..."
    
    # Determine actual region ID based on primary/secondary designation
    local region_id
    if [[ "$NEW_ACTIVE_REGION" == "primary" ]]; then
        region_id="${PRIMARY_REGION:-us-west-2}"
    else
        region_id="${SECONDARY_REGION:-us-east-1}"
    fi
    
    # Update the configuration file
    if [ -f "$ALERTING_CONFIG_PATH" ]; then
        sed -i.bak "s/alert_region=.*/alert_region=$region_id/" "$ALERTING_CONFIG_PATH" || {
            log "ERROR: Failed to update alerting configuration"
            return 1
        }
        log "Alerting configuration updated to $region_id"
    else
        log "WARNING: Alerting configuration file not found at $ALERTING_CONFIG_PATH"
        return 1
    fi
    
    # Update alerting thresholds for DR mode if applicable
    if [[ "$DR_MODE" == "true" ]]; then
        log "Adjusting alerting thresholds for DR mode operation"
        if [ -f "$ALERTING_CONFIG_PATH" ]; then
            sed -i "s/cpu_threshold=.*/cpu_threshold=85/" "$ALERTING_CONFIG_PATH"
            sed -i "s/memory_threshold=.*/memory_threshold=90/" "$ALERTING_CONFIG_PATH"
            sed -i "s/disk_threshold=.*/disk_threshold=90/" "$ALERTING_CONFIG_PATH"
            log "Alerting thresholds adjusted for DR operation"
        fi
    fi
    
    return 0
}

reload_services() {
    log "Reloading monitoring and alerting services..."
    
    if command -v systemctl &> /dev/null; then
        systemctl reload monitoring.service || {
            log "WARNING: Failed to reload monitoring service"
        }
        systemctl reload alerting.service || {
            log "WARNING: Failed to reload alerting service"
        }
        log "Services reloaded successfully"
    else
        log "WARNING: systemctl not available, services not reloaded"
        return 1
    fi
    
    return 0
}

update_dashboards() {
    log "Updating monitoring dashboards for new active region..."
    
    # Update Grafana dashboards for the new region
    if [ -x "${PROJECT_ROOT}/scripts/monitoring/update-dashboards.py" ]; then
        python3 "${PROJECT_ROOT}/scripts/monitoring/update-dashboards.py" --region "$NEW_ACTIVE_REGION" || {
            log "WARNING: Failed to update dashboards"
            return 1
        }
        log "Dashboards updated successfully"
    else
        log "WARNING: Dashboard update script not found, skipping dashboard updates"
        return 1
    fi
    
    return 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --primary-region)
            NEW_ACTIVE_REGION="$2"
            shift
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --dr-mode)
            DR_MODE=true
            shift
            ;;
        *)
            log "ERROR: Unknown option: $key"
            echo "Usage: $0 --primary-region [primary|secondary] [--force] [--quiet] [--dr-mode]"
            exit 1
            ;;
    esac
done

# Validate arguments
if [[ -z "$NEW_ACTIVE_REGION" ]]; then
    log "ERROR: Primary region not specified"
    echo "Usage: $0 --primary-region [primary|secondary] [--force] [--quiet] [--dr-mode]"
    exit 1
fi

if [[ "$NEW_ACTIVE_REGION" != "primary" && "$NEW_ACTIVE_REGION" != "secondary" ]]; then
    log "ERROR: Invalid region specified: $NEW_ACTIVE_REGION. Use 'primary' or 'secondary'."
    echo "Usage: $0 --primary-region [primary|secondary] [--force] [--quiet] [--dr-mode]"
    exit 1
fi

# Execute update process
log "Starting monitoring update process for new active region: $NEW_ACTIVE_REGION..."

# Backup existing configs
backup_configs

# Update monitoring and alerting configurations
update_result=0
update_monitoring || update_result=1
update_alerting || update_result=1

# Reload services if update was successful
if [[ $update_result -eq 0 ]]; then
    reload_services
    update_dashboards
    
    # Log the monitoring update event for DR audit trail
    mkdir -p "/var/log/cloud-platform"
    echo "$(date '+%Y-%m-%d %H:%M:%S'),MONITORING_UPDATE,$NEW_ACTIVE_REGION,SUCCESS" >> "/var/log/cloud-platform/dr-events.log"
    
    log "Monitoring and alerting update completed successfully"
    exit 0
else
    log "ERROR: Monitoring and alerting update failed"
    
    if [[ "$FORCE" == "true" ]]; then
        log "Continuing despite failures due to --force flag"
        exit 0
    else
        # Log the monitoring update failure for DR audit trail
        mkdir -p "/var/log/cloud-platform"
        echo "$(date '+%Y-%m-%d %H:%M:%S'),MONITORING_UPDATE,$NEW_ACTIVE_REGION,FAILURE" >> "/var/log/cloud-platform/dr-events.log"
        exit 1
    fi
fi