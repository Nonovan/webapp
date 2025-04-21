#!/bin/bash
# Security Updates Application Script for Cloud Infrastructure Platform
# Applies pending security updates with configurable options for scheduling, notifications, and rollback
# Usage: ./apply_security_updates.sh [--environment <env>] [--dry-run] [--notify <email>] [--rollback-plan]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
ENVIRONMENT="production"
DRY_RUN=false
ROLLBACK_PLAN=false
NOTIFY=false
EMAIL_RECIPIENT=""
QUIET=false
LOG_DIR="/var/log/cloud-platform"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
LOG_FILE="${LOG_DIR}/security-updates-${TIMESTAMP}.log"
BACKUP_DIR="/var/backups/cloud-platform/security-updates"
EXIT_CODE=0

# Ensure directories exist
mkdir -p "$LOG_DIR"
mkdir -p "$BACKUP_DIR"

# Function to log messages
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    
    if [[ "$QUIET" != "true" ]]; then
        echo "$message"
    fi
    
    echo "$message" >> "$LOG_FILE"
}

# Function to display usage
usage() {
    cat <<EOF
Security Updates Application Script for Cloud Infrastructure Platform

Usage: $0 [options]

Options:
  --environment, -e ENV     Specify environment (default: production)
  --dry-run, -d             Check updates without applying them
  --rollback-plan, -r       Create rollback plan before updating
  --notify, -n [EMAIL]      Send notification with results
  --quiet, -q               Minimal output
  --help, -h                Show this help message
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --dry-run|-d)
            DRY_RUN=true
            shift
            ;;
        --rollback-plan|-r)
            ROLLBACK_PLAN=true
            shift
            ;;
        --notify|-n)
            NOTIFY=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Load environment-specific variables
ENV_FILE="${PROJECT_ROOT}/deployment/environments/${ENVIRONMENT}.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    log "Loaded environment configuration from $ENV_FILE"
else
    log "WARNING: Environment file $ENV_FILE not found, using defaults"
fi

# Email notification function
send_notification() {
    local subject="$1"
    local message="$2"
    local attachment="$3"
    
    if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
        if [[ -x "${PROJECT_ROOT}/scripts/utils/send-notification.sh" ]]; then
            "${PROJECT_ROOT}/scripts/utils/send-notification.sh" \
                --priority "high" \
                --subject "$subject" \
                --message "$message" \
                --recipient "$EMAIL_RECIPIENT" \
                ${attachment:+--attachment "$attachment"}
            log "Notification sent to $EMAIL_RECIPIENT"
        elif command -v mail &>/dev/null; then
            echo "$message" | mail -s "$subject" ${attachment:+-a "$attachment"} "$EMAIL_RECIPIENT"
            log "Notification sent to $EMAIL_RECIPIENT using mail command"
        else
            log "WARNING: Could not send notification, notification tools not available"
        fi
    fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log "ERROR: This script must be run as root"
    exit 1
fi

log "Starting security updates for ${ENVIRONMENT} environment"

# Detect package manager and system type
if command -v apt-get &>/dev/null; then
    PACKAGE_MANAGER="apt"
    log "Detected Debian/Ubuntu system using apt"
elif command -v dnf &>/dev/null; then
    PACKAGE_MANAGER="dnf"
    log "Detected Fedora/RHEL system using dnf"
elif command -v yum &>/dev/null; then
    PACKAGE_MANAGER="yum"
    log "Detected RHEL/CentOS system using yum"
else
    log "ERROR: Unsupported system. Could not find apt-get, yum, or dnf."
    exit 1
fi

# Function to check for and list available security updates
check_security_updates() {
    log "Checking for available security updates..."
    
    local security_updates_list="/tmp/security-updates-${TIMESTAMP}.list"
    local security_updates_count=0
    
    case $PACKAGE_MANAGER in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            # Update package lists
            apt-get update -qq || {
                log "ERROR: Failed to update package lists"
                exit 1
            }
            
            # List security updates
            apt-get --just-print upgrade | grep -i security > "$security_updates_list" || true
            security_updates_count=$(grep -c "^Inst.*security" "$security_updates_list" || echo "0")
            
            # Check for critical packages
            local critical_updates=0
            for pkg in openssl openssh-server nginx linux-image postgresql apache2; do
                if grep -q "$pkg" "$security_updates_list"; then
                    log "CRITICAL: Update available for $pkg"
                    ((critical_updates++))
                fi
            done
            
            if [[ $critical_updates -gt 0 ]]; then
                log "ATTENTION: $critical_updates critical security updates found"
            fi
            ;;
            
        yum|dnf)
            # Check for security updates
            "$PACKAGE_MANAGER" check-update --security > "$security_updates_list" 2>/dev/null || true
            
            # Count security updates (exit code 100 means updates available)
            if [[ -s "$security_updates_list" ]]; then
                security_updates_count=$(grep -c -v "^$\|^Loaded" "$security_updates_list" || echo "0")
            fi
            
            # Check for critical packages
            local critical_updates=0
            for pkg in openssl openssh kernel nginx postgresql httpd; do
                if grep -q "$pkg" "$security_updates_list"; then
                    log "CRITICAL: Update available for $pkg"
                    ((critical_updates++))
                fi
            done
            
            if [[ $critical_updates -gt 0 ]]; then
                log "ATTENTION: $critical_updates critical security updates found"
            fi
            ;;
    esac
    
    log "Found $security_updates_count security updates"
    echo "$security_updates_count"
}

# Function to create pre-update system snapshot
create_system_snapshot() {
    log "Creating system snapshot before updates..."
    local snapshot_file="${BACKUP_DIR}/system-snapshot-${TIMESTAMP}.tar.gz"
    
    # Create a list of installed packages
    case $PACKAGE_MANAGER in
        apt)
            dpkg --get-selections > "${BACKUP_DIR}/packages-${TIMESTAMP}.list"
            ;;
        yum|dnf)
            "$PACKAGE_MANAGER" list installed > "${BACKUP_DIR}/packages-${TIMESTAMP}.list"
            ;;
    esac
    
    # Backup important configuration files
    log "Backing up important configuration files..."
    
    local config_dirs=(
        "/etc/nginx"
        "/etc/apache2"
        "/etc/httpd"
        "/etc/postgresql"
        "/etc/mysql"
        "/etc/ssh"
        "/etc/cloud-platform"
        "/etc/systemd/system"
    )
    
    # Create snapshot tarball
    tar -czf "$snapshot_file" --ignore-failed-read \
        "${BACKUP_DIR}/packages-${TIMESTAMP}.list" \
        /etc/passwd /etc/group /etc/shadow /etc/gshadow \
        /etc/fstab /etc/hosts /etc/resolv.conf \
        "${config_dirs[@]}" 2>/dev/null || true
    
    log "System snapshot created: $snapshot_file"
}

# Function to create rollback plan
create_rollback_plan() {
    log "Creating rollback plan..."
    local rollback_file="${BACKUP_DIR}/rollback-plan-${TIMESTAMP}.sh"
    
    # Create rollback script header
    cat > "$rollback_file" <<EOF
#!/bin/bash
# Rollback plan for security updates applied on $(date)
# WARNING: Use only in case of system issues after updates

set -e

echo "Starting rollback of security updates from ${TIMESTAMP}..."

# Restore from snapshot
echo "Restoring configuration files from snapshot..."
tar -xzf "${BACKUP_DIR}/system-snapshot-${TIMESTAMP}.tar.gz" -C / 2>/dev/null || {
    echo "WARNING: Error restoring some files from snapshot"
}

# Package-specific rollback instructions
EOF
    
    # Add package manager specific rollback commands
    case $PACKAGE_MANAGER in
        apt)
            cat >> "$rollback_file" <<EOF
# If needed, downgrade specific packages:
# apt-get install --allow-downgrades <package>=<version>

# To downgrade all updated packages, you will need the specific versions.
# Check the package diff file: ${BACKUP_DIR}/packages-diff-${TIMESTAMP}.list

# Packages that were updated:
cat "${BACKUP_DIR}/packages-diff-${TIMESTAMP}.list" 2>/dev/null || echo "Package diff file not found"

# If system won't boot:
# 1. Boot into recovery mode
# 2. Mount filesystem as read-write: mount -o remount,rw /
# 3. Run this script

# Restart affected services
systemctl daemon-reload
for service in ssh nginx apache2 postgresql mysql redis; do
    if systemctl is-enabled \$service &>/dev/null; then
        echo "Restarting \$service..."
        systemctl restart \$service || echo "WARNING: Failed to restart \$service"
    fi
done
EOF
            ;;
        yum|dnf)
            cat >> "$rollback_file" <<EOF
# For RHEL/CentOS systems, use yum history to rollback
# Run this to see update transaction ID:
$PACKAGE_MANAGER history | grep "${TIMESTAMP:0:8}"
# 
# Then run:
# $PACKAGE_MANAGER history undo <ID>

# Packages that were updated:
cat "${BACKUP_DIR}/packages-diff-${TIMESTAMP}.list" 2>/dev/null || echo "Package diff file not found"

# If system won't boot:
# 1. Boot into rescue mode
# 2. Mount filesystem: chroot /mnt/sysimage
# 3. Run the rollback: $PACKAGE_MANAGER history undo <ID>

# Restart affected services
systemctl daemon-reload
for service in sshd nginx httpd postgresql mariadb redis; do
    if systemctl is-enabled \$service &>/dev/null; then
        echo "Restarting \$service..."
        systemctl restart \$service || echo "WARNING: Failed to restart \$service"
    fi
done
EOF
            ;;
    esac
    
    # Make the rollback script executable
    chmod +x "$rollback_file"
    log "Rollback plan created: $rollback_file"
    
    return 0
}

# Function to apply security updates
apply_security_updates() {
    if [[ "$DRY_RUN" = true ]]; then
        log "DRY RUN: Would apply security updates now, but skipping due to --dry-run flag"
        return 0
    fi
    
    log "Applying security updates..."
    local update_output="${BACKUP_DIR}/update-output-${TIMESTAMP}.log"
    
    case $PACKAGE_MANAGER in
        apt)
            # Set noninteractive mode to avoid prompts
            export DEBIAN_FRONTEND=noninteractive
            
            # Log current package versions for potential rollback
            dpkg -l > "${BACKUP_DIR}/packages-before-${TIMESTAMP}.list"
            
            # Apply only security updates
            apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
                upgrade -t "$(lsb_release -cs)-security" > "$update_output" 2>&1 || {
                log "ERROR: Security update failed. Check $update_output for details"
                EXIT_CODE=1
                return 1
            }
            
            # Log updated packages
            dpkg -l > "${BACKUP_DIR}/packages-after-${TIMESTAMP}.list"
            ;;
            
        yum|dnf)
            # Log current package versions
            "$PACKAGE_MANAGER" list installed > "${BACKUP_DIR}/packages-before-${TIMESTAMP}.list"
            
            # Apply only security updates
            "$PACKAGE_MANAGER" -y update --security > "$update_output" 2>&1 || {
                log "ERROR: Security update failed. Check $update_output for details"
                EXIT_CODE=1
                return 1
            }
            
            # Log updated packages
            "$PACKAGE_MANAGER" list installed > "${BACKUP_DIR}/packages-after-${TIMESTAMP}.list"
            ;;
    esac
    
    # Create diff of packages before and after
    diff "${BACKUP_DIR}/packages-before-${TIMESTAMP}.list" "${BACKUP_DIR}/packages-after-${TIMESTAMP}.list" | \
        grep -E "^[<>]" > "${BACKUP_DIR}/packages-diff-${TIMESTAMP}.list" 2>/dev/null || true
    
    log "Security updates applied successfully"
    return 0
}

# Function to perform post-update verification
verify_system() {
    log "Performing post-update system verification..."
    local verification_output="${BACKUP_DIR}/verification-${TIMESTAMP}.log"
    local services=(ssh sshd nginx apache2 httpd postgresql mysql mariadb mongod redis docker)
    
    # Check if important services are running
    for service in "${services[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            if systemctl is-active "$service" &>/dev/null; then
                log "✅ Service $service is running"
            else
                log "⚠️ WARNING: Service $service is not running"
                systemctl status "$service" >> "$verification_output" 2>&1 || true
                EXIT_CODE=1
            fi
        fi
    done
    
    # Check system load
    local load
    load=$(uptime | awk -F'[a-z]:' '{print $2}' | xargs)
    log "System load: $load"
    
    # Check disk space
    log "Disk space usage:"
    df -h / | tail -n 1 | tee -a "$verification_output"
    
    # Run security-audit if available
    if [[ -x "${PROJECT_ROOT}/scripts/security/security_audit.py" ]]; then
        log "Running security audit..."
        python3 "${PROJECT_ROOT}/scripts/security/security_audit.py" --updates-only >> "$verification_output" 2>&1 || true
    elif [[ -x "${PROJECT_ROOT}/scripts/security/security-audit.sh" ]]; then
        log "Running security audit..."
        "${PROJECT_ROOT}/scripts/security/security-audit.sh" --updates-only >> "$verification_output" 2>&1 || true
    elif [[ -x "${PROJECT_ROOT}/deployment/security/security-audit.sh" ]]; then
        log "Running security audit..."
        "${PROJECT_ROOT}/deployment/security/security-audit.sh" --updates-only >> "$verification_output" 2>&1 || true
    fi
    
    log "Verification details saved to $verification_output"
    return 0
}

# Function to clean up old backup files
cleanup_old_backups() {
    log "Cleaning up old backup files..."
    
    # Find and remove backups older than 30 days
    find "$BACKUP_DIR" -name "system-snapshot-*.tar.gz" -type f -mtime +30 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "packages-*.list" -type f -mtime +30 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "update-output-*.log" -type f -mtime +30 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "rollback-plan-*.sh" -type f -mtime +30 -delete 2>/dev/null || true
    find "$BACKUP_DIR" -name "verification-*.log" -type f -mtime +30 -delete 2>/dev/null || true
    
    log "Cleanup complete"
}

# Main execution flow
security_updates=$(check_security_updates)

if [[ $security_updates -eq 0 ]]; then
    log "No security updates available. Exiting."
    if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
        send_notification \
            "No Security Updates Required - ${ENVIRONMENT}" \
            "No security updates are currently available for ${ENVIRONMENT} environment.\n\nTimestamp: $(date)" \
            ""
    fi
    exit 0
fi

# Create system snapshot
create_system_snapshot

# Create rollback plan if requested
if [[ "$ROLLBACK_PLAN" = true ]]; then
    create_rollback_plan
fi

# Apply security updates
apply_security_updates
update_status=$?

if [[ $update_status -ne 0 ]]; then
    log "ERROR: Security updates failed to apply"
    send_notification \
        "FAILED: Security Updates on ${ENVIRONMENT}" \
        "Security updates failed to apply on ${ENVIRONMENT} environment.\n\nPlease check the logs at $LOG_FILE for details.\n\nTimestamp: $(date)" \
        "$LOG_FILE"
    exit 1
fi

# Verify system after updates
verify_system

# Clean up old backups
cleanup_old_backups

# Send notification about the update result
if [[ "$NOTIFY" = true && -n "$EMAIL_RECIPIENT" ]]; then
    local status_msg="Successful"
    if [[ $EXIT_CODE -ne 0 ]]; then
        status_msg="Completed with warnings"
    fi
    
    send_notification \
        "${status_msg}: Security Updates on ${ENVIRONMENT}" \
        "Security updates have been applied to the ${ENVIRONMENT} environment.\n\nTotal updates applied: ${security_updates}\nStatus: ${status_msg}\n\nTimestamp: $(date)" \
        "$LOG_FILE"
fi

log "Security updates process completed with exit code: $EXIT_CODE"
exit $EXIT_CODE