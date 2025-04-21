#!/bin/bash
# Security Script Permissions Check Tool
# Validates that security scripts in the /scripts/security/ directory have appropriate
# permissions and ownership to prevent unauthorized access or modification
#
# Usage: ./check_permissions.sh [options]

set -e

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SECURITY_DIR="${PROJECT_ROOT}/scripts/security"
LOG_DIR="/var/log/cloud-platform/security"
LOG_FILE="${LOG_DIR}/permissions_check.log"
REPORT_FILE="${LOG_DIR}/permissions_report_$(date +%Y%m%d%H%M%S).txt"
VERBOSE=false
FIX_PERMISSIONS=false
EMAIL_REPORT=false
EMAIL_RECIPIENT=""
EXIT_ON_FAIL=false
EXPECTED_OWNER="root"
EXPECTED_GROUP="root"
SUMMARY_ONLY=false
ISSUES_FOUND=0
TIMESTAMP=$(date +"%Y-%m-%d_%H:%M:%S")
RECURSIVELY_CHECK=false
CHECK_WEB_SCRIPTS=false
WEB_DIR="${PROJECT_ROOT}/static/js"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --fix|-f)
            FIX_PERMISSIONS=true
            shift
            ;;
        --email|-e)
            EMAIL_REPORT=true
            if [[ "$2" != --* && "$2" != "" ]]; then
                EMAIL_RECIPIENT="$2"
                shift
            fi
            shift
            ;;
        --exit-on-fail)
            EXIT_ON_FAIL=true
            shift
            ;;
        --owner)
            EXPECTED_OWNER="$2"
            shift 2
            ;;
        --group)
            EXPECTED_GROUP="$2"
            shift 2
            ;;
        --summary-only)
            SUMMARY_ONLY=true
            shift
            ;;
        --recursive|-r)
            RECURSIVELY_CHECK=true
            shift
            ;;
        --check-web-scripts|-w)
            CHECK_WEB_SCRIPTS=true
            shift
            ;;
        --help|-h)
            echo "Security Script Permissions Check Tool"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v            Enable verbose output"
            echo "  --fix, -f                Automatically fix permissions issues"
            echo "  --email, -e [RECIPIENT]  Email report when complete (default: security admin)"
            echo "  --exit-on-fail           Exit with non-zero code if issues found"
            echo "  --owner OWNER            Expected file owner (default: root)"
            echo "  --group GROUP            Expected file group (default: root)"
            echo "  --summary-only           Only show summary of issues"
            echo "  --recursive, -r          Recursively check subdirectories"
            echo "  --check-web-scripts, -w  Also check web scripts in static/js"
            echo "  --help, -h               Display this help message"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set up logging functions
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local message="[$timestamp] $1"
    local level="${3:-INFO}"
    
    echo "[$level] $message" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" && -n "$2" ]]; then
        echo "  $2" | tee -a "$LOG_FILE"
    fi
}

# Function to check if running as root
check_if_root() {
    if [[ $EUID -ne 0 ]]; then
        if [[ "$FIX_PERMISSIONS" == "true" ]]; then
            log "ERROR: This script must be run as root to fix permissions" "ERROR"
            exit 1
        else
            log "WARNING: Running without root privileges. Cannot fix permissions and some checks may fail" "WARNING"
        fi
    fi
}

# Function to record an issue
record_issue() {
    local file="$1"
    local issue_type="$2"
    local details="$3"
    local recommendation="$4"
    local severity="${5:-HIGH}"
    
    ((ISSUES_FOUND++))
    
    echo "Issue #$ISSUES_FOUND:" >> "$REPORT_FILE"
    echo "  File: $file" >> "$REPORT_FILE"
    echo "  Type: $issue_type" >> "$REPORT_FILE"
    echo "  Severity: $severity" >> "$REPORT_FILE"
    echo "  Details: $details" >> "$REPORT_FILE"
    echo "  Recommendation: $recommendation" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if [[ "$SUMMARY_ONLY" != "true" ]]; then
        log "$issue_type in $file: $details" "$recommendation"
    fi
}

# Check if the security directory exists
check_security_dir() {
    if [[ ! -d "$SECURITY_DIR" ]]; then
        log "ERROR: Security scripts directory not found: $SECURITY_DIR" "ERROR"
        exit 1
    fi
    
    # Check the security directory permissions
    local dir_perms=$(stat -c "%a" "$SECURITY_DIR" 2>/dev/null || stat -f "%Lp" "$SECURITY_DIR" 2>/dev/null)
    local dir_owner=$(stat -c "%U" "$SECURITY_DIR" 2>/dev/null || stat -f "%Su" "$SECURITY_DIR" 2>/dev/null)
    local dir_group=$(stat -c "%G" "$SECURITY_DIR" 2>/dev/null || stat -f "%Sg" "$SECURITY_DIR" 2>/dev/null)
    
    if [[ "$dir_perms" != "750" && "$dir_perms" != "700" ]]; then
        record_issue "$SECURITY_DIR" "Directory Permissions" \
            "Directory has permissions $dir_perms (expected 750 or 700)" \
            "Run: chmod 750 $SECURITY_DIR" \
            "HIGH"
            
        if [[ "$FIX_PERMISSIONS" == "true" ]]; then
            log "Fixing directory permissions on $SECURITY_DIR"
            chmod 750 "$SECURITY_DIR" && log "✅ Fixed permissions on $SECURITY_DIR" || log "❌ Failed to fix permissions on $SECURITY_DIR" "ERROR"
        fi
    fi
    
    if [[ "$dir_owner" != "$EXPECTED_OWNER" ]]; then
        record_issue "$SECURITY_DIR" "Directory Ownership" \
            "Directory owned by $dir_owner (expected $EXPECTED_OWNER)" \
            "Run: chown $EXPECTED_OWNER $SECURITY_DIR" \
            "HIGH"
            
        if [[ "$FIX_PERMISSIONS" == "true" ]]; then
            log "Fixing directory ownership on $SECURITY_DIR"
            chown "$EXPECTED_OWNER" "$SECURITY_DIR" && log "✅ Fixed ownership on $SECURITY_DIR" || log "❌ Failed to fix ownership on $SECURITY_DIR" "ERROR"
        fi
    fi
    
    if [[ "$dir_group" != "$EXPECTED_GROUP" ]]; then
        record_issue "$SECURITY_DIR" "Directory Group" \
            "Directory group is $dir_group (expected $EXPECTED_GROUP)" \
            "Run: chgrp $EXPECTED_GROUP $SECURITY_DIR" \
            "MEDIUM"
            
        if [[ "$FIX_PERMISSIONS" == "true" ]]; then
            log "Fixing directory group on $SECURITY_DIR"
            chgrp "$EXPECTED_GROUP" "$SECURITY_DIR" && log "✅ Fixed group on $SECURITY_DIR" || log "❌ Failed to fix group on $SECURITY_DIR" "ERROR"
        fi
    fi
}

# Check script permissions
check_script_permissions() {
    log "Checking individual script permissions..."
    
    # Start with a clean report file
    echo "Security Script Permissions Check Report" > "$REPORT_FILE"
    echo "Generated: $(date)" >> "$REPORT_FILE"
    echo "Target directory: $SECURITY_DIR" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Find command with recursive option if specified
    local find_cmd="find \"$SECURITY_DIR\" -type f"
    if [[ "$RECURSIVELY_CHECK" != "true" ]]; then
        find_cmd="find \"$SECURITY_DIR\" -maxdepth 1 -type f"
    fi
    
    # Get all scripts (sh, py, rb files) in the security directory
    local scripts=$(eval "$find_cmd" -name "*.sh" -o -name "*.py" -o -name "*.rb" 2>/dev/null | sort)
    local script_count=$(echo "$scripts" | grep -v "^$" | wc -l)
    
    if [[ "$script_count" -eq 0 ]]; then
        log "WARNING: No scripts found in $SECURITY_DIR" "WARNING"
        return
    fi
    
    log "Found $script_count scripts to check"
    
    # Check each script
    while IFS= read -r script; do
        if [[ -z "$script" ]]; then
            continue
        fi
        
        local script_name=$(basename "$script")
        local perms=$(stat -c "%a" "$script" 2>/dev/null || stat -f "%Lp" "$script" 2>/dev/null)
        local owner=$(stat -c "%U" "$script" 2>/dev/null || stat -f "%Su" "$script" 2>/dev/null)
        local group=$(stat -c "%G" "$script" 2>/dev/null || stat -f "%Sg" "$script" 2>/dev/null)
        
        # Check executable flag for shell scripts
        if [[ "$script" == *.sh ]]; then
            if [[ ! -x "$script" ]]; then
                record_issue "$script" "Not Executable" \
                    "Shell script is not executable" \
                    "Run: chmod +x $script" \
                    "MEDIUM"
                    
                if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                    log "Making $script_name executable"
                    chmod +x "$script" && log "✅ Made $script executable" || log "❌ Failed to make $script executable" "ERROR"
                fi
            fi
        fi
        
        # Check permissions
        # Security scripts should be 700 (rwx------) or 750 (rwxr-x---)
        if [[ "$perms" != "700" && "$perms" != "750" && "$perms" != "755" && "$perms" != "500" && "$perms" != "550" ]]; then
            record_issue "$script" "File Permissions" \
                "Script has permissions $perms (expected 700, 750, or 500)" \
                "Run: chmod 750 $script" \
                "HIGH"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing permissions on $script_name"
                chmod 750 "$script" && log "✅ Fixed permissions on $script" || log "❌ Failed to fix permissions on $script" "ERROR"
            fi
        fi
        
        # Check ownership
        if [[ "$owner" != "$EXPECTED_OWNER" ]]; then
            record_issue "$script" "File Ownership" \
                "Script owned by $owner (expected $EXPECTED_OWNER)" \
                "Run: chown $EXPECTED_OWNER $script" \
                "HIGH"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing ownership on $script_name"
                chown "$EXPECTED_OWNER" "$script" && log "✅ Fixed ownership on $script" || log "❌ Failed to fix ownership on $script" "ERROR"
            fi
        fi
        
        # Check group
        if [[ "$group" != "$EXPECTED_GROUP" ]]; then
            record_issue "$script" "File Group" \
                "Script group is $group (expected $EXPECTED_GROUP)" \
                "Run: chgrp $EXPECTED_GROUP $script" \
                "MEDIUM"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing group on $script_name"
                chgrp "$EXPECTED_GROUP" "$script" && log "✅ Fixed group on $script" || log "❌ Failed to fix group on $script" "ERROR"
            fi
        fi
        
        # Check for world-readable/writable scripts
        if [[ "${perms:2:1}" != "0" ]]; then
            record_issue "$script" "World Accessible" \
                "Script is accessible by all users (permissions: $perms)" \
                "Run: chmod o-rwx $script" \
                "HIGH"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Removing world permissions on $script_name"
                chmod o-rwx "$script" && log "✅ Removed world permissions on $script" || log "❌ Failed to remove world permissions on $script" "ERROR"
            fi
        fi
        
        # Additional check for especially sensitive scripts
        if [[ "$script_name" == *password* || "$script_name" == *credential* || "$script_name" == *key* || 
              "$script_name" == *token* || "$script_name" == *secret* || "$script_name" == *auth* ]]; then
            # Sensitive scripts should be 700 (rwx------)
            if [[ "$perms" != "700" && "$perms" != "500" ]]; then
                record_issue "$script" "Sensitive Script Permissions" \
                    "Sensitive script has permissions $perms (expected 700 or 500)" \
                    "Run: chmod 700 $script" \
                    "CRITICAL"
                    
                if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                    log "Setting strict permissions on sensitive script $script_name"
                    chmod 700 "$script" && log "✅ Set strict permissions on $script" || log "❌ Failed to set strict permissions on $script" "ERROR"
                fi
            fi
        fi
        
        # Check script content for hardcoded secrets
        if [[ "$VERBOSE" == "true" ]]; then
            if grep -q -E '(password|secret|token|key|credential).*=.*[^$]' "$script" 2>/dev/null; then
                record_issue "$script" "Potential Hardcoded Secret" \
                    "Script may contain hardcoded credentials" \
                    "Review script content and externalize secrets" \
                    "CRITICAL"
            fi
        fi
        
    done <<< "$scripts"
    
    # Check for non-script files that may need attention
    log "Checking for other files that may need attention..."
    local other_files=$(eval "$find_cmd" -not -name "*.sh" -not -name "*.py" -not -name "*.rb" -not -name "README*" -not -name "*.md" 2>/dev/null | sort)
    
    while IFS= read -r file; do
        if [[ -z "$file" ]]; then
            continue
        fi
        
        local file_name=$(basename "$file")
        local perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Lp" "$file" 2>/dev/null)
        local owner=$(stat -c "%U" "$file" 2>/dev/null || stat -f "%Su" "$file" 2>/dev/null)
        local group=$(stat -c "%G" "$file" 2>/dev/null || stat -f "%Sg" "$file" 2>/dev/null)
        
        # Configuration files, key files, etc. should be 600 or 640
        if [[ "$perms" != "600" && "$perms" != "640" && "$perms" != "400" && "$perms" != "440" ]]; then
            record_issue "$file" "Non-Script File Permissions" \
                "File has permissions $perms (expected 600 or 640 for config files)" \
                "Run: chmod 640 $file" \
                "MEDIUM"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Setting appropriate permissions on file $file_name"
                chmod 640 "$file" && log "✅ Set correct permissions on $file" || log "❌ Failed to set permissions on $file" "ERROR"
            fi
        fi
        
        # Check ownership
        if [[ "$owner" != "$EXPECTED_OWNER" ]]; then
            record_issue "$file" "File Ownership" \
                "File owned by $owner (expected $EXPECTED_OWNER)" \
                "Run: chown $EXPECTED_OWNER $file" \
                "MEDIUM"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing ownership on $file_name"
                chown "$EXPECTED_OWNER" "$file" && log "✅ Fixed ownership on $file" || log "❌ Failed to fix ownership on $file" "ERROR"
            fi
        fi
        
        # Check for world-readable/writable files
        if [[ "${perms:2:1}" != "0" ]]; then
            record_issue "$file" "World Accessible" \
                "File is accessible by all users (permissions: $perms)" \
                "Run: chmod o-rwx $file" \
                "HIGH"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Removing world permissions on $file_name"
                chmod o-rwx "$file" && log "✅ Removed world permissions on $file" || log "❌ Failed to remove world permissions on $file" "ERROR"
            fi
        fi
        
        # Special checks for sensitive files
        if [[ "$file_name" == *password* || "$file_name" == *key* || "$file_name" == *secret* || 
              "$file_name" == *token* || "$file_name" == *credential* || "$file_name" == *.pem || 
              "$file_name" == *.key || "$file_name" == *.crt ]]; then
            if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                record_issue "$file" "Sensitive File Permissions" \
                    "Sensitive file has permissions $perms (expected 600 or 400)" \
                    "Run: chmod 600 $file" \
                    "CRITICAL"
                    
                if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                    log "Setting strict permissions on sensitive file $file_name"
                    chmod 600 "$file" && log "✅ Set strict permissions on $file" || log "❌ Failed to set strict permissions on $file" "ERROR"
                fi
            fi
        fi
        
    done <<< "$other_files"
}

# Check web scripts if requested
check_web_scripts() {
    if [[ "$CHECK_WEB_SCRIPTS" != "true" ]]; then
        return
    fi
    
    if [[ ! -d "$WEB_DIR" ]]; then
        log "WARNING: Web scripts directory not found: $WEB_DIR" "WARNING"
        return
    }
    
    log "Checking web scripts in $WEB_DIR"
    
    # Web scripts should be readable by www-data or nginx user but not writable
    local web_expected_perms="644"
    local web_expected_owner="root"  # Or specific web user
    local web_expected_group="www-data"  # Or nginx/apache group
    
    local web_files=$(find "$WEB_DIR" -type f -name "*.js" 2>/dev/null | sort)
    local web_count=$(echo "$web_files" | grep -v "^$" | wc -l)
    
    if [[ "$web_count" -eq 0 ]]; then
        log "No web scripts found in $WEB_DIR" "WARNING"
        return
    }
    
    log "Found $web_count web scripts to check"
    
    while IFS= read -r script; do
        if [[ -z "$script" ]]; then
            continue
        fi
        
        local script_name=$(basename "$script")
        local perms=$(stat -c "%a" "$script" 2>/dev/null || stat -f "%Lp" "$script" 2>/dev/null)
        local owner=$(stat -c "%U" "$script" 2>/dev/null || stat -f "%Su" "$script" 2>/dev/null)
        local group=$(stat -c "%G" "$script" 2>/dev/null || stat -f "%Sg" "$script" 2>/dev/null)
        
        # Web scripts should be 644 (rw-r--r--)
        if [[ "$perms" != "644" && "$perms" != "444" ]]; then
            record_issue "$script" "Web Script Permissions" \
                "Web script has permissions $perms (expected 644 or 444)" \
                "Run: chmod 644 $script" \
                "MEDIUM"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing permissions on web script $script_name"
                chmod 644 "$script" && log "✅ Fixed permissions on $script" || log "❌ Failed to fix permissions on $script" "ERROR"
            fi
        fi
        
        # Check ownership
        if [[ "$owner" != "$web_expected_owner" ]]; then
            record_issue "$script" "Web Script Ownership" \
                "Web script owned by $owner (expected $web_expected_owner)" \
                "Run: chown $web_expected_owner $script" \
                "LOW"
                
            if [[ "$FIX_PERMISSIONS" == "true" ]]; then
                log "Fixing ownership on web script $script_name"
                chown "$web_expected_owner" "$script" && log "✅ Fixed ownership on $script" || log "❌ Failed to fix ownership on $script" "ERROR"
            fi
        fi
    done <<< "$web_files"
}

# Check for suspicious scripts or modifications
check_for_suspicious_scripts() {
    log "Checking for potentially suspicious scripts or modifications..."
    
    # Find command with recursive option if specified
    local find_cmd="find \"$SECURITY_DIR\" -type f"
    if [[ "$RECURSIVELY_CHECK" != "true" ]]; then
        find_cmd="find \"$SECURITY_DIR\" -maxdepth 1 -type f"
    fi
    
    # Check for recently modified files
    local recent_files=$(eval "$find_cmd" -mtime -7 2>/dev/null | sort)
    local recent_count=$(echo "$recent_files" | grep -v "^$" | wc -l)
    
    if [[ "$recent_count" -gt 0 ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Recently Modified Files (last 7 days):" >> "$REPORT_FILE"
        while IFS= read -r file; do
            if [[ -z "$file" ]]; then
                continue
            fi
            
            local mod_time=$(stat -c "%y" "$file" 2>/dev/null || stat -f "%Sm" "$file" 2>/dev/null)
            echo "  $(basename "$file") - Modified: $mod_time" >> "$REPORT_FILE"
            
        done <<< "$recent_files"
        
        log "Found $recent_count recently modified files"
    fi
    
    # Check for files with unusual patterns or names
    local suspicious_patterns=("backdoor" "hack" "exploit" "rootkit" "malware" "payload" "reverse_shell" "connect-back")
    local suspicious_files=""
    
    for pattern in "${suspicious_patterns[@]}"; do
        local matches=$(eval "$find_cmd" -name "*$pattern*" 2>/dev/null)
        if [[ -n "$matches" ]]; then
            suspicious_files+="$matches"$'\n'
        fi
    done
    
    # Remove trailing newline and check if any suspicious files were found
    suspicious_files=$(echo "$suspicious_files" | sed '/^$/d')
    
    if [[ -n "$suspicious_files" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Potentially Suspicious Files:" >> "$REPORT_FILE"
        echo "$suspicious_files" >> "$REPORT_FILE"
        
        record_issue "$SECURITY_DIR" "Suspicious Files" \
            "Files with suspicious names found in security directory" \
            "Review these files for legitimacy" \
            "CRITICAL"
    fi
    
    # Check for unusual file types in the security directory
    local unusual_files=$(eval "$find_cmd" -name "*.exe" -o -name "*.dll" -o -name "*.bin" -o -name "*.dat" 2>/dev/null | sort)
    
    if [[ -n "$unusual_files" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Unusual File Types:" >> "$REPORT_FILE"
        echo "$unusual_files" >> "$REPORT_FILE"
        
        record_issue "$SECURITY_DIR" "Unusual File Types" \
            "Unusual file types found in security directory" \
            "Review these files for legitimacy" \
            "HIGH"
    fi
    
    # Check for files with SUID/SGID bit set
    local privileged_files=$(eval "$find_cmd" \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
    
    if [[ -n "$privileged_files" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Files with SUID/SGID bit set:" >> "$REPORT_FILE"
        echo "$privileged_files" >> "$REPORT_FILE"
        
        record_issue "$SECURITY_DIR" "Privileged Files" \
            "Files with SUID/SGID bit set in security directory" \
            "Review these files and remove SUID/SGID if not required" \
            "CRITICAL"
            
        if [[ "$FIX_PERMISSIONS" == "true" ]]; then
            log "Removing SUID/SGID bits from files"
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    chmod -s "$file" && log "✅ Removed SUID/SGID from $file" || log "❌ Failed to remove SUID/SGID from $file" "ERROR"
                fi
            done <<< "$privileged_files"
        fi
    fi
    
    # Check for hidden files
    local hidden_files=$(eval "$find_cmd" -name ".*" -not -name "." -not -name ".." 2>/dev/null | sort)
    
    if [[ -n "$hidden_files" ]]; then
        echo "" >> "$REPORT_FILE"
        echo "Hidden Files:" >> "$REPORT_FILE"
        echo "$hidden_files" >> "$REPORT_FILE"
        
        record_issue "$SECURITY_DIR" "Hidden Files" \
            "Hidden files found in security directory" \
            "Review these files for legitimacy" \
            "MEDIUM"
    fi
}

# Function to verify script integrity
verify_script_integrity() {
    if [[ -x "${PROJECT_ROOT}/scripts/security/verify_files.py" ]]; then
        log "Verifying script integrity..."
        
        # First check if the verification script itself is trustworthy
        local verifier="${PROJECT_ROOT}/scripts/security/verify_files.py"
        local verifier_perms=$(stat -c "%a" "$verifier" 2>/dev/null || stat -f "%Lp" "$verifier" 2>/dev/null)
        local verifier_owner=$(stat -c "%U" "$verifier" 2>/dev/null || stat -f "%Su" "$verifier" 2>/dev/null)
        
        if [[ "$verifier_perms" != "700" && "$verifier_perms" != "750" && "$verifier_owner" != "$EXPECTED_OWNER" ]]; then
            record_issue "$verifier" "Integrity Checker Permissions" \
                "Integrity verification script has incorrect permissions/ownership" \
                "Run: chmod 750 $verifier && chown $EXPECTED_OWNER $verifier" \
                "CRITICAL"
            return
        fi
        
        # Run the verification script
        python3 "$verifier" --directory "$SECURITY_DIR" --report integrity_report.json 2>/dev/null
        
        if [[ $? -ne 0 || ! -f "integrity_report.json" ]]; then
            record_issue "$SECURITY_DIR" "Integrity Verification" \
                "Failed to verify script integrity" \
                "Check the integrity verification script" \
                "HIGH"
        else
            # Check if any integrity issues were found
            local issues=$(grep -c "\"status\": \"failed\"" integrity_report.json 2>/dev/null || echo "0")
            
            if [[ "$issues" -gt 0 ]]; then
                record_issue "$SECURITY_DIR" "Integrity Issues" \
                    "$issues integrity issues found in security scripts" \
                    "Review integrity_report.json for details" \
                    "CRITICAL"
                
                # Append the integrity report to our report
                echo "" >> "$REPORT_FILE"
                echo "Script Integrity Issues:" >> "$REPORT_FILE"
                grep -A 3 "\"status\": \"failed\"" integrity_report.json >> "$REPORT_FILE"
            else
                log "Script integrity verification completed successfully. No issues found."
            fi
            
            # Clean up
            rm -f integrity_report.json
        fi
    fi
}

# Function to generate summary
generate_summary() {
    # Calculate counts by severity
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    
    # Count issues by severity
    if [[ -f "$REPORT_FILE" ]]; then
        critical_count=$(grep -c "Severity: CRITICAL" "$REPORT_FILE")
        high_count=$(grep -c "Severity: HIGH" "$REPORT_FILE")
        medium_count=$(grep -c "Severity: MEDIUM" "$REPORT_FILE")
        low_count=$(grep -c "Severity: LOW" "$REPORT_FILE")
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "SUMMARY" >> "$REPORT_FILE"
    echo "=======" >> "$REPORT_FILE"
    echo "Total issues found: $ISSUES_FOUND" >> "$REPORT_FILE"
    echo "  - Critical: $critical_count" >> "$REPORT_FILE"
    echo "  - High: $high_count" >> "$REPORT_FILE"
    echo "  - Medium: $medium_count" >> "$REPORT_FILE"
    echo "  - Low: $low_count" >> "$REPORT_FILE"
    echo "Check executed: $(date)" >> "$REPORT_FILE"
    
    if [[ "$FIX_PERMISSIONS" == "true" ]]; then
        echo "Permissions were automatically fixed" >> "$REPORT_FILE"
    else
        echo "Permissions were NOT automatically fixed" >> "$REPORT_FILE"
    fi
    
    if [[ "$ISSUES_FOUND" -eq 0 ]]; then
        log "SUCCESS: No permission issues found in security scripts"
        echo "No permission issues found in security scripts" >> "$REPORT_FILE"
    else
        log "ALERT: Found $ISSUES_FOUND permission issues in security scripts ($critical_count critical, $high_count high)"
        
        # If there are critical issues, highlight them
        if [[ "$critical_count" -gt 0 ]]; then
            log "CRITICAL ISSUES FOUND: $critical_count critical security issues require immediate attention!" "ERROR"
        fi
    fi
}

# Email report if requested
email_report() {
    if [[ "$EMAIL_REPORT" == "true" ]]; then
        if [[ -z "$EMAIL_RECIPIENT" ]]; then
            EMAIL_RECIPIENT="security-admin@$(hostname -d 2>/dev/null || echo "example.com")"
            log "No email recipient specified, sending to $EMAIL_RECIPIENT"
        fi
        
        log "Sending report by email to $EMAIL_RECIPIENT"
        
        local email_subject="Security Scripts Permission Check - ${ISSUES_FOUND} Issues Found"
        
        # Add severity to subject line if critical issues exist
        if grep -q "Severity: CRITICAL" "$REPORT_FILE" 2>/dev/null; then
            email_subject="[CRITICAL] $email_subject"
        elif grep -q "Severity: HIGH" "$REPORT_FILE" 2>/dev/null; then
            email_subject="[HIGH] $email_subject"
        fi
        
        if command -v mail > /dev/null; then
            mail -s "$email_subject" "$EMAIL_RECIPIENT" < "$REPORT_FILE"
            log "Email sent to $EMAIL_RECIPIENT"
        else
            log "WARNING: 'mail' command not found. Email not sent." "WARNING"
        fi
    fi
}

# Main function
main() {
    log "Starting security scripts permission check..."
    
    # Check if running as root for permission fixes
    check_if_root
    
    # Check the security directory
    check_security_dir
    
    # Check individual script permissions
    check_script_permissions
    
    # Check web scripts if requested
    check_web_scripts
    
    # Check for suspicious scripts
    check_for_suspicious_scripts
    
    # Verify script integrity
    verify_script_integrity
    
    # Generate summary
    generate_summary
    
    # Email report if requested
    email_report
    
    log "Permission check complete. Full report available at: $REPORT_FILE"
    
    # Return appropriate exit code
    if [[ "$EXIT_ON_FAIL" == "true" && "$ISSUES_FOUND" -gt 0 ]]; then
        exit 1
    fi
    
    exit 0
}

# Run the script
main