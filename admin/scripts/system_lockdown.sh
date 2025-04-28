#!/bin/bash
# System Security Lockdown Script for Cloud Infrastructure Platform
# Applies security hardening configurations based on defined levels or policies.
#
# Usage: ./system_lockdown.sh [--environment <env>] [--security-level <level>] [--component <name>] [--apply-policy <policy>] [--verify] [--policy-file <file>] [--force] [--help]
#
# Examples:
#   # Apply high security level lockdown in production
#   ./system_lockdown.sh --environment production --security-level high
#
#   # Apply specific policy to the authentication component
#   ./system_lockdown.sh --component authentication --apply-policy strict-mfa
#
#   # Verify current configuration against a baseline policy file
#   ./system_lockdown.sh --verify --policy-file security-baseline.json

set -euo pipefail

# Default settings
ENVIRONMENT="production"
SECURITY_LEVEL="high" # Default level if none specified
COMPONENT=""
APPLY_POLICY=""
VERIFY_MODE=false
POLICY_FILE=""
FORCE_MODE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_DIR="/var/log/cloud-platform/admin"
LOG_FILE="${LOG_DIR}/system_lockdown_$(date +%Y%m%d%H%M%S).log"
BACKUP_DIR="/var/backups/cloud-platform/lockdown"
HARDENING_PROFILES_DIR="${PROJECT_ROOT}/admin/security/incident_response_kit/recovery/resources/hardening_profiles" # Example path
BASELINE_DIR="${PROJECT_ROOT}/admin/security/assessment_tools/config_files/security_baselines" # Example path
DEPLOYMENT_SECURITY_CONFIG="${PROJECT_ROOT}/deployment/security/config"
DEPLOYMENT_SECURITY_SCRIPTS="${PROJECT_ROOT}/deployment/security/scripts"

# Ensure directories exist
mkdir -p "$LOG_DIR"
mkdir -p "$BACKUP_DIR"

# --- Logging Functions ---
log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$1] $2" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "$1"
}

warn() {
    log "WARN" "$1"
}

error() {
    log "ERROR" "$1"
    exit 1
}

# --- Helper Functions ---

usage() {
    cat <<EOF
System Security Lockdown Script

Applies or verifies security hardening configurations.

Usage: $0 [options]

Options:
  --environment <env>     Target environment (default: production).
  --security-level <level> Apply a predefined security level (e.g., baseline, medium, high, critical). Default: high.
  --component <name>      Target a specific system component (e.g., ssh, kernel, authentication, network, filesystem).
  --apply-policy <policy> Apply a specific named policy (requires --component).
  --verify                Verify current configuration against the specified level or policy file.
  --policy-file <file>    Path to a custom policy file (JSON format) for applying or verifying. Overrides level/component. Requires 'jq'.
  --force                 Apply changes without confirmation prompts (use with caution).
  --help                  Show this help message.
EOF
    exit 0
}

confirm_action() {
    if [[ "$FORCE_MODE" == "true" ]]; then
        return 0 # Skip confirmation
    fi
    read -p "$1 [y/N]: " -n 1 -r
    echo # Move to a new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        info "Operation cancelled by user."
        exit 0
    fi
}

backup_config_file() {
    local file_path="$1"
    if [[ -z "$file_path" || ! -e "$file_path" ]]; then # Check if exists (file or dir)
        warn "Cannot back up '$file_path': Path does not exist or is empty."
        return 1
    fi
    local backup_path="${BACKUP_DIR}/$(basename "$file_path").$(date +%Y%m%d%H%M%S).bak"
    info "Backing up '$file_path' to '$backup_path'..."
    # Use cp -a for directories, cp -p for files
    if [[ -d "$file_path" ]]; then
        cp -a "$file_path" "$backup_path" || {
            error "Failed to create backup for directory '$file_path'."
            return 1
        }
    else
        cp -p "$file_path" "$backup_path" || {
            error "Failed to create backup for file '$file_path'."
            return 1
        }
    fi
    # Set secure permissions for backup
    chmod -R 600 "$backup_path" || warn "Failed to set secure permissions on backup '$backup_path'."
    info "Backup created successfully."
}

# Apply a configuration setting if it doesn't already exist or match
# Usage: apply_setting <file> <setting_regex> <new_setting_line>
apply_setting() {
    local file="$1"
    local setting_regex="$2"
    local new_setting="$3"

    if [[ ! -f "$file" ]]; then
        warn "Configuration file '$file' not found. Cannot apply setting: $new_setting"
        return 1
    fi

    # Check if setting exists and matches (ignoring leading/trailing whitespace)
    if grep -qE "^\s*${setting_regex}\s*$" "$file"; then
        local current_setting
        current_setting=$(grep -E "^\s*${setting_regex}\s*$" "$file" | head -n 1)
        if [[ "$current_setting" == "$new_setting" ]]; then
            info "Setting '$new_setting' already correctly configured in '$file'."
            return 0
        else
            info "Updating setting in '$file': '$current_setting' -> '$new_setting'"
            # Backup before modifying
            backup_config_file "$file" || return 1
            # Use sed to replace the line (handle potential special characters in regex/setting)
            # This is a basic replacement, might need refinement for complex cases
            sed -i.bak_sed "s|^\s*${setting_regex}\s*.*$|${new_setting}|" "$file"
            rm -f "${file}.bak_sed" # Clean up sed backup
            return 0
        fi
    else
        info "Adding setting to '$file': '$new_setting'"
        # Backup before modifying
        backup_config_file "$file" || return 1
        # Append the setting if it doesn't exist
        echo "$new_setting" >> "$file"
        return 0
    fi
}

# --- Lockdown/Verification Functions ---

apply_kernel_hardening() {
    info "Applying kernel hardening parameters..."
    local sysctl_conf="/etc/sysctl.conf"
    local sysctl_d="/etc/sysctl.d/99-hardening.conf" # Use a dedicated file in sysctl.d

    # Create/backup the dedicated file
    if [[ ! -f "$sysctl_d" ]]; then
        touch "$sysctl_d"
    fi
    backup_config_file "$sysctl_d" || return 1

    # Common kernel hardening settings (adjust based on policy/level)
    # Network Security
    apply_setting "$sysctl_d" "net.ipv4.tcp_syncookies" "net.ipv4.tcp_syncookies = 1"
    apply_setting "$sysctl_d" "net.ipv4.ip_forward" "net.ipv4.ip_forward = 0" # Disable IP forwarding unless router
    apply_setting "$sysctl_d" "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.all.accept_source_route = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.default.accept_source_route" "net.ipv4.conf.default.accept_source_route = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.all.accept_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.default.accept_redirects" "net.ipv4.conf.default.accept_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.all.secure_redirects" "net.ipv4.conf.all.secure_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.default.secure_redirects" "net.ipv4.conf.default.secure_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.send_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.default.send_redirects" "net.ipv4.conf.default.send_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.all.rp_filter = 1" # Strict Reverse Path Filtering
    apply_setting "$sysctl_d" "net.ipv4.conf.default.rp_filter" "net.ipv4.conf.default.rp_filter = 1"
    apply_setting "$sysctl_d" "net.ipv4.icmp_echo_ignore_broadcasts" "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    apply_setting "$sysctl_d" "net.ipv4.icmp_ignore_bogus_error_responses" "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    # IPv6 equivalents if needed
    apply_setting "$sysctl_d" "net.ipv6.conf.all.accept_ra" "net.ipv6.conf.all.accept_ra = 0"
    apply_setting "$sysctl_d" "net.ipv6.conf.default.accept_ra" "net.ipv6.conf.default.accept_ra = 0"
    apply_setting "$sysctl_d" "net.ipv6.conf.all.accept_redirects" "net.ipv6.conf.all.accept_redirects = 0"
    apply_setting "$sysctl_d" "net.ipv6.conf.default.accept_redirects" "net.ipv6.conf.default.accept_redirects = 0"

    # Memory Security
    apply_setting "$sysctl_d" "kernel.randomize_va_space" "kernel.randomize_va_space = 2" # ASLR
    apply_setting "$sysctl_d" "kernel.exec-shield" "kernel.exec-shield = 1" # May not be available/needed on all kernels

    # Filesystem Security
    apply_setting "$sysctl_d" "fs.protected_hardlinks" "fs.protected_hardlinks = 1"
    apply_setting "$sysctl_d" "fs.protected_symlinks" "fs.protected_symlinks = 1"

    # Apply changes
    info "Applying sysctl changes..."
    sysctl -p "$sysctl_d" || warn "Failed to apply some sysctl settings from $sysctl_d"
    # Also apply system-wide if needed
    sysctl --system || warn "Failed to apply system-wide sysctl settings"
    info "Kernel hardening parameters applied."
}

apply_ssh_hardening() {
    info "Applying SSH hardening..."
    local sshd_config="/etc/ssh/sshd_config"
    local ssh_hardening_conf="${DEPLOYMENT_SECURITY_CONFIG}/ssh-hardening.conf" # Reference our standard

    if [[ ! -f "$sshd_config" ]]; then
        warn "SSHD config file '$sshd_config' not found. Skipping SSH hardening."
        return 1
    fi

    backup_config_file "$sshd_config" || return 1

    # Apply settings based on hardening checklist/policy (examples)
    apply_setting "$sshd_config" "Protocol" "Protocol 2"
    apply_setting "$sshd_config" "PermitRootLogin" "PermitRootLogin no"
    apply_setting "$sshd_config" "PasswordAuthentication" "PasswordAuthentication no"
    apply_setting "$sshd_config" "ChallengeResponseAuthentication" "ChallengeResponseAuthentication no"
    apply_setting "$sshd_config" "UsePAM" "UsePAM yes" # Ensure PAM is used for auth methods like MFA
    apply_setting "$sshd_config" "X11Forwarding" "X11Forwarding no"
    apply_setting "$sshd_config" "AllowAgentForwarding" "AllowAgentForwarding no"
    apply_setting "$sshd_config" "AllowTcpForwarding" "AllowTcpForwarding no"
    apply_setting "$sshd_config" "MaxAuthTries" "MaxAuthTries 3"
    apply_setting "$sshd_config" "MaxSessions" "MaxSessions 5"
    apply_setting "$sshd_config" "LoginGraceTime" "LoginGraceTime 30s"
    apply_setting "$sshd_config" "ClientAliveInterval" "ClientAliveInterval 300"
    apply_setting "$sshd_config" "ClientAliveCountMax" "ClientAliveCountMax 0" # Disconnect idle clients
    apply_setting "$sshd_config" "PermitEmptyPasswords" "PermitEmptyPasswords no"
    apply_setting "$sshd_config" "IgnoreRhosts" "IgnoreRhosts yes"
    apply_setting "$sshd_config" "HostbasedAuthentication" "HostbasedAuthentication no"

    # Apply strong crypto if defined in ssh-hardening.conf or policy
    if [[ -f "$ssh_hardening_conf" ]]; then
        info "Applying crypto settings from $ssh_hardening_conf"
        # Example: Extract and apply KexAlgorithms, Ciphers, MACs
        local kex=$(grep -iE "^\s*KexAlgorithms" "$ssh_hardening_conf" | sed 's/KexAlgorithms //')
        local ciphers=$(grep -iE "^\s*Ciphers" "$ssh_hardening_conf" | sed 's/Ciphers //')
        local macs=$(grep -iE "^\s*MACs" "$ssh_hardening_conf" | sed 's/MACs //')
        [[ -n "$kex" ]] && apply_setting "$sshd_config" "KexAlgorithms" "KexAlgorithms $kex"
        [[ -n "$ciphers" ]] && apply_setting "$sshd_config" "Ciphers" "Ciphers $ciphers"
        [[ -n "$macs" ]] && apply_setting "$sshd_config" "MACs" "MACs $macs"
    else
        warn "SSH hardening config '$ssh_hardening_conf' not found. Using basic settings."
    fi

    # Validate config and reload
    info "Validating SSHD configuration..."
    if sshd -t -f "$sshd_config"; then
        info "SSHD configuration is valid. Reloading service..."
        systemctl reload sshd || error "Failed to reload sshd service."
        info "SSHD service reloaded."
    else
        error "SSHD configuration validation failed. Check '$sshd_config'. Manual intervention required."
    fi
    info "SSH hardening applied."
}

apply_filesystem_hardening() {
    info "Applying filesystem security settings..."
    local fstab="/etc/fstab"

    backup_config_file "$fstab" || return 1

    # Harden /tmp
    info "Hardening /tmp mount point..."
    if grep -qE '\s/tmp\s' "$fstab"; then
        # Check if options already exist, add if not
        if ! grep -qE '\s/tmp\s.*\snosuid\s' "$fstab"; then sed -i.bak_sed '/\s\/tmp\s/ s/defaults/defaults,nosuid/' "$fstab"; fi
        if ! grep -qE '\s/tmp\s.*\snodev\s' "$fstab"; then sed -i.bak_sed '/\s\/tmp\s/ s/defaults/defaults,nodev/' "$fstab"; fi
        if ! grep -qE '\s/tmp\s.*\snoexec\s' "$fstab"; then sed -i.bak_sed '/\s\/tmp\s/ s/defaults/defaults,noexec/' "$fstab"; fi
        rm -f "${fstab}.bak_sed"
        info "Applied nosuid,nodev,noexec to /tmp in fstab. Remounting..."
        mount -o remount /tmp || warn "Failed to remount /tmp. Reboot may be required."
    else
        warn "/tmp mount point not found in $fstab. Skipping fstab hardening for /tmp."
    fi
    # Ensure correct permissions for /tmp itself
    chmod 1777 /tmp
    chown root:root /tmp

    # Harden /dev/shm (shared memory)
    info "Hardening /dev/shm mount point..."
    if grep -qE '\s/dev/shm\s' "$fstab"; then
        if ! grep -qE '\s/dev/shm\s.*\snosuid\s' "$fstab"; then sed -i.bak_sed '/\s\/dev\/shm\s/ s/defaults/defaults,nosuid/' "$fstab"; fi
        if ! grep -qE '\s/dev/shm\s.*\snodev\s' "$fstab"; then sed -i.bak_sed '/\s\/dev\/shm\s/ s/defaults/defaults,nodev/' "$fstab"; fi
        if ! grep -qE '\s/dev/shm\s.*\snoexec\s' "$fstab"; then sed -i.bak_sed '/\s\/dev\/shm\s/ s/defaults/defaults,noexec/' "$fstab"; fi
        rm -f "${fstab}.bak_sed"
        info "Applied nosuid,nodev,noexec to /dev/shm in fstab. Remounting..."
        mount -o remount /dev/shm || warn "Failed to remount /dev/shm. Reboot may be required."
    else
        warn "/dev/shm mount point not found in $fstab. Skipping fstab hardening for /dev/shm."
    fi

    # Set secure umask (system-wide)
    info "Setting secure umask (027)..."
    apply_setting "/etc/profile" "umask" "umask 027"
    # Also set in login.defs for useradd defaults
    if [[ -f "/etc/login.defs" ]]; then
        backup_config_file "/etc/login.defs" || return 1
        sed -i.bak_sed 's/^\(UMASK\s*\)[0-9]*/\1027/' /etc/login.defs
        rm -f "/etc/login.defs.bak_sed"
    fi

    # Secure critical file permissions
    info "Setting secure permissions for critical files..."
    chmod 644 /etc/passwd /etc/group /etc/hosts
    chmod 600 /etc/shadow /etc/gshadow
    chmod 640 /etc/rsyslog.conf # Or syslog-ng.conf
    # Add more as needed based on policy

    info "Filesystem hardening applied."
}

apply_network_hardening() {
    info "Applying network security settings..."

    # Apply firewall rules
    local iptables_script="${DEPLOYMENT_SECURITY_SCRIPTS}/iptables_rules.sh"
    if [[ -f "$iptables_script" && -x "$iptables_script" ]]; then
        info "Applying firewall rules from $iptables_script..."
        # Backup current rules first (implementation depends on firewall type)
        # Example for iptables: iptables-save > "${BACKUP_DIR}/iptables-rules-$(date +%Y%m%d%H%M%S).bak"
        if command -v iptables-save &> /dev/null; then
             iptables-save > "${BACKUP_DIR}/iptables-rules-$(date +%Y%m%d%H%M%S).bak" || warn "Failed to backup iptables rules."
        fi
        "$iptables_script" || error "Failed to apply firewall rules from $iptables_script."
        info "Firewall rules applied."
    else
        warn "Firewall script '$iptables_script' not found or not executable. Skipping firewall rules application."
    fi

    # Disable unnecessary network services (handled by disable_non_essential_services)

    # Kernel network hardening (handled by apply_kernel_hardening)

    info "Network hardening applied (partially covered by kernel hardening and service disabling)."
}

apply_authentication_hardening() {
    info "Applying authentication hardening..."

    # Configure password policies in /etc/login.defs
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        info "Configuring password policies in $login_defs..."
        backup_config_file "$login_defs" || return 1
        # Example settings (adjust based on policy)
        sed -i.bak_sed 's/^\(PASS_MAX_DAYS\s*\)[0-9]*/\190/' "$login_defs"
        sed -i.bak_sed 's/^\(PASS_MIN_DAYS\s*\)[0-9]*/\11/' "$login_defs"
        sed -i.bak_sed 's/^\(PASS_WARN_AGE\s*\)[0-9]*/\114/' "$login_defs"
        # Ensure ENCRYPT_METHOD is strong (e.g., SHA512 or YESCRYPT)
        sed -i.bak_sed 's/^\(ENCRYPT_METHOD\s*\).*/\1SHA512/' "$login_defs"
        rm -f "${login_defs}.bak_sed"
    else
        warn "$login_defs not found. Skipping password policy configuration."
    fi

    # Configure password quality via PAM (e.g., pam_pwquality or pam_cracklib)
    local pwquality_conf="/etc/security/pwquality.conf"
    if [[ -f "$pwquality_conf" ]]; then
        info "Configuring password quality in $pwquality_conf..."
        backup_config_file "$pwquality_conf" || return 1
        # Example settings (adjust based on policy)
        apply_setting "$pwquality_conf" "minlen" "minlen = 14"
        apply_setting "$pwquality_conf" "dcredit" "dcredit = -1" # At least 1 digit
        apply_setting "$pwquality_conf" "ucredit" "ucredit = -1" # At least 1 uppercase
        apply_setting "$pwquality_conf" "lcredit" "lcredit = -1" # At least 1 lowercase
        apply_setting "$pwquality_conf" "ocredit" "ocredit = -1" # At least 1 special char
        apply_setting "$pwquality_conf" "difok" "difok = 5"     # Min 5 chars different from old pwd
        apply_setting "$pwquality_conf" "retry" "retry = 3"
    else
        warn "$pwquality_conf not found. Skipping password quality configuration."
        # Check for older pam_cracklib settings if needed
    fi

    # Configure account lockout via PAM (e.g., pam_tally2 or pam_faillock)
    info "Configuring account lockout policy..."
    # This requires modifying files in /etc/pam.d/ (e.g., system-auth, password-auth)
    # Example for pam_faillock (preferred over pam_tally2):
    local pam_files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth") # Adjust for specific distro
    for pam_file in "${pam_files[@]}"; do
        if [[ -f "$pam_file" ]]; then
            backup_config_file "$pam_file" || continue
            # Add faillock lines if they don't exist (order matters in PAM)
            if ! grep -q "pam_faillock.so preauth" "$pam_file"; then
                sed -i.bak_sed '/^auth\s*sufficient\s*pam_unix.so/i auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900' "$pam_file"
            fi
            if ! grep -q "pam_faillock.so authfail" "$pam_file"; then
                 sed -i.bak_sed '/^auth\s*\[default=die\]\s*pam_faillock.so/d' "$pam_file" # Remove old entry if exists
                 sed -i.bak_sed '/^auth\s*sufficient\s*pam_unix.so/a auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' "$pam_file"
            fi
             if ! grep -q "pam_faillock.so authsucc" "$pam_file"; then
                 sed -i.bak_sed '/^account\s*required\s*pam_unix.so/i account     required      pam_faillock.so' "$pam_file"
            fi
            rm -f "${pam_file}.bak_sed"
            info "Applied faillock settings to $pam_file (deny=5, unlock_time=900)."
        else
            warn "PAM file $pam_file not found. Skipping faillock configuration for this file."
        fi
    done

    # TODO: Add MFA configuration steps if required by policy (e.g., configuring pam_google_authenticator)

    info "Authentication hardening applied."
}

disable_non_essential_services() {
    info "Disabling non-essential services based on policy..."
    # Define services based on security level or policy file
    local services_to_disable=()
    # Baseline/Medium might disable fewer than High/Critical
    if [[ "$SECURITY_LEVEL" == "high" || "$SECURITY_LEVEL" == "critical" ]]; then
        services_to_disable=(
            "telnet.socket" "telnet" "rsh.socket" "rlogin.socket" "rexec.socket" # Insecure remote access
            "tftp.socket" "tftp"                                                # Trivial FTP
            "avahi-daemon.socket" "avahi-daemon"                                # Zeroconf networking
            "cups.socket" "cups"                                                # Printing service (disable if not needed)
            "nfs-server" "rpcbind"                                              # NFS server (disable if not needed)
            "smb" "nmb"                                                         # Samba (disable if not needed)
            "vsftpd"                                                            # FTP server (disable if not needed)
            # Add others based on hardening guides (e.g., NIS, talk, finger)
        )
    elif [[ "$SECURITY_LEVEL" == "medium" ]]; then
         services_to_disable=(
            "telnet.socket" "telnet" "rsh.socket" "rlogin.socket" "rexec.socket"
            "tftp.socket" "tftp"
            "avahi-daemon.socket" "avahi-daemon"
        )
    else # Baseline
         services_to_disable=(
            "telnet.socket" "telnet" "rsh.socket" "rlogin.socket" "rexec.socket"
        )
    fi

    # TODO: Allow overriding services_to_disable from policy file if provided

    if [[ ${#services_to_disable[@]} -eq 0 ]]; then
        info "No services marked for disabling at this level/policy."
        return
    fi

    info "Attempting to disable: ${services_to_disable[*]}"
    for service in "${services_to_disable[@]}"; do
        # Check if service exists and is active or enabled
        if systemctl list-unit-files --type=service,socket | grep -q "^${service}"; then
            if systemctl is-active "$service" --quiet || systemctl is-enabled "$service" --quiet; then
                info "Processing service: $service"
                if [[ "$FORCE_MODE" != "true" ]]; then
                    warn "Skipping disable of $service (requires --force or policy confirmation)"
                    continue
                fi
                info "Stopping service: $service"
                systemctl stop "$service" || warn "Failed to stop $service (may not be running)"
                info "Disabling service: $service"
                systemctl disable "$service" || warn "Failed to disable $service"
            else
                info "Service $service is already inactive/disabled."
            fi
        else
             info "Service $service not found."
        fi
    done
    info "Non-essential service disabling process complete."
}

# Verification function - checks current settings against expected state
# Returns 0 if compliant, 1 if non-compliant
verify_configuration() {
    local policy_source="$1"
    local compliant=true # Assume compliant initially
    info "Verifying system configuration against policy: $policy_source..."

    # TODO: Implement parsing of policy_source (level, component/policy, or file)
    # This example verifies a subset of 'high' level settings

    # Verify Kernel Params
    info "Verifying kernel parameters..."
    if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" != "1" ]]; then warn "Verification FAILED: net.ipv4.tcp_syncookies is not 1"; compliant=false; fi
    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "0" ]]; then warn "Verification FAILED: net.ipv4.ip_forward is not 0"; compliant=false; fi
    if [[ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" != "0" ]]; then warn "Verification FAILED: net.ipv4.conf.all.accept_redirects is not 0"; compliant=false; fi
    if [[ "$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)" != "1" ]]; then warn "Verification FAILED: net.ipv4.conf.all.rp_filter is not 1"; compliant=false; fi
    if [[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" != "2" ]]; then warn "Verification FAILED: kernel.randomize_va_space is not 2"; compliant=false; fi

    # Verify SSH Config
    info "Verifying SSH configuration..."
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        if ! grep -qE "^\s*Protocol\s+2\s*$" "$sshd_config"; then warn "Verification FAILED: SSH Protocol is not 2"; compliant=false; fi
        if ! grep -qE "^\s*PermitRootLogin\s+no\s*$" "$sshd_config"; then warn "Verification FAILED: SSH PermitRootLogin is not no"; compliant=false; fi
        if ! grep -qE "^\s*PasswordAuthentication\s+no\s*$" "$sshd_config"; then warn "Verification FAILED: SSH PasswordAuthentication is not no"; compliant=false; fi
        if ! grep -qE "^\s*X11Forwarding\s+no\s*$" "$sshd_config"; then warn "Verification FAILED: SSH X11Forwarding is not no"; compliant=false; fi
        if ! grep -qE "^\s*MaxAuthTries\s+3\s*$" "$sshd_config"; then warn "Verification FAILED: SSH MaxAuthTries is not 3"; compliant=false; fi
    else
        warn "Verification SKIPPED: SSH config file $sshd_config not found.";
    fi

    # Verify Filesystem Mounts
    info "Verifying filesystem mount options..."
    if ! findmnt -n -o OPTIONS /tmp | grep -q 'noexec'; then warn "Verification FAILED: /tmp is not mounted with noexec"; compliant=false; fi
    if ! findmnt -n -o OPTIONS /tmp | grep -q 'nosuid'; then warn "Verification FAILED: /tmp is not mounted with nosuid"; compliant=false; fi
    if ! findmnt -n -o OPTIONS /tmp | grep -q 'nodev'; then warn "Verification FAILED: /tmp is not mounted with nodev"; compliant=false; fi
    if ! findmnt -n -o OPTIONS /dev/shm | grep -q 'noexec'; then warn "Verification FAILED: /dev/shm is not mounted with noexec"; compliant=false; fi
    if ! findmnt -n -o OPTIONS /dev/shm | grep -q 'nosuid'; then warn "Verification FAILED: /dev/shm is not mounted with nosuid"; compliant=false; fi
    if ! findmnt -n -o OPTIONS /dev/shm | grep -q 'nodev'; then warn "Verification FAILED: /dev/shm is not mounted with nodev"; compliant=false; fi

    # Verify Umask (check default for root or a standard user)
    # info "Verifying default umask..."
    # local current_umask=$(su - root -c umask) # This might be tricky to get reliably
    # if [[ "$current_umask" != "0027" ]]; then warn "Verification FAILED: Default umask is not 027 (found $current_umask)"; compliant=false; fi

    # Verify Disabled Services
    info "Verifying disabled services..."
    local services_to_check=("telnet.socket" "avahi-daemon.socket") # Example
    for service in "${services_to_check[@]}"; do
         if systemctl is-enabled "$service" --quiet; then
             warn "Verification FAILED: Service $service is enabled"; compliant=false;
         fi
    done

    # Verify Authentication Settings (Password Policy)
    info "Verifying password policies..."
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        if ! grep -qE "^\s*PASS_MAX_DAYS\s+90\s*$" "$login_defs"; then warn "Verification FAILED: PASS_MAX_DAYS is not 90"; compliant=false; fi
        if ! grep -qE "^\s*PASS_MIN_DAYS\s+1\s*$" "$login_defs"; then warn "Verification FAILED: PASS_MIN_DAYS is not 1"; compliant=false; fi
        if ! grep -qE "^\s*ENCRYPT_METHOD\s+SHA512\s*$" "$login_defs"; then warn "Verification FAILED: ENCRYPT_METHOD is not SHA512"; compliant=false; fi
    else
         warn "Verification SKIPPED: $login_defs not found.";
    fi

    # TODO: Add verification for pwquality, faillock/tally2, firewall rules etc.

    if [[ "$compliant" == "true" ]]; then
        info "Verification PASSED: All checked items are compliant."
        return 0
    else
        error "Verification FAILED: One or more items are non-compliant. Check warnings above."
        return 1
    fi
}

# --- Main Execution Logic ---

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --security-level)
            SECURITY_LEVEL="$2"
            shift 2
            ;;
        --component)
            COMPONENT="$2"
            shift 2
            ;;
        --apply-policy)
            APPLY_POLICY="$2"
            shift 2
            ;;
        --verify)
            VERIFY_MODE=true
            shift
            ;;
        --policy-file)
            POLICY_FILE="$2"
            shift 2
            ;;
        --force)
            FORCE_MODE=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

info "Starting System Lockdown Script..."
info "Environment: $ENVIRONMENT"
if [[ "$VERIFY_MODE" == "true" ]]; then
    info "Mode: Verification"
else
    info "Mode: Application"
    [[ "$FORCE_MODE" == "true" ]] && warn "Force mode enabled - changes will be applied without confirmation."
fi

# Determine policy source
POLICY_SOURCE=""
if [[ -n "$POLICY_FILE" ]]; then
    if [[ ! -f "$POLICY_FILE" ]]; then
        error "Policy file not found: $POLICY_FILE"
    fi
     if ! command -v jq &> /dev/null; then
        error "jq command is required for --policy-file but not found. Please install jq."
    fi
    POLICY_SOURCE="$POLICY_FILE"
    info "Using custom policy file: $POLICY_SOURCE"
    # Reset level/component if policy file is specified
    SECURITY_LEVEL=""
    COMPONENT=""
    APPLY_POLICY=""
elif [[ -n "$COMPONENT" && -n "$APPLY_POLICY" ]]; then
    POLICY_SOURCE="Component: $COMPONENT, Policy: $APPLY_POLICY"
    info "Targeting component '$COMPONENT' with policy '$APPLY_POLICY'"
    SECURITY_LEVEL="" # Component/policy overrides level
elif [[ -n "$SECURITY_LEVEL" ]]; then
    # Validate security level
    case "$SECURITY_LEVEL" in
        baseline|medium|high|critical)
            POLICY_SOURCE="Security Level: $SECURITY_LEVEL"
            info "Using security level: $SECURITY_LEVEL"
            ;;
        *)
            error "Unsupported security level: $SECURITY_LEVEL. Choose from baseline, medium, high, critical."
            ;;
    esac
else
    error "No security level, component/policy, or policy file specified."
fi


if [[ "$VERIFY_MODE" == "true" ]]; then
    # --- Verification Mode ---
    info "--- Starting Configuration Verification ---"
    verify_configuration "$POLICY_SOURCE"
    # verify_configuration function now handles exit status
else
    # --- Application Mode ---
    info "--- Starting Security Lockdown Application ---"
    confirm_action "Apply security lockdown settings based on '$POLICY_SOURCE' to environment '$ENVIRONMENT'?"

    # Apply settings based on policy source
    if [[ -n "$POLICY_FILE" ]]; then
        # TODO: Implement logic to parse JSON policy file with jq and call specific functions
        error "Applying custom policy files is not yet implemented. Requires jq parsing logic."
        # Example:
        # local min_tls=$(jq -r '.controls.tls_configuration.min_tls_version // empty' "$POLICY_FILE")
        # if [[ "$min_tls" == "1.3" ]]; then apply_tls_1_3_settings; fi
    elif [[ -n "$COMPONENT" ]]; then
        info "Applying policy '$APPLY_POLICY' to component '$COMPONENT'..."
        case "$COMPONENT" in
            kernel) apply_kernel_hardening ;; # Needs policy parsing
            ssh) apply_ssh_hardening ;;       # Needs policy parsing
            filesystem) apply_filesystem_hardening ;; # Needs policy parsing
            network) apply_network_hardening ;;     # Needs policy parsing
            authentication) apply_authentication_hardening ;; # Needs policy parsing
            services) disable_non_essential_services ;; # Needs policy parsing
            *) error "Unsupported component: $COMPONENT" ;;
        esac
        warn "Component-specific policy application is basic; full policy parsing not implemented."
    elif [[ -n "$SECURITY_LEVEL" ]]; then
        info "Applying settings for security level: $SECURITY_LEVEL"
        # Apply functions based on level - order can matter
        # Baseline applies minimal set
        if [[ "$SECURITY_LEVEL" == "baseline" || "$SECURITY_LEVEL" == "medium" || "$SECURITY_LEVEL" == "high" || "$SECURITY_LEVEL" == "critical" ]]; then
            apply_kernel_hardening
            apply_ssh_hardening
            apply_filesystem_hardening
            apply_authentication_hardening
            apply_network_hardening # Includes firewall if script exists
        fi
        # Medium adds more
        if [[ "$SECURITY_LEVEL" == "medium" || "$SECURITY_LEVEL" == "high" || "$SECURITY_LEVEL" == "critical" ]]; then
            # Add medium-specific actions if any (e.g., stricter PAM)
            : # Placeholder
        fi
         # High/Critical adds most restrictive settings and disables more services
        if [[ "$SECURITY_LEVEL" == "high" || "$SECURITY_LEVEL" == "critical" ]]; then
            disable_non_essential_services
            # Add other high/critical specific actions (e.g., AppArmor/SELinux enforcement if configured)
            # Example: source "${DEPLOYMENT_SECURITY_SCRIPTS}/apparmor_setup.sh" if exists
        fi
    fi

    info "--- Security Lockdown Application Completed ---"
    info "Review logs for details: $LOG_FILE"
    info "It is recommended to reboot the system or restart relevant services for all changes to take effect."
    info "Run '$0 --verify --security-level $SECURITY_LEVEL' (or relevant policy) to confirm the applied settings."
fi

exit 0
