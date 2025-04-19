#!/bin/bash
# Install NGINX configurations for Cloud Infrastructure Platform
# Usage: ./install-configs.sh --environment [environment] [options]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
NGINX_ROOT="/etc/nginx"
ENVIRONMENT="production"
SOURCE_DIR="${SCRIPT_DIR}/../"
BACKUP_DIR="/var/backups/nginx-configs"
FORCE=false
DRY_RUN=false
RESTART_NGINX=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log function
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --source-dir|-s)
            SOURCE_DIR="$2"
            shift 2
            ;;
        --nginx-root|-n)
            NGINX_ROOT="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --dry-run|-d)
            DRY_RUN=true
            shift
            ;;
        --no-restart)
            RESTART_NGINX=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --environment, -e    Environment to install (development, staging, production) [default: production]"
            echo "  --source-dir, -s     Source directory for NGINX configs [default: current parent directory]"
            echo "  --nginx-root, -n     NGINX installation directory [default: /etc/nginx]"
            echo "  --force, -f          Force overwrite of existing files"
            echo "  --dry-run, -d        Don't actually install anything, just show what would be done"
            echo "  --no-restart         Don't restart NGINX after installation"
            echo "  --help, -h           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production|dr-recovery)$ ]]; then
    log "${RED}Invalid environment: $ENVIRONMENT${NC}"
    log "Valid environments: development, staging, production, dr-recovery"
    exit 1
fi

# Check if NGINX is installed
if ! command -v nginx &> /dev/null; then
    log "${RED}ERROR: NGINX is not installed${NC}"
    exit 1
fi

log "${BLUE}Installing NGINX configurations for ${ENVIRONMENT} environment${NC}"

# Create backup directory if not in dry run mode
if [ "$DRY_RUN" = false ]; then
    mkdir -p "$BACKUP_DIR"
fi

# Backup existing configuration
backup_config() {
    if [ "$DRY_RUN" = false ] && [ -d "$NGINX_ROOT" ]; then
        local timestamp=$(date "+%Y%m%d%H%M%S")
        local backup_file="${BACKUP_DIR}/nginx-backup-${timestamp}.tar.gz"
        log "${BLUE}Backing up existing NGINX configuration to ${backup_file}${NC}"
        if tar -czf "$backup_file" -C "$NGINX_ROOT" .; then
            log "${GREEN}✓ Backup created successfully${NC}"
        else
            log "${YELLOW}⚠ Failed to create backup${NC}"
        fi
    else
        log "${YELLOW}Skipping backup (dry run or NGINX root not found)${NC}"
    fi
}

# Create directory if it doesn't exist
ensure_directory() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        if [ "$DRY_RUN" = false ]; then
            log "Creating directory: $dir"
            mkdir -p "$dir"
        else
            log "[DRY RUN] Would create directory: $dir"
        fi
    fi
}

# Copy a file, backing up any existing destination
copy_file() {
    local src="$1"
    local dst="$2"
    
    if [ ! -f "$src" ]; then
        log "${YELLOW}⚠ Source file not found: $src${NC}"
        return 1
    fi
    
    if [ -f "$dst" ]; then
        if [ "$FORCE" = false ]; then
            log "${YELLOW}⚠ File exists, skipping: $dst${NC}"
            return 0
        else
            # Backup before overwriting
            if [ "$DRY_RUN" = false ]; then
                local timestamp=$(date "+%Y%m%d%H%M%S")
                local backup="${dst}.${timestamp}.bak"
                log "Backing up $dst to $backup"
                cp "$dst" "$backup"
            else
                log "[DRY RUN] Would backup $dst"
            fi
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        log "Installing $src to $dst"
        cp "$src" "$dst"
        chmod 644 "$dst"
    else
        log "[DRY RUN] Would install $src to $dst"
    fi
    return 0
}

# Create a symbolic link if it doesn't exist
create_symlink() {
    local src="$1"
    local dst="$2"
    
    if [ -L "$dst" ]; then
        if [ "$FORCE" = true ]; then
            if [ "$DRY_RUN" = false ]; then
                log "Removing existing symlink: $dst"
                rm "$dst"
            else
                log "[DRY RUN] Would remove existing symlink: $dst"
            fi
        else
            log "${YELLOW}⚠ Symlink exists, skipping: $dst${NC}"
            return 0
        fi
    elif [ -e "$dst" ]; then
        if [ "$FORCE" = true ]; then
            if [ "$DRY_RUN" = false ]; then
                log "Backing up and removing existing file: $dst"
                local timestamp=$(date "+%Y%m%d%H%M%S")
                mv "$dst" "${dst}.${timestamp}.bak"
            else
                log "[DRY RUN] Would backup and remove existing file: $dst"
            fi
        else
            log "${YELLOW}⚠ File exists, skipping symlink creation: $dst${NC}"
            return 0
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        log "Creating symlink: $dst -> $src"
        ln -sf "$src" "$dst"
    else
        log "[DRY RUN] Would create symlink: $dst -> $src"
    fi
    return 0
}

# Run config generation
generate_config() {
    local templates_dir="${SOURCE_DIR}/templates"
    local output_dir="${SOURCE_DIR}/sites-available"
    local script="${SOURCE_DIR}/scripts/generate-config.py"
    
    if [ -f "$script" ]; then
        log "${BLUE}Generating NGINX configuration for ${ENVIRONMENT} environment${NC}"
        
        local cmd="$script --environment $ENVIRONMENT"
        if [ "$FORCE" = true ]; then
            cmd="$cmd --force"
        fi
        if [ "$DRY_RUN" = true ]; then
            cmd="$cmd --dry-run"
        fi
        
        if [ "$DRY_RUN" = false ]; then
            if python3 $cmd; then
                log "${GREEN}✓ Configuration generated successfully${NC}"
            else
                log "${RED}✗ Configuration generation failed${NC}"
                return 1
            fi
        else
            log "[DRY RUN] Would run: python3 $cmd"
        fi
    else
        log "${YELLOW}⚠ Configuration generator script not found: $script${NC}"
    fi
    
    return 0
}

# Install configuration files
install_config_files() {
    # Create necessary directories
    ensure_directory "$NGINX_ROOT/sites-available"
    ensure_directory "$NGINX_ROOT/sites-enabled"
    ensure_directory "$NGINX_ROOT/conf.d"
    ensure_directory "$NGINX_ROOT/includes"
    
    # Install main site configuration
    local site_config="${SOURCE_DIR}/sites-available/cloud-platform.conf"
    
    if [ "$ENVIRONMENT" = "production" ]; then
        copy_file "$site_config" "${NGINX_ROOT}/sites-available/cloud-platform.conf"
        create_symlink "${NGINX_ROOT}/sites-available/cloud-platform.conf" "${NGINX_ROOT}/sites-enabled/cloud-platform.conf"
    elif [ "$ENVIRONMENT" = "staging" ]; then
        local staging_config="${SOURCE_DIR}/sites-available/staging.conf"
        if [ -f "$staging_config" ]; then
            copy_file "$staging_config" "${NGINX_ROOT}/sites-available/staging.conf"
            create_symlink "${NGINX_ROOT}/sites-available/staging.conf" "${NGINX_ROOT}/sites-enabled/staging.conf"
        else
            log "${YELLOW}⚠ Staging configuration not found: $staging_config${NC}"
        fi
    elif [ "$ENVIRONMENT" = "development" ]; then
        local dev_config="${SOURCE_DIR}/sites-available/development.conf"
        if [ -f "$dev_config" ]; then
            copy_file "$dev_config" "${NGINX_ROOT}/sites-available/development.conf"
            create_symlink "${NGINX_ROOT}/sites-available/development.conf" "${NGINX_ROOT}/sites-enabled/development.conf"
        else
            log "${YELLOW}⚠ Development configuration not found: $dev_config${NC}"
        fi
    elif [ "$ENVIRONMENT" = "dr-recovery" ]; then
        local dr_config="${SOURCE_DIR}/sites-available/dr-recovery.conf"
        if [ -f "$dr_config" ]; then
            copy_file "$dr_config" "${NGINX_ROOT}/sites-available/dr-recovery.conf"
            create_symlink "${NGINX_ROOT}/sites-available/dr-recovery.conf" "${NGINX_ROOT}/sites-enabled/dr-recovery.conf"
        else
            log "${YELLOW}⚠ DR recovery configuration not found: $dr_config${NC}"
        fi
    fi
    
    # Install conf.d files
    log "${BLUE}Installing configuration module files to ${NGINX_ROOT}/conf.d/${NC}"
    for conf_file in "${SOURCE_DIR}/conf.d/"*.conf; do
        if [ -f "$conf_file" ]; then
            local filename=$(basename "$conf_file")
            copy_file "$conf_file" "${NGINX_ROOT}/conf.d/${filename}"
        fi
    done
    
    # Install includes files
    log "${BLUE}Installing include files to ${NGINX_ROOT}/includes/${NC}"
    for include_file in "${SOURCE_DIR}/includes/"*.conf; do
        if [ -f "$include_file" ]; then
            local filename=$(basename "$include_file")
            copy_file "$include_file" "${NGINX_ROOT}/includes/${filename}"
        fi
    done
    
    # Create security header symlinks if not already done
    local security_headers_src="${PROJECT_ROOT}/security/security-headers.conf"
    local ssl_params_src="${PROJECT_ROOT}/security/ssl-params.conf"
    
    if [ -f "$security_headers_src" ]; then
        create_symlink "$security_headers_src" "${NGINX_ROOT}/conf.d/security-headers.conf"
    else
        log "${YELLOW}⚠ Security headers file not found: $security_headers_src${NC}"
    fi
    
    if [ -f "$ssl_params_src" ]; then
        create_symlink "$ssl_params_src" "${NGINX_ROOT}/conf.d/ssl-params.conf"
    else
        log "${YELLOW}⚠ SSL parameters file not found: $ssl_params_src${NC}"
    fi
    
    return 0
}

# Test NGINX configuration
test_config() {
    log "${BLUE}Testing NGINX configuration${NC}"
    if [ "$DRY_RUN" = false ]; then
        if nginx -t; then
            log "${GREEN}✓ NGINX configuration test passed${NC}"
            return 0
        else
            log "${RED}✗ NGINX configuration test failed${NC}"
            return 1
        fi
    else
        log "[DRY RUN] Would test NGINX configuration"
        return 0
    fi
}

# Reload NGINX
reload_nginx() {
    if [ "$RESTART_NGINX" = true ]; then
        log "${BLUE}Reloading NGINX${NC}"
        if [ "$DRY_RUN" = false ]; then
            if systemctl is-active --quiet nginx; then
                if systemctl reload nginx; then
                    log "${GREEN}✓ NGINX reloaded successfully${NC}"
                else
                    log "${RED}✗ Failed to reload NGINX${NC}"
                    return 1
                fi
            else
                log "${YELLOW}⚠ NGINX is not running, starting it${NC}"
                if systemctl start nginx; then
                    log "${GREEN}✓ NGINX started successfully${NC}"
                else
                    log "${RED}✗ Failed to start NGINX${NC}"
                    return 1
                fi
            fi
        else
            log "[DRY RUN] Would reload NGINX"
        fi
    else
        log "${YELLOW}⚠ NGINX reload skipped (--no-restart option)${NC}"
    fi
    return 0
}

# Main installation process
main() {
    if [ "$DRY_RUN" = true ]; then
        log "${YELLOW}DRY RUN: No changes will be made${NC}"
    fi
    
    # Backup existing configuration
    backup_config
    
    # Generate configuration if possible
    generate_config
    
    # Install configuration files
    install_config_files
    
    # Test configuration
    if ! test_config; then
        log "${RED}Installation failed: NGINX configuration test failed${NC}"
        return 1
    fi
    
    # Reload NGINX
    if ! reload_nginx; then
        log "${RED}Installation failed: Could not reload NGINX${NC}"
        return 1
    fi
    
    if [ "$DRY_RUN" = false ]; then
        log "${GREEN}✓ NGINX configuration installed successfully for ${ENVIRONMENT} environment${NC}"
    else
        log "${BLUE}DRY RUN completed. No changes were made.${NC}"
    fi
    
    return 0
}

# Run the main installation
main

exit $?