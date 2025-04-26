# NGINX Site Configuration Symlinks

This directory contains symbolic links to active NGINX server block configuration files, enabling the web server to load and serve the appropriate environments for the Cloud Infrastructure Platform.

## Contents

- Overview
- Usage
- File Structure
- Management
- Related Files
- Best Practices
- Related Documentation

## Overview

The `sites-enabled` directory implements the standard NGINX pattern of storing active configuration symlinks that point to server blocks defined in the `sites-available` directory. Only configurations with symlinks in this directory are loaded by NGINX. This approach allows for easy enabling and disabling of server blocks without modifying or deleting the original configuration files, facilitating environment-specific configuration management and zero-downtime deployment practices.

## Usage

### Activating a Configuration

To enable a configuration from `sites-available`:

```bash
# Create a symbolic link manually
ln -s /etc/nginx/sites-available/configuration-name.conf /etc/nginx/sites-enabled/configuration-name.conf

# Or use the install-configs.sh script
./scripts/install-configs.sh --environment production
```

### Deactivating a Configuration

To disable a configuration that's currently enabled:

```bash
# Remove the symbolic link
rm /etc/nginx/sites-enabled/configuration-name.conf

# Reload NGINX to apply changes
nginx -s reload
```

### Switching Environments

To switch between environment configurations:

```bash
# Remove existing links
rm -f /etc/nginx/sites-enabled/*.conf

# Create new symlink for desired environment
ln -s /etc/nginx/sites-available/development.conf /etc/nginx/sites-enabled/development.conf

# Test and reload NGINX
nginx -t && nginx -s reload
```

## File Structure

```plaintext
deployment/nginx/sites-enabled/
├── README.md              # This documentation
├── cloud-platform.conf    # Symlink to production configuration
├── development.conf       # Symlink to development configuration (when active)
├── dr-recovery.conf       # Symlink to disaster recovery configuration (when active)
└── staging.conf           # Symlink to staging configuration (when active)
```

In a typical deployment, only one environment configuration is active at a time, though multiple configurations can be enabled for complex setups with multiple domains.

## Management

This directory is managed primarily through the NGINX utility scripts:

- **`install-configs.sh`**: Installs and activates environment-specific configurations
- **`nginx-reload.sh`**: Safely reloads NGINX after configuration changes
- **`setup-ssl.sh`**: Creates server blocks and corresponding symlinks for SSL-enabled sites
- **`test-config.sh`**: Verifies NGINX configuration integrity, including symlinks

### Example Script Usage

```bash
# Install production configuration
./scripts/install-configs.sh --environment production

# Install development configuration
./scripts/install-configs.sh --environment development

# Install staging configuration
./scripts/install-configs.sh --environment staging

# Install disaster recovery configuration
./scripts/install-configs.sh --environment dr-recovery
```

## Related Files

- **Server Block Definitions**: Located in `../sites-available/`
  - `cloud-platform.conf`: Production environment configuration
  - `development.conf`: Development environment configuration
  - `dr-recovery.conf`: Disaster recovery environment configuration
  - `staging.conf`: Staging environment configuration

- **Configuration Modules**: Common configurations in `../conf.d/`
  - Included by server blocks to implement specific functionality
  - Shared across multiple server blocks for consistency

- **Include Files**: Reusable snippets in `../includes/`
  - Used within server and location blocks
  - Provide functionality like cache control, CORS, and security headers

## Best Practices

- **Single Active Environment**: In most cases, only enable one environment at a time to prevent conflicts
- **Configuration Testing**: Always test configurations before reloading (`nginx -t`)
- **Symlink Management**: Use scripts to manage symlinks rather than creating them manually
- **No Direct Edits**: Never edit symlinks directly; modify the source files in `sites-available`
- **Descriptive Naming**: Use descriptive names for symlinks to match their source files
- **Validation**: Regularly verify that symlinks point to valid configuration files
- **Backups**: Keep backups of working configurations before making changes
- **Change Tracking**: Document configuration changes in version control

## Related Documentation

- NGINX Site Configuration Documentation
- Configuration Architecture Guide
- Environment-Specific Configuration Guide
- Server Block Management
- Web Server Security Guide
- NGINX Deployment Procedures
