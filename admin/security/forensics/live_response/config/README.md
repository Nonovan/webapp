# Live Response Configuration Files

This directory contains configuration files for the Live Response Forensic Toolkit, which determines how evidence is collected, analyzed, and stored during security incident investigations.

## Contents

- [Overview](#overview)
- [Key Configuration Files](#key-configuration-files)
- [Directory Structure](#directory-structure)
- [Configuration Format](#configuration-format)
- [Usage](#usage)
- [Environment Support](#environment-support)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The configuration files in this directory control various aspects of the live response toolkit behavior, including evidence collection methods, analysis profiles for different incident types, and tool dependencies. These files ensure consistent forensic operations across different investigations while allowing appropriate customization for specific incident response needs.

Each configuration file is designed to be environment-aware, with specific settings that can be applied to different operational environments (development, testing, staging, production) while maintaining consistent functionality and forensic integrity.

## Key Configuration Files

- **`collection_config.json`**: Primary configuration for evidence collection
  - Evidence handling and storage settings
  - Chain of custody configuration
  - Hashing algorithms and integrity verification
  - Memory acquisition parameters
  - Volatile data collection settings
  - Network state capture options
  - Remote collection authentication methods
  - Logging and audit trail configuration

- **`default_profiles.json`**: Predefined incident response profiles
  - Malware investigation profile
  - Data breach investigation profile
  - Unauthorized access investigation profile
  - Quick triage profile
  - Full collection profile
  - Ransomware incident profile
  - Lateral movement detection profile
  - Persistence analysis profile

- **`tool_dependencies.conf`**: Path configurations for external tools
  - Core system utilities
  - Hashing utilities
  - Compression utilities
  - Memory acquisition tools
  - Volatile data collection tools
  - Network state tools
  - Artifact analysis tools
  - Evidence handling tools
  - OS-specific tools (Windows, macOS)

## Directory Structure

```plaintext
admin/security/forensics/live_response/config/
├── README.md                     # This documentation
├── collection_config.json        # Main configuration
├── collection_config.json.example # Example configuration with comments
├── default_profiles.json         # Response profiles for different scenarios
└── tool_dependencies.conf        # External tool dependencies and paths
```

## Configuration Format

All configuration files follow consistent formatting principles:

- **`collection_config.json`** and **`default_profiles.json`** use JSON format with a consistent structure:
  - Version and metadata sections
  - Component-specific configuration blocks
  - Environment-specific settings
  - Clear documentation in example files

- **`tool_dependencies.conf`** uses an INI-style format:
  - Categorized sections for different tool types
  - Key-value pairs for tool names and paths
  - Comment-based documentation

## Usage

### Loading Configuration Files

Configuration files are loaded automatically by the live response toolkit scripts. You can customize them as needed:

```bash
# Create a custom configuration based on the example
cp collection_config.json.example collection_config.json
nano collection_config.json  # Edit as needed
```

### Using Collection Profiles

Predefined collection profiles can be used to tailor response to specific incident types:

```bash
# For malware investigations
./volatile_data.sh --profile malware_investigation --output /mnt/evidence/

# For data breach investigations
./network_state.sh --profile data_breach --output /mnt/evidence/
```

### Environment-Specific Configuration

The configuration files include environment-specific settings that are automatically selected:

```bash
# Set the environment (production, staging, development, testing)
export APP_ENV=production

# Run collection with environment-specific settings
./volatile_data.sh --output /mnt/evidence/
```

## Environment Support

Configuration files support different environments through dedicated sections:

- **Production**: Settings optimized for actual incident response
  - Strict security requirements
  - Full chain of custody enforcement
  - Comprehensive logging
  - Secure evidence storage
  - Encryption requirements

- **Staging**: Nearly identical to production but for pre-production testing
  - Mirrors production security controls
  - Uses separate storage paths
  - May have reduced approval requirements

- **Development**: Settings optimized for toolkit development
  - Relaxed security requirements for faster iteration
  - Local temporary storage paths
  - Optional encryption
  - Enhanced debugging output

- **Testing**: Settings optimized for automated testing
  - Temporary storage locations
  - Faster execution with reduced security checks
  - Test-specific verification requirements

## Best Practices & Security

- **Validate Files**: Always validate configuration files before deployment to production
- **Version Control**: Maintain configuration files in version control
- **Secure Storage**: Store configurations with appropriate access controls
- **Audit Changes**: Document and review all configuration changes
- **Environment Separation**: Keep environment-specific settings distinct and appropriate
- **Default Security**: Use secure defaults requiring explicit opt-out
- **Parameter Validation**: All live response scripts validate configurations before use
- **Documentation**: Keep non-obvious configuration options documented
- **Minimal Exposure**: Only expose required parameters through configuration
- **Regular Updates**: Review and update tools paths when system tools are updated

## Common Features

All configuration files support these consistent features:

- **Environment Awareness**: Settings adapt to different operational environments
- **Cascading Defaults**: Sensible defaults with explicit override capability
- **Version Tracking**: Clear versioning of configuration structures
- **Documentation**: In-file documentation of configuration parameters
- **Structured Format**: Consistent organization for maintainability
- **Security Controls**: Configuration-based security enforcement
- **Fallback Options**: Graceful degradation when optimal settings aren't available
- **Cross-References**: References to related configuration parameters

## Related Documentation

- Live Response Forensic Tools
- Live Response Usage Guide
- Evidence Handling Guidelines
- Forensic Analysis Toolkit
- Static Analysis Tools
- Chain of Custody Requirements
- Digital Forensics Procedures
- Forensics Utils Documentation
