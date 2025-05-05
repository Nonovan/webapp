# Forensic Analysis Configuration Files

This directory contains configuration files used by the Forensic Analysis Toolkit to customize behavior, define analysis profiles, and specify paths requiring special handling during forensic investigations.

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

The configuration files in this directory control various aspects of the forensic toolkit's behavior, including evidence collection parameters, analysis profiles for different scenarios, and the identification of sensitive paths that require special handling. These files enable consistent forensic operations across different cases while allowing appropriate customization for specific investigation needs.

Each configuration file is designed to be environment-aware, with specific settings that can be applied to different operational environments (development, testing, staging, production) while maintaining consistent functionality.

## Key Configuration Files

- **`collection_config.json`**: Defines evidence collection parameters
  - Evidence handling and storage locations
  - Chain of custody configuration
  - Hashing algorithms and integrity verification
  - Live response settings
  - Logging and documentation settings
  - Data sanitization rules

- **`analysis_profiles.json`**: Defines profiles for different analysis scenarios
  - Static analysis configurations
  - Memory analysis profiles
  - Network analysis parameters
  - Disk forensic examination settings
  - Resource limits and timeout values
  - Output formatting options

- **`sensitive_paths.json`**: Identifies paths requiring special handling
  - Critical system paths to monitor
  - Application security-sensitive paths
  - File extension classifications
  - Content signature patterns
  - Special handling requirements
  - Access restrictions by path criticality

## Directory Structure

```plaintext
admin/security/forensics/config/
├── README.md                 # This documentation
├── analysis_profiles.json    # Analysis configuration profiles
├── collection_config.json    # Evidence collection settings
└── sensitive_paths.json      # Sensitive file location reference
```

## Configuration Format

All configuration files use JSON format with a consistent structure:

- Version and metadata section
- Environment-specific settings
- Component-specific configuration blocks
- Default values with clear descriptions

This standardized format ensures that configuration files are easy to understand, validate, and maintain.

## Usage

### Loading Configuration Files

Configuration files are automatically loaded by the forensic toolkit when the corresponding modules are initialized. You can also manually load them as needed:

```python
import json
from pathlib import Path

# Load a configuration file
config_path = Path("admin/security/forensics/config/collection_config.json")
with open(config_path, "r") as f:
    collection_config = json.load(f)

# Access configuration values
evidence_base_dir = collection_config["evidence_collection"]["base_dir"]
hash_algorithm = collection_config["hash_algorithms"]["primary"]
```

### Environment-Specific Configuration

The configuration files include environment-specific settings that are automatically selected based on the current environment:

```python
# Get environment-specific settings (example)
env_name = os.environ.get("ENVIRONMENT", "development")
env_settings = collection_config["environments"].get(env_name, collection_config["environments"]["development"])

# Access environment-specific paths
evidence_dir = env_settings["evidence_base_dir"]
log_dir = env_settings["log_dir"]
```

### Analysis Profiles

Analysis profiles can be selected based on the specific investigation requirements:

```python
# Select an appropriate analysis profile (example)
profile_name = "malware"  # For malware investigation
profile = analysis_profiles["static_analysis"].get(profile_name, analysis_profiles["static_analysis"]["default"])

# Configure analysis based on profile
yara_rules_sets = profile["signature_analysis"]["yara_rules_sets"]
max_file_size_mb = profile["signature_analysis"]["max_file_size_mb"]
```

## Environment Support

Configuration files support different environments through dedicated sections:

- **Production**: Settings optimized for actual forensic investigations
  - Strict security requirements
  - Full chain of custody enforcement
  - Comprehensive logging
  - Secure evidence storage

- **Staging**: Nearly identical to production but for pre-production testing
  - Mirrors production security controls
  - Uses separate storage paths
  - May reduce certain approval requirements

- **Development**: Settings optimized for toolkit development
  - Relaxed security requirements for faster iteration
  - Local storage paths
  - Optional encryption
  - Enhanced debugging output

- **Testing**: Settings optimized for automated testing
  - Temporary storage locations
  - Faster execution with reduced security checks
  - Test-specific verification requirements

## Best Practices & Security

- **Validate Files**: Always validate configuration files before deployment
- **Version Control**: Maintain configuration files in version control
- **Secure Storage**: Store configurations with appropriate access controls
- **Audit Changes**: Document and review all configuration changes
- **Environment Separation**: Keep environment-specific settings distinct
- **Default Security**: Use secure defaults requiring explicit opt-out
- **Parameter Validation**: Implement validation for all configuration parameters
- **Documentation**: Comment all non-obvious configuration options
- **Minimal Exposure**: Only expose required parameters through configuration

## Common Features

All configuration files support these common features:

- **Environment Awareness**: Settings adapt to different operational environments
- **Cascading Defaults**: Sensible defaults with override capability
- **Version Tracking**: Clear versioning of configuration structures
- **Documentation**: In-file documentation of configuration parameters
- **Structured Format**: Consistent organization for maintainability
- **Security Controls**: Configuration-based security enforcement
- **Fallback Options**: Graceful degradation when optimal settings aren't available
- **Cross-References**: References to related configuration parameters

## Related Documentation

- Forensic Analysis Toolkit
- Live Response Tools
- Static Analysis Tools
- Evidence Handling Guidelines
- Chain of Custody Requirements
- Digital Forensics Procedures
- Forensics Utils Documentation
