# Configuration Files for Incident Response

This directory contains configuration files used by the Incident Response Kit to manage settings, tool configurations, access permissions, and environment-specific parameters during security incident handling.

## Contents

- Overview
- Key Components
- Directory Structure
- Configuration Format
- Usage
- Best Practices & Security
- Related Documentation

## Overview

The configuration files provide centralized settings for incident response tools, specify external tool dependencies, define emergency access permissions, and establish default parameters for the incident response process. These files support the complete incident lifecycle following the NIST SP 800-61 framework, enabling consistent response actions across different incident types.

## Key Components

- **`response_config.json`**: Core configuration settings for incident response tools
  - Defines logging levels and destinations
  - Specifies evidence collection parameters
  - Sets retention periods for incident data
  - Configures notification thresholds and recipients
  - Defines tool-specific behavior settings

- **`tool_paths.json`**: External tool dependencies and paths
  - Locations of forensic tools
  - Paths to required system utilities
  - External API endpoints
  - Directory paths for evidence storage
  - Paths to log sources

- **`permission_sets.json`**: Emergency access control definitions
  - Temporary privilege elevation settings
  - Break-glass account configurations
  - Role-based access permissions during incidents
  - System access limitations for different response phases

## Directory Structure

```plaintext
admin/security/incident_response_kit/config/
├── README.md                # This documentation
├── response_config.json     # Core tool configuration
├── tool_paths.json          # External tool paths
└── permission_sets.json     # Emergency access permissions
```

## Configuration Format

### response_config.json

```json
{
  "logging": {
    "level": "INFO",
    "file": "/var/log/incident-response/ir-toolkit.log",
    "syslog": true,
    "audit_trail": true
  },
  "evidence_collection": {
    "base_dir": "/secure/evidence",
    "compress": true,
    "encrypt": true,
    "encryption_key_path": "/secure/keys/evidence.key",
    "retention_days": 180
  },
  "notification": {
    "enabled": true,
    "methods": ["email", "sms", "slack"],
    "critical_contacts": ["security-team@example.com", "incident-manager@example.com"],
    "templates_dir": "../templates/notifications"
  },
  "forensic_analysis": {
    "memory_capture": {
      "timeout_seconds": 600,
      "compression": "lz4"
    },
    "network_capture": {
      "interface": "any",
      "snaplen": 1600,
      "duration_seconds": 300
    }
  },
  "isolation": {
    "default_policy": "restrict_outbound",
    "network_segments": {
      "quarantine_vlan": 999,
      "forensic_vlan": 998
    }
  }
}
```

### tool_paths.json

```json
{
  "system_tools": {
    "tcpdump": "/usr/sbin/tcpdump",
    "dd": "/bin/dd",
    "netstat": "/bin/netstat",
    "lsof": "/usr/bin/lsof"
  },
  "forensic_tools": {
    "volatility": "/usr/local/bin/vol.py",
    "bulk_extractor": "/usr/local/bin/bulk_extractor",
    "sleuthkit": "/usr/local/bin/mmls"
  },
  "directories": {
    "evidence": "/secure/evidence",
    "temp": "/tmp/ir-toolkit",
    "logs": "/var/log",
    "config": "/etc/ir-toolkit"
  },
  "api_endpoints": {
    "threat_intel": "https://api.threatintel.example.com/v1",
    "ticket_system": "https://helpdesk.example.com/api/incidents"
  }
}
```

### permission_sets.json

```json
{
  "emergency_access": {
    "security_analyst": {
      "systems": ["web-servers", "database-servers"],
      "permissions": ["read_logs", "capture_memory", "isolate_network"],
      "approval_required": false,
      "max_duration_hours": 8
    },
    "incident_manager": {
      "systems": ["all"],
      "permissions": ["all"],
      "approval_required": true,
      "approvers": ["security-director@example.com", "ciso@example.com"],
      "max_duration_hours": 24
    }
  },
  "break_glass": {
    "enabled": true,
    "accounts": {
      "emergency_admin": {
        "activation_command": "../coordination/create_emergency_access.py --role admin",
        "deactivation_command": "../coordination/revoke_emergency_access.py --role admin",
        "notification_list": ["security-alerts@example.com", "it-director@example.com"]
      }
    }
  }
}
```

## Usage

These configuration files are used by various incident response tools in the toolkit:

```python
import json
import os

# Load configuration
config_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(config_dir, "response_config.json"), "r") as f:
    config = json.load(f)

# Access configuration values
log_level = config["logging"]["level"]
evidence_dir = config["evidence_collection"]["base_dir"]

# Set up appropriate logging and evidence directories
# ...
```

Tools will also verify configuration integrity at startup:

```python
# Example configuration validation
def validate_config(config):
    required_keys = ["logging", "evidence_collection", "notification"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration section: {key}")

    # Validate evidence directory exists and is writable
    evidence_dir = config["evidence_collection"]["base_dir"]
    if not os.path.isdir(evidence_dir):
        raise ValueError(f"Evidence directory {evidence_dir} does not exist")
    if not os.access(evidence_dir, os.W_OK):
        raise ValueError(f"Evidence directory {evidence_dir} is not writable")

    # Additional validation checks...
```

## Best Practices & Security

- **Regular Updates**: Review and update configurations quarterly or after significant environment changes
- **Environment-Specific Settings**: Maintain separate settings for development, staging, and production
- **Secure Storage**: Store sensitive configuration values (API keys, passwords) in a secrets management system
- **Access Control**: Restrict access to configuration files, particularly those with emergency access credentials
- **Version Control**: Track configuration changes in version control with appropriate access restrictions
- **Documentation**: Document all configuration options with descriptions and default values
- **Validation**: Implement configuration validation to prevent misconfigurations
- **Audit Trail**: Maintain an audit trail for configuration changes, especially to emergency access permissions

## Related Documentation

- Incident Response Kit Overview
- Incident Response Procedures
- Security Incident Response Plan
- Forensic Tools Documentation
- Response Coordination Guide
