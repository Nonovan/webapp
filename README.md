# Cloud Infrastructure Platform

A secure, scalable platform for managing multi-cloud infrastructure with integrated monitoring, security, and ICS support.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Deployment](#deployment)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Security Features](#security-features)
  - [File Integrity Monitoring](#file-integrity-monitoring)
- [Integration Capabilities](#integration-capabilities)
  - [Webhook System](#webhook-system)
  - [Cloud Providers](#cloud-providers)
- [Compliance](#compliance)
- [Scripts & Utilities](#scripts--utilities)
- [Development](#development)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)
- [Documentation](#documentation)

## Overview

The Cloud Infrastructure Platform is a comprehensive Flask-based application that provides secure management, monitoring, and analytics for cloud infrastructure with integrated industrial control systems (ICS) support. The platform is designed with security as a core principle and supports multi-cloud environments including AWS, Azure, and GCP.

This platform enables organizations to centralize cloud resource management, enforce security policies, monitor system health, and respond to incidents across their entire infrastructure through a unified interface.

## Getting Started

### Installation

```bash
# Clone repository
git clone https://github.com/username/cloud-platform.git
cd cloud-platform

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env file with your configuration

# Initialize the database
flask db init
flask db migrate
flask db upgrade

# Create initial admin user
flask create-admin

# Initialize security baseline
flask integrity init-baseline

# Run development server
flask run
```

### Configuration

The platform uses a hierarchical configuration system with these sources (in order of precedence):

1. Environment variables
2. .env file variables
3. Default configuration values

Key configuration options:

| Variable | Description | Default |
| --- | --- | --- |
| `SECRET_KEY` | Flask secret key for session security | *required* |
| `DATABASE_URL` | Database connection string | `sqlite:///app.db` |
| `REDIS_URL` | Redis connection for caching & sessions | `redis://localhost:6379/0` |
| `JWT_SECRET_KEY` | Secret for JWT token generation | *required* |
| `ENVIRONMENT` | Application environment | `development` |
| `CLOUD_PROVIDERS_ENABLED` | Enable cloud provider integrations | `True` |
| `FILE_INTEGRITY_MONITORING` | Enable file integrity monitoring | `True` |
| `FILE_BASELINE_PATH` | Path to integrity baseline file | `file_baseline.json` |
| `VERIFY_BASELINE_CONSISTENCY` | Validate baseline structure on startup | `True` |
| `AUTO_REPAIR_BASELINE` | Auto-repair baseline inconsistencies in development | `False` |
| `AUTO_UPDATE_BASELINE` | Auto-update baseline for non-critical changes in development | `False` |
| `BASELINE_UPDATE_MAX_FILES` | Maximum files to update in one operation | `50` |
| `NOTIFY_CRITICAL_VIOLATIONS` | Send SMS alerts for critical integrity violations | `True` |
| `BASELINE_BACKUP_PATH_TEMPLATE` | Template for baseline backups | `instance/security/baseline_backups/{timestamp}_{environment}.json` |
| `BASELINE_UPDATE_RETENTION` | Number of baseline backups to retain | `5` |

See the environment example files in the environments directory for a comprehensive list of configuration options.

### Deployment

For production deployment, follow the documentation in the deployment directory:

```bash
# Set up production configuration
cp deployment/environments/production.env.example deployment/environments/production.env
# Edit production.env with your production settings

# Deploy using the deployment script
cd deployment
./scripts/deploy.sh production
```

For detailed deployment instructions including cloud provider-specific deployment, container deployment, and Kubernetes deployment, refer to `README.md`.

## Core Features

- **Cloud Resource Management**
  - Multi-provider support (AWS, Azure, GCP)
  - Resource provisioning, monitoring, and lifecycle management
  - Real-time metrics collection and visualization
  - Centralized cloud inventory and cost tracking

- **Security & Compliance**
  - Role-based access control with fine-grained permissions
  - Multi-factor authentication and secure password policies
  - Comprehensive audit logging and security incident tracking
  - File integrity monitoring and anomaly detection

- **Monitoring & Alerts**
  - Real-time cloud resource metrics visualization
  - Anomaly detection with configurable thresholds
  - Alert management and notification system
  - Historical metrics analysis and trend reporting

- **Industrial Control Systems (ICS) Integration**
  - Environmental control system monitoring
  - ICS device management and metrics collection
  - Secure control interface with access controls
  - Historical data collection for ICS equipment

## Architecture

The platform is built with a modular architecture that emphasizes security, scalability, and maintainability:

- **Frontend**: Modern responsive UI with Bootstrap 5 and JavaScript
- **Backend**: Python 3 with Flask framework
- **Database**: PostgreSQL for relational data, Redis for caching/queues
- **API**: RESTful API with comprehensive documentation and SDK libraries
- **Security**: Defense-in-depth approach with multiple security layers

The architecture implements:

- Comprehensive authentication and authorization
- Secure communication with TLS encryption
- Layered security controls at multiple levels
- Horizontal scaling capabilities for high availability
- Fault tolerance with circuit breakers and graceful degradation

For detailed architecture information, see `architecture-overview.md`.

## Project Structure

```plaintext
├── api/                # RESTful API endpoints
│   ├── auth/           # Authentication endpoints
│   ├── cloud/          # Cloud resource management endpoints
│   ├── newsletter/     # Newsletter subscription endpoints
│   ├── security/       # Security operations endpoints
│   └── webhooks/       # Webhook configuration and delivery
├── app.py              # Application entry point
├── blueprints/         # Flask blueprints for main app components
├── cli/                # Application command-line interface tools
├── config/             # Configuration management
├── core/               # Core utility functions and security tools
│   ├── security/       # Core security implementation
│   │   ├── cs_audit.py            # Security audit logging
│   │   ├── cs_authentication.py   # Authentication services
│   │   ├── cs_authorization.py    # Authorization services
│   │   ├── cs_crypto.py           # Cryptographic operations
│   │   ├── cs_file_integrity.py   # File integrity monitoring
│   │   ├── cs_monitoring.py       # Security monitoring
│   │   ├── cs_session.py          # Session security management
│   │   └── cs_utils.py            # Security utilities
│   └── utils/          # Shared utility functions
├── deployment/         # Deployment configuration and scripts
├── extensions/         # Flask extensions and shared components
├── models/             # Database models and ORM definitions
│   ├── auth/           # Authentication models
│   ├── cloud/          # Cloud resource models
│   └── security/       # Security models
├── services/           # Business logic and service layer
├── static/             # Static assets (CSS, JS, images)
├── tests/              # Automated tests
└── views/              # View helpers and template utilities
```

## API Reference

The platform provides a comprehensive RESTful API for integration with external systems. All APIs use JWT authentication and follow consistent patterns for requests and responses.

Key API categories:

- **Authentication**: User authentication and token management
- **Cloud Resources**: Managing cloud provider resources
- **ICS Systems**: Industrial control system monitoring and control
- **Webhooks**: Event subscription and notification
- **Security**: Security incident management and reporting

API features include:

- Consistent error handling and status codes
- Comprehensive input validation
- Proper rate limiting and throttling
- Detailed documentation with examples
- Secure authentication and authorization

For detailed API documentation, see `api-overview.md`.

## Security Features

The platform implements a defense-in-depth security approach with multiple layers of protection:

- Content Security Policy (CSP) with nonce-based script validation
- CSRF protection for all forms and API endpoints
- Subresource Integrity (SRI) checks for static assets
- Secure cookie handling and session management
- Password security with strength requirements and history checks
- Input validation and sanitization against XSS and injection attacks
- Web Application Firewall (WAF) with customized rule sets
- Multi-factor authentication support
- File integrity monitoring and verification
- Comprehensive security event logging and monitoring
- Automated security scanning integration

For detailed security documentation, see `security-overview.md`.

### File Integrity Monitoring

The platform provides sophisticated file integrity monitoring to detect unauthorized modifications to critical system files:

#### Key Features

- **Baseline Management**: Creates and maintains cryptographic hashes of critical files
- **Real-time Detection**: Detects modifications to protected files during startup and runtime
- **Severity Classification**: Categorizes changes based on file criticality (critical, high, medium, low)
- **Automated Response**: Configurable actions based on severity (abort startup, create incident, notify)
- **Environment-Specific Controls**: Different handling for development vs. production environments
- **Notification Systems**: Multi-channel alerts for integrity violations (SMS, email, webhooks)
- **Baseline Versioning**: Maintains backups of previous baselines for recovery
- **Circuit Breaker Pattern**: Prevents cascading failures due to integrity issues
- **Detailed Auditing**: Comprehensive logging of all baseline changes and violations
- **API Access**: RESTful API for baseline management and integrity verification

#### Command-Line Interface

The platform provides comprehensive CLI commands for file integrity management:

```bash
# Verify file integrity against baseline
flask integrity verify [--baseline PATH] [--report-only/--update] [-v]

# Update the baseline with approved changes
flask integrity update-baseline [--path PATH] [--force/--no-force] [--backup/--no-backup]

# List contents of baseline file with filtering
flask integrity list [--path PATH] [--filter PATTERN] [--format text|json] [--sort path|hash]

# Check specific file against baseline
flask integrity check-file FILE_PATH [--baseline PATH] [--algorithm ALGO]

# Analyze files for potential integrity risks
flask integrity analyze [--path DIR] [--pattern PATTERN] [--limit NUM]

# Create backup of baseline
flask integrity backup [--path PATH] [--output DIR] [--comment TEXT]

# Compare two baseline files
flask integrity compare BASELINE1 BASELINE2 [--format text|json] [--output FILE]

# Shortcut commands via Makefile
make verify-integrity [BASELINE_PATH=path] [VERBOSE="-v"]
make list-baseline [BASELINE_PATH=path] [FILTER="-f core/"] [FORMAT="--format json"]
make backup-baseline [BASELINE_PATH=path] [COMMENT="pre-deployment"]
make check-file-integrity FILE_PATH=app.py [ALGORITHM="--algorithm sha256"]
make compare-baselines BASELINE1=baseline1.json BASELINE2=baseline2.json [FORMAT="--format json"]
```

#### Baseline Management Features

The enhanced baseline management includes:

1. **Intelligent Backup System**:
   - Automatically creates timestamped backups before updates
   - Configurable backup retention policies
   - Backup naming with optional comments for context
   - Environment-specific backup locations

2. **Enhanced Security Controls**:
   - Role-based permissions for baseline updates
   - Multi-approval workflow for production baselines
   - Severity-based authorization requirements
   - Comprehensive audit trail for all baseline operations

3. **Fault Tolerance**:
   - Automatic baseline corruption detection
   - Self-healing capabilities for development environments
   - Atomic file operations to prevent partial updates
   - Rollback capabilities to previous baseline versions

4. **Analysis Tools**:
   - File permission analysis to detect security issues
   - Recently modified file detection
   - Suspicious content pattern recognition
   - Unexpected executable file detection

5. **Integration with Security Systems**:
   - Automated incident creation for violations
   - Integration with notification service for alerts
   - Webhook support for external system notifications
   - Integration with security monitoring dashboards

#### API Access

File integrity operations are available through the security API:

```bash
# Check current integrity status
curl -X GET /api/security/integrity/status \
  -H "Authorization: Bearer ${TOKEN}"

# Update baseline with approved changes
curl -X PUT /api/security/baseline \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "changes": [
      {
        "path": "config/app.py",
        "current_hash": "a1b2c3d4e5f6...",
        "severity": "medium"
      }
    ],
    "remove_missing": false,
    "notify": true
  }'

# Export baseline comparison
curl -X POST /api/security/baseline/compare \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "baseline1": "instance/security/baseline.json",
    "baseline2": "instance/security/baseline_backups/20240710_production.json",
    "format": "json"
  }' > baseline_diff.json

# Analyze file integrity risks
curl -X POST /api/security/baseline/analyze \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/app",
    "patterns": ["*.py", "*.conf"],
    "limit": 200
  }'
```

#### Using the File Integrity Service

The platform provides a service layer for programmatically working with file integrity:

```python
from services import FileIntegrityService

# Verify integrity
result = FileIntegrityService.verify_integrity(
    baseline_path="instance/security/baseline.json",
    report_critical=True,    # Report critical violations to security team
    check_permissions=True   # Also verify file permissions
)

if not result.is_valid:
    print(f"Found {len(result.violations)} integrity violations")
    for violation in result.violations:
        print(f"File: {violation.file_path}, Severity: {violation.severity}")

# Update baseline with enhanced notification and audit capabilities
result = FileIntegrityService.update_baseline_with_notifications(
    baseline_path="instance/security/baseline.json",
    changes=[
        {"path": "app.py", "current_hash": "abc123...", "severity": "medium"},
        {"path": "config.py", "current_hash": "def456...", "severity": "high"}
    ],
    remove_missing=True,
    notify=True,
    audit=True,
    severity_threshold="medium",
    reason="Weekly security review"
)

print(f"Update result: {result.success}")
print(f"Updated {result.stats.changes_applied} files, removed {result.stats.removed_entries} entries")
```

For detailed file integrity documentation, see `file-integrity-monitoring.md`.

## Integration Capabilities

### Webhook System

The platform includes a webhook system allowing external systems to receive real-time notifications about events:

| Event Category | Description | Examples |
| --- | --- | --- |
| Cloud Resources | Resource lifecycle events | `resource.created`, `resource.updated` |
| Alerts | Alert state changes | `alert.triggered`, `alert.resolved` |
| Security | Security-related events | `security.incident`, `security.integrity.violation` |
| ICS | Industrial control system events | `ics.reading`, `ics.state.change` |
| System | Platform system events | `system.backup.completed` |

Webhooks feature HMAC signature verification, automatic retries, and delivery confirmation. For detailed webhook documentation, see `webhooks.md`.

### Cloud Providers

The platform integrates with multiple cloud providers:

- **AWS**: EC2, S3, RDS, Lambda, and other AWS services
- **Azure**: Virtual Machines, Storage Accounts, SQL Database, and other Azure services
- **Google Cloud Platform**: Compute Engine, Cloud Storage, Cloud SQL, and other GCP services
- **On-premises**: Custom integrations with on-premises infrastructure

## Compliance

The platform is designed to help meet requirements from:

- ISO 27001/27002
- SOC 2 Type II
- GDPR
- NIST Cybersecurity Framework
- PCI DSS (where applicable)

Compliance features include comprehensive audit logging, encryption for sensitive data, role-based access control, and security monitoring capabilities.

For compliance documentation, see `compliance.md`.

## Scripts & Utilities

The platform includes various scripts for automation, maintenance, compliance checking, and security management organized in the scripts directory:

### Core Scripts

- **`common/config_loader.sh`**: Loads environment-specific configuration files
- **`common/logging_utils.sh`**: Provides standardized logging with multiple levels
- **`common/validation_utils.sh`**: Validates and sanitizes input data
- **`file_integrity_checker.sh`**: Monitors file changes to ensure integrity
- **`security_audit.sh`**: Performs security audits to identify vulnerabilities

### Compliance Scripts

- **`generate-report.sh`**: Generates compliance reports in HTML or JSON format
- **`validate_compliance.sh`**: Validates configurations against compliance standards

### Database Scripts

- **`optimize.sh`**: Performs database optimization tasks including VACUUM, index rebuilding
- **`verify-backups.sh`**: Validates the integrity of database backups

### Deployment Scripts

- **`config_validator.sh`**: Validates configuration files against schemas
- **`configure_resources.sh`**: Configures cloud resources based on environment settings
- **`rollback.sh`**: Handles application rollback to a previous version
- **`update-dns.sh`**: Updates DNS records for disaster recovery failover

### Security Scripts

- **`update_file_baseline.sh`**: Updates the file integrity baseline with current file states
- **`integrity_report.sh`**: Generates detailed integrity reports with change analysis
- **`validate_baseline.sh`**: Validates the consistency and format of baseline files
- **`rotate_baseline.sh`**: Creates and manages baseline rotation with retention policies

Example script usage:

```bash
# Validate configuration files
./scripts/deployment/config/config_validator.sh --environment production

# Validate compliance with PCI DSS
./scripts/compliance/validate_compliance.sh --standard pci-dss --report compliance-report.json

# Generate file integrity report
./scripts/security/integrity_report.sh --format html --output integrity-report.html

# Update security baseline for specific directories
./scripts/security/update_file_baseline.sh --dirs config,core/security --remove-missing
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test categories
python -m pytest tests/unit
python -m pytest tests/integration
python -m pytest tests/security

# Run file integrity tests
python -m pytest tests/security/test_file_integrity.py
```

### Code Style

The project follows PEP 8 style guidelines with some exceptions defined in `setup.cfg`.

```bash
# Check code style
flake8

# Format code
black .
```

## Contributing

Please see `CONTRIBUTING.md` for details on our code of conduct and the process for submitting pull requests.

## Support

For support, please create an issue in the GitHub repository or contact the development team.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Documentation

For more detailed documentation, see these key resources:

- Architecture Overview
- API Documentation
- Deployment Guide
- Security Overview
- File Integrity Monitoring Guide
- User Guide
