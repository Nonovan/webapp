# Continuous Integration and Deployment (CI/CD)

This directory contains the configuration files, scripts, and documentation for the Cloud Infrastructure Platform's continuous integration and deployment pipeline.

## Contents

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [CI/CD Pipeline](#cicd-pipeline)
- [Environments](#environments)
- [Security Features](#security-features)
- [Usage](#usage)
- [Security Scanning](#security-scanning)
- [Integration with Deployment Scripts](#integration-with-deployment-scripts)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Overview

The CI/CD system automates building, testing, security scanning, and deploying the Cloud Infrastructure Platform. It supports multiple CI/CD providers with equivalent functionality through configuration files tailored to each provider.

## Directory Structure

```plaintext
deployment/ci/
├── .gitlab-ci.yml          # GitLab CI/CD pipeline configuration
├── Dockerfile              # Container for CI/CD operations
├── Jenkinsfile             # Jenkins pipeline configuration
├── README.md               # This documentation
├── __init__.py             # Package initialization with dependency checking
├── build_package.py        # Script to build deployment packages
├── config.yml              # Shared CI/CD configuration settings
├── dependency_check.py     # Script to analyze dependencies for vulnerabilities
├── entrypoint.sh           # Container entrypoint script
├── github-actions.yml      # GitHub Actions workflow configuration
├── pipeline.yml            # Generic pipeline configuration
├── sast_scan.py            # Script to perform static application security testing
└── sonarqube.properties    # SonarQube static analysis configuration
```

## CI/CD Pipeline

The CI/CD pipeline consists of the following stages:

1. **Prepare** - Set up the environment and install dependencies
2. **Test** - Run unit and integration tests
3. **Security** - Perform security scans and dependency checks
4. **Build** - Create deployment package and Docker images
5. **Deploy** - Deploy application to target environments
6. **Verify** - Run post-deployment checks and tests

## Environments

The pipeline supports multiple deployment environments:

- **Development** - For ongoing development work
- **Staging** - For pre-release testing
- **Production** - For live deployment

## Security Features

The pipeline includes several security measures:

- Compliance checks
- Container security scanning
- Dependency vulnerability scanning
- File integrity verification
- Package integrity monitoring
- Security test automation
- Static Application Security Testing (SAST)

## Usage

### Running Locally

You can use the Docker container to run CI/CD tasks locally:

```bash
# Build the CI container
docker build -f deployment/ci/Dockerfile -t cloud-platform-ci .

# Run a specific CI task
docker run --rm cloud-platform-ci test:unit
```

### Available Commands

The CI container supports these commands:

- `build` - Build deployment package
- `deploy:production` - Deploy to production environment
- `deploy:staging` - Deploy to staging environment
- `security` - Run security scans
- `test` - Run all tests
- `test:e2e` - Run end-to-end tests
- `test:integration` - Run integration tests
- `test:unit` - Run unit tests

## Security Scanning

### Dependency Checking

The dependency_check.py module performs comprehensive dependency security scanning with the following capabilities:

- **Vulnerability Assessment**: Scans Python dependencies using the Safety database
- **License Compliance**: Verifies that dependencies use approved licenses
- **Outdated Package Detection**: Identifies outdated packages that need updating
- **File Integrity Verification**: Detects tampering with installed packages by comparing file hashes
- **Reporting**: Generates detailed reports with findings categorized by severity

#### Dependency Checking Key Functions

- `run_safety_check()`: Scans for known security vulnerabilities
- `check_licenses()`: Verifies compliance with allowed license types
- `check_outdated_dependencies()`: Identifies packages with updates available
- `verify_dependency_integrity()`: Detects tampering with installed packages
- `generate_dependency_report()`: Creates comprehensive security reports

### Static Application Security Testing (SAST)

The sast_scan.py module performs static code analysis to identify potential security issues:

- **Multi-Tool Analysis**: Combines results from Bandit, Semgrep, and PyLint
- **Critical Path Protection**: Enhanced security checks for sensitive code paths
- **Customizable Thresholds**: Configurable severity thresholds by category
- **Integrated File Integrity**: Incorporates core file integrity verification
- **GitLab Integration**: Produces GitLab-compatible SAST reports

#### SAST Key Functions

- `run_bandit()`: Performs Python-specific security scanning
- `run_semgrep()`: Applies customizable security rule patterns
- `run_pylint()`: Applies Python code quality and security checks
- `run_safety_check()`: Identifies vulnerable dependencies
- `check_file_integrity()`: Verifies critical file integrity
- `generate_report()`: Creates comprehensive security reports

## Integration with Deployment Scripts

The CI/CD pipeline leverages the scripts in the `scripts/deployment` directory for many operations:

- Deployment execution
- Health checks
- Performance testing
- Post-deployment verification
- Pre-deployment checks
- Security auditing

## Troubleshooting

### Common Issues

- **Build Failures**: Verify dependencies are available and that the build environment has sufficient resources.
- **Deployment Failures**: Check deployment logs for error messages. Common issues include connectivity problems and permission errors.
- **Failed Tests**: Check test logs for details. Most test failures include information about the specific test and assertion that failed.
- **Security Scan Failures**: Review security reports in the artifacts. Each finding includes a severity level and recommended remediation.
- **Integrity Check Failures**: If dependency integrity checks fail, investigate possible tampering. Use the `CI_SKIP_INTEGRITY_CHECK` environment variable to bypass in exceptional cases.

### Logs and Artifacts

CI/CD runs produce several artifacts that can help with troubleshooting:

- Build packages
- Coverage reports
- Deployment logs
- Security scan reports (Dependency check and SAST)
- Test results (JUnit XML format)

## References

- [GitLab CI Documentation](https://docs.gitlab.com/ee/ci/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Jenkins Pipeline Documentation](https://www.jenkins.io/doc/book/pipeline/)
- [SonarQube Documentation](https://docs.sonarqube.org/)
- [Safety Documentation](https://github.com/pyupio/safety)
- [Bandit Documentation](https://github.com/PyCQA/bandit)
- [Semgrep Documentation](https://semgrep.dev/docs/)
