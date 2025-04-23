# Development Tools

This directory contains development tools for the Cloud Infrastructure Platform. These tools are designed to streamline development workflows, code quality, documentation, and environment setup.

## Overview

The development tools in this directory provide essential utilities for documentation generation, code quality management, and development environment setup. These tools are primarily used during development and CI/CD processes to maintain code quality and ensure proper documentation.

## Key Scripts

- **`generate_docs.sh`**: Automates documentation generation for various components
- **`lint.sh`**: Runs code linting and formatting tools on Python code
- **`setup_dev_environment.sh`**: Sets up a development environment for the platform

## Directory Structure

```
scripts/utils/dev_tools/
├── generate_docs.sh           # Documentation generation script
├── lint.sh                    # Code linting and formatting utility
├── README.md                  # This documentation
├── setup_dev_environment.sh   # Development environment setup
└── python/                    # Python helper scripts
    ├── convert_format.py      # Converts documents between formats
    ├── generate_cli_docs.py   # Generates CLI documentation
    └── process_template.py    # Processes template files with variable substitution
```

## Usage

### Documentation Generation

```bash
# Generate all documentation with verbose output
./scripts/utils/dev_tools/generate_docs.sh --verbose

# Generate HTML documentation, cleaning the output directory first
./scripts/utils/dev_tools/generate_docs.sh --format html --clean

# Generate only API documentation for specific directories
./scripts/utils/dev_tools/generate_docs.sh --api api/endpoints

# Generate only user guides and CLI documentation
./scripts/utils/dev_tools/generate_docs.sh --user-guides --cli
```

### Code Linting

```bash
# Run all linters on default directories
./scripts/utils/dev_tools/lint.sh

# Fix code formatting issues automatically
./scripts/utils/dev_tools/lint.sh --fix

# Run only security checks
./scripts/utils/dev_tools/lint.sh --security

# Check specific directories
./scripts/utils/dev_tools/lint.sh --check api/ models/
```

### Development Environment Setup

```bash
# Set up development environment with default settings
./scripts/utils/dev_tools/setup_dev_environment.sh

# Set up development environment with verbose output
./scripts/utils/dev_tools/setup_dev_environment.sh --verbose

# Set up development environment in debug mode
./scripts/utils/dev_tools/setup_dev_environment.sh --debug
```

## Configuration

The development tools read configuration from the following default locations:

- Documentation: `config/documentation.conf`
- Linting: `.flake8`, `.isort.cfg`, `pyproject.toml` (for Black), `.bandit`
- Environment Setup: `config/development.conf`

## Best Practices

- Run lint checks before committing code
- Generate documentation regularly during development
- Use a clean development environment for testing
- Run all linter checks with `--fix` before submitting pull requests
- Always verify generated documentation for accuracy

## Security Considerations

- The development tools are not intended for production use
- Environment setup tools should only be run in development environments
- Always review linting security findings carefully
- Never commit API keys or credentials to documentation templates

## Common Features

- Support for multiple output formats (markdown, HTML, RST, PDF)
- Configuration through command-line arguments and config files
- Comprehensive logging with different verbosity levels
- Support for CI/CD integration
- Cross-platform compatibility

## Python Helpers

The `python/` subdirectory contains Python scripts that support the main shell scripts:

- **`convert_format.py`**: Converts documents between different formats using Pandoc
- **`generate_cli_docs.py`**: Generates comprehensive documentation for CLI modules
- **`process_template.py`**: Processes template files with variable substitution

## Related Documentation

- Development Guide
- Documentation Standards
- Code Style Guide
