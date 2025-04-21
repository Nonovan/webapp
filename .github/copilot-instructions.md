# GitHub Copilot Instructions for Cloud Infrastructure Platform

## Project Overview

This repository contains a Python Flask web application for cloud infrastructure management. The application provides secure management of resources across multiple cloud providers (AWS, Azure, GCP), with features for monitoring, security, and compliance.

## Code Structure

- api - RESTful API endpoints and API-related functionality
- blueprints - Flask blueprints for different application modules
- cli - Command-line interface tools
- config - Configuration management
- core - Core utilities and security functions
- deployment - Deployment scripts and infrastructure configuration
- docs - Documentation files
- extensions - Flask extensions
- models - Database models
- scripts - Utility scripts for maintenance, security, compliance, etc.
- services - Business logic services
- static - Static assets (CSS, JS, images)
- tests - Automated tests
- views - View helpers and template utilities

## Coding Standards

Please follow these standards when generating code:

### Python

- Follow PEP 8 style guidelines
- Use type hints for function parameters and return values
- Include docstrings for all functions, classes, and modules
- Handle exceptions appropriately with specific exception types
- Use context managers for resource cleanup when appropriate
- Write unit tests for new functionality
- Prioritize security in all code (input validation, output encoding, etc.)

### JavaScript

- Use modern ES6+ syntax
- Prefer const over let, and avoid var
- Use async/await for asynchronous operations
- Validate user input
- Include CSP nonce in inline scripts
- Implement proper CSRF protection
- Use strict mode ('use strict')

### HTML/Templates

- Follow HTML5 standards
- Include proper ARIA attributes for accessibility
- Use Bootstrap 5 components and utility classes
- Implement responsive designs

### Security Practices

- Implement strict Content Security Policy
- Validate all user inputs
- Sanitize outputs to prevent XSS
- Use parameterized queries to prevent SQL injection
- Implement proper authentication checks
- Use CSRF tokens for all forms
- Follow the principle of least privilege

## Organization Preferences

- Organize files by feature area and functionality
- Keep related code together when possible
- Prefer smaller, focused functions over large, complex ones
- Use dependency injection for better testability
- Implement proper error handling and logging
- Document complex logic with comments
- Use configuration files for environment-specific settings

## Specific Guidance

### Scripts Directory

- Place deployment-related scripts in deployment
- Put DR (disaster recovery) scripts in dr
- Put security-related scripts in security
- Put compliance scripts in compliance
- Place monitoring scripts in monitoring
- Put core reusable functions in core
- Place utility scripts in utils

### Documentation

- Include [README.md](http://readme.md/) files in each directory explaining its purpose
- Document API endpoints with examples
- Include security considerations in component documentation

### Testing

- Write unit tests for all new functionality
- Include integration tests for critical paths
- Add security tests for authentication and authorization
- Document test coverage requirements

## Architectural Patterns

- Follow a layered architecture (presentation, business logic, data access)
- Use the repository pattern for data access
- Implement service layers for business logic
- Use dependency injection for better testability
- Follow RESTful design principles for APIs

By following these guidelines, you'll help maintain consistency and quality throughout the codebase.