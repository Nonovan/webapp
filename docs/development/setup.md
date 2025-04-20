# Development Environment Setup Guide

This document provides step-by-step instructions for setting up your development environment for the Cloud Infrastructure Platform.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Initial Setup](#initial-setup)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Development Tools](#development-tools)
- [Testing](#testing)
- [Common Issues](#common-issues)
- [Advanced Configuration](#advanced-configuration)
- [IDE Configuration](#ide-configuration)

## Prerequisites

Before you begin, ensure you have the following software installed on your system:

- Python 3.8 or higher
- pip (Python package manager)
- PostgreSQL 12 or higher
- Redis 6.0 or higher
- Git
- Node.js 14+ (for frontend assets)
- Docker and Docker Compose (optional, for containerized development)

### Operating System-Specific Instructions

#### Linux (Ubuntu/Debian)

```bash
# Update package index
sudo apt update

# Install Python and development tools
sudo apt install python3 python3-pip python3-venv python3-dev build-essential

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Install Redis
sudo apt install redis-server

# Install Git
sudo apt install git

# Install Node.js
curl -fsSL <https://deb.nodesource.com/setup_16.x> | sudo -E bash -
sudo apt install nodejs

```

### macOS

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL <https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh>)"

# Install Python
brew install python

# Install PostgreSQL
brew install postgresql
brew services start postgresql

# Install Redis
brew install redis
brew services start redis

# Install Git
brew install git

# Install Node.js
brew install node

```

### Windows

1. Download and install Python from [python.org](https://www.python.org/downloads/)
2. Download and install PostgreSQL from [postgresql.org](https://www.postgresql.org/download/windows/)
3. Download and install Redis using [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/install) or [Redis Windows](https://github.com/tporadowski/redis/releases)
4. Download and install Git from [git-scm.com](https://git-scm.com/download/win)
5. Download and install Node.js from [nodejs.org](https://nodejs.org/)

## Initial Setup

### Clone the Repository

```bash
# Clone the repository
git clone <https://github.com/username/cloud-platform.git>

# Navigate to the project directory
cd cloud-platform

```

### Create Virtual Environment

```bash
# Create a Python virtual environment
python3 -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\\Scripts\\activate

```

### Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install main dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

```

## Configuration

### Setup Environment Variables

Copy the example development environment file:

```bash
cp deployment/environments/development.env.example deployment/environments/.env

```

Edit the .env file to configure your local development settings:

```bash
# Core settings
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=DEBUG

# Database connection
DATABASE_URL=postgresql://dev_user:dev_password@localhost/cloud_platform_development

# Redis connection
REDIS_URL=redis://localhost:6379/0

# Security settings - replace with your own secure values
SECRET_KEY=your-local-dev-secret-key
JWT_SECRET_KEY=your-local-dev-jwt-secret-key

# Feature flags
FEATURE_DARK_MODE=true
FEATURE_ICS_CONTROL=true
FEATURE_CLOUD_MANAGEMENT=true
FEATURE_MFA=true

# Development-specific settings
FLASK_ENV=development
FLASK_DEBUG=1
DEBUG_TB_ENABLED=true
DEBUG_TB_INTERCEPT_REDIRECTS=false

# Email settings - use mailhog or similar for local development
MAIL_SERVER=localhost
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_USE_TLS=false
MAIL_USE_SSL=false

# Static asset settings
STATIC_FOLDER=./static
UPLOAD_FOLDER=./uploads

```

## Database Setup

### Create Database

```bash
# For PostgreSQL, create a new database
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE DATABASE cloud_platform_development;
CREATE USER dev_user WITH PASSWORD 'dev_password';
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_development TO dev_user;

# Exit PostgreSQL
\\q

```

### Initialize Database

```bash
# Initialize database migrations
flask db init

# Generate initial migration
flask db migrate -m "Initial migration"

# Apply migrations
flask db upgrade

```

### Create Admin User

```bash
# Create an admin user for development
flask create-admin

```

## Running the Application

### Start Development Server

```bash
# Run the Flask development server
flask run

# Alternatively, using the Makefile
make run

```

Access the application at [http://localhost:5000](http://localhost:5000/)

### Run with Docker (Alternative)

If you prefer using Docker for development:

```bash
# Build and start Docker containers
docker-compose -f docker-compose.dev.yml up -d

# Apply migrations in the Docker container
docker-compose -f docker-compose.dev.yml exec app flask db upgrade

# Create admin user in the Docker container
docker-compose -f docker-compose.dev.yml exec app flask create-admin

```

## Development Tools

### Code Linting

The project uses flake8 and pylint for code quality:

```bash
# Run flake8
flake8 .

# Run pylint
pylint app.py api core models services

# Run all linters using the Makefile
make lint

```

### Code Formatting

The project uses black and isort for code formatting:

```bash
# Format code with black
black .

# Sort imports with isort
isort .

```

### Documentation Generation

Generate documentation locally:

```bash
# Build documentation
make docs

```

Access the documentation at `docs/_build/html/index.html`

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage report
pytest --cov=. --cov-report=html --cov-report=term tests/

# Run tests with coverage using the Makefile
make coverage

```

### Test Database

The tests use an in-memory SQLite database by default. To use PostgreSQL for testing:

```bash
# Create test database
createdb cloud_platform_test

# Configure test settings in .env
TEST_DATABASE_URL=postgresql://dev_user:dev_password@localhost/cloud_platform_test

```

## Common Issues

### Database Connection Issues

If you encounter database connection issues:

1. Verify PostgreSQL is running: `pg_isready`
2. Check your connection string in the .env file
3. Ensure the database user has proper permissions
4. For Docker: ensure the correct host is set (usually `db` instead of `localhost`)

### Dependency Conflicts

If you encounter dependency conflicts:

1. Create a fresh virtual environment
2. Update pip to the latest version
3. Install dependencies in order: `pip install -r requirements.txt && pip install -r requirements-dev.txt`

### Port Already in Use

If port 5000 is already in use:

```bash
# Specify a different port
flask run --port=5001

# Or modify your .env file
FLASK_RUN_PORT=5001

```

## Advanced Configuration

### Cloud Provider Development

To develop with cloud provider integrations:

1. Create credentials for the relevant cloud provider:
    - AWS: Set up `~/.aws/credentials` or use environment variables
    - Azure: Create a service principal and configure environment variables
    - GCP: Set up a service account key and configure `GOOGLE_APPLICATION_CREDENTIALS`
2. Update your .env file with the appropriate values:
    
    ```
    # AWS Configuration
    AWS_ACCESS_KEY_ID=your-access-key
    AWS_SECRET_ACCESS_KEY=your-secret-key
    AWS_DEFAULT_REGION=us-west-2
    
    # Azure Configuration
    AZURE_SUBSCRIPTION_ID=your-subscription-id
    AZURE_TENANT_ID=your-tenant-id
    AZURE_CLIENT_ID=your-client-id
    AZURE_CLIENT_SECRET=your-client-secret
    
    # GCP Configuration
    GCP_PROJECT_ID=your-project-id
    GOOGLE_APPLICATION_CREDENTIALS=./instance/gcp-credentials.json
    
    ```
    

### Working with Feature Flags

The platform uses feature flags to enable/disable functionality during development:

```python
# Example of using a feature flag in code
from config import Config

if Config.FEATURE_DARK_MODE:
    # Dark mode code
else:
    # Light mode code

```

Toggle features in your .env file:

```
FEATURE_DARK_MODE=true
FEATURE_ICS_CONTROL=false

```

## IDE Configuration

### Visual Studio Code

1. Install recommended extensions:
    - Python
    - Pylance
    - Python Test Explorer
    - markdownlint
    - GitLens
2. Configure settings (`.vscode/settings.json`):
    
    ```json
    {
      "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
      "python.linting.enabled": true,
      "python.linting.flake8Enabled": true,
      "python.linting.pylintEnabled": true,
      "python.formatting.provider": "black",
      "python.testing.pytestEnabled": true,
      "editor.formatOnSave": true,
      "editor.codeActionsOnSave": {
        "source.organizeImports": true
      }
    }
    
    ```
    

### PyCharm

1. Set up the project interpreter:
    - Go to Settings/Preferences → Project → Python Interpreter
    - Add the virtual environment as the interpreter
2. Configure code style:
    - Go to Settings/Preferences → Editor → Code Style → Python
    - Import the project's `.editorconfig` file
3. Set up testing:
    - Go to Settings/Preferences → Tools → Python Integrated Tools
    - Set Default test runner to pytest
4. Run Configurations:
    - Create a Flask Server configuration
    - Set the FLASK_APP environment variable to [app.py](http://app.py/)
    - Enable Flask debug mode

## Getting Help

If you encounter issues not covered in this guide:

- Check the troubleshooting documentation
- Reach out to the development team on the internal Slack channel (#cloud-platform-dev)
- Submit an issue in the GitHub repository
- Consult the API documentation for interface details