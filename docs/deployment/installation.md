# Installation Guide

This document provides step-by-step instructions for installing the Cloud Infrastructure Platform across different environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
  - [Standard Installation](#standard-installation)
  - [Docker Installation](#docker-installation)
  - [Kubernetes Installation](#kubernetes-installation)
- [Environment-Specific Installation](#environment-specific-installation)
  - [Development Environment](#development-environment)
  - [Staging Environment](#staging-environment)
  - [Production Environment](#production-environment)
- [Cloud Provider Installation](#cloud-provider-installation)
  - [AWS Installation](#aws-installation)
  - [Azure Installation](#azure-installation)
  - [Google Cloud Installation](#google-cloud-installation)
- [Post-Installation Configuration](#post-installation-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Next Steps](#next-steps)

## Prerequisites

Before beginning the installation, ensure you have the following:

### Software Requirements

- Python 3.8 or higher
- pip (Python package manager)
- PostgreSQL 12 or higher
- Redis 6.0 or higher (for caching and message queues)
- NGINX (for production deployments)
- Git

### Account Requirements

- Admin access to the target systems
- Database admin credentials
- Cloud provider accounts (if deploying to cloud)
- Docker Hub account (if using Docker)

### Network Requirements

- Outbound internet access for package downloads
- Required ports open for internal communication
- Domain names configured (for production)

## System Requirements

The hardware requirements depend on your deployment size and expected load:

| Environment | CPU | Memory | Disk Space | Network |
|-------------|-----|--------|------------|---------|
| Development | 2 cores | 4 GB | 20 GB | 100 Mbps |
| Staging | 4 cores | 8 GB | 50 GB | 1 Gbps |
| Production (Small) | 8 cores | 16 GB | 100 GB | 1 Gbps |
| Production (Medium) | 16 cores | 32 GB | 250 GB | 10 Gbps |
| Production (Large) | 32+ cores | 64+ GB | 500+ GB | 10+ Gbps |

For detailed architectural requirements, see the [Architecture Overview](/docs/architecture/architecture-overview.md).

## Installation Methods

### Standard Installation

#### 1. Clone the Repository

```bash
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt

```

### 4. Configure Environment

```bash
cp deployment/environments/production.env.example deployment/environments/production.env
# Edit the .env file with appropriate configuration values
nano deployment/environments/production.env

```

### 5. Initialize Database

```bash
flask db init
flask db migrate
flask db upgrade

```

### 6. Create Admin User

```bash
flask create-admin

```

### 7. Collect Static Assets

```bash
./scripts/deployment/collect_static.sh

```

### 8. Start Application Server

For development:

```bash
flask run

```

For production:

```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app

```

### Docker Installation

### 1. Clone the Repository

```bash
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

```

### 2. Configure Environment

```bash
cp deployment/environments/production.env.example deployment/environments/.env
# Edit the .env file with appropriate configuration values
nano deployment/environments/.env

```

### 3. Build and Start Docker Containers

```bash
docker-compose build
docker-compose up -d

```

### 4. Initialize Database

```bash
docker-compose exec app flask db upgrade

```

### 5. Create Admin User

```bash
docker-compose exec app flask create-admin

```

### Kubernetes Installation

### 1. Clone the Repository

```bash
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

```

### 2. Configure Kubernetes Manifests

Update configuration values in the Kubernetes manifests:

```bash
# Edit the ConfigMap and Secret resources
nano deployment/kubernetes/manifests/configmap.yaml
nano deployment/kubernetes/manifests/secrets.yaml

```

### 3. Apply Kubernetes Manifests

```bash
kubectl apply -f deployment/kubernetes/manifests/namespace.yaml
kubectl apply -f deployment/kubernetes/manifests/configmap.yaml
kubectl apply -f deployment/kubernetes/manifests/secrets.yaml
kubectl apply -f deployment/kubernetes/manifests/postgres.yaml
kubectl apply -f deployment/kubernetes/manifests/redis.yaml
kubectl apply -f deployment/kubernetes/manifests/app.yaml
kubectl apply -f deployment/kubernetes/manifests/service.yaml
kubectl apply -f deployment/kubernetes/manifests/ingress.yaml

```

### 4. Initialize Database

```bash
# Find the pod name
POD_NAME=$(kubectl get pods -l app=cloud-platform -o jsonpath='{.items[0].metadata.name}')

# Run migrations
kubectl exec $POD_NAME -- flask db upgrade

# Create admin user
kubectl exec -it $POD_NAME -- flask create-admin

```

## Environment-Specific Installation

### Development Environment

For local development setup:

```bash
# Clone repository
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Configure development environment
cp deployment/environments/development.env.example deployment/environments/development.env
# Edit the .env file with appropriate configuration values

# Initialize database
flask db upgrade

# Start development server
flask run

```

### Staging Environment

For a staging environment deployment:

```bash
# Use the deployment script with staging environment
./scripts/deployment/deploy.sh staging

```

Or manually:

```bash
# Clone repository
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

# Check out the appropriate branch or tag
git checkout staging  # or specific tag

# Configure staging environment
cp deployment/environments/staging.env.example deployment/environments/staging.env
# Edit the .env file with appropriate configuration values

# Run the deployment script
./scripts/deployment/pre_deploy_check.sh staging
./scripts/deployment/deploy.sh staging
./scripts/deployment/post_deploy_check.sh staging

```

### Production Environment

For a production environment deployment:

```bash
# Use the deployment script with production environment
./scripts/deployment/deploy.sh production

```

Or manually:

```bash
# Clone repository
git clone <https://github.com/username/cloud-platform.git>
cd cloud-platform

# Check out the latest stable tag
git checkout v1.0.0  # replace with actual version

# Configure production environment
cp deployment/environments/production.env.example deployment/environments/production.env
# Edit the .env file with appropriate configuration values

# Run database migrations
flask db upgrade

# Collect static files
./scripts/deployment/collect_static.sh

# Install the application as a service
sudo cp deployment/systemd/cloud-platform.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloud-platform
sudo systemctl start cloud-platform

# Configure NGINX
sudo cp deployment/nginx/sites-available/cloud-platform.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/cloud-platform.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

```

## Cloud Provider Installation

### AWS Installation

### Using CloudFormation

```bash
# Configure AWS credentials
aws configure

# Deploy the CloudFormation stack
aws cloudformation deploy \\
  --template-file deployment/infrastructure/aws/cloudformation/main.yaml \\
  --stack-name cloud-platform-production \\
  --parameter-overrides \\
    Environment=production \\
    InstanceType=t3.large \\
    VpcId=vpc-12345 \\
    SubnetIds=subnet-12345,subnet-67890 \\
  --capabilities CAPABILITY_IAM

```

### Using Terraform

```bash
cd deployment/infrastructure/aws/terraform

# Initialize Terraform
terraform init

# Create workspace if not exists
terraform workspace new production || terraform workspace select production

# Plan deployment
terraform plan -var-file=environments/production.tfvars -out=tfplan

# Apply deployment
terraform apply tfplan

```

### Azure Installation

```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "Your Subscription Name"

# Create resource group
az group create --name cloud-platform-rg --location eastus

# Deploy ARM template
az deployment group create \\
  --name cloud-platform-deployment \\
  --resource-group cloud-platform-rg \\
  --template-file deployment/infrastructure/azure/arm-templates/main.json \\
  --parameters @deployment/infrastructure/azure/arm-templates/parameters.production.json

```

### Google Cloud Installation

```bash
# Login to Google Cloud
gcloud auth login

# Set project
gcloud config set project your-project-id

# Deploy using Deployment Manager
gcloud deployment-manager deployments create cloud-platform-production \\
  --template deployment/infrastructure/gcp/deployment-manager/main.py \\
  --properties environment:production

```

## Post-Installation Configuration

### Security Hardening

Apply security hardening measures for production:

```bash
# Run security setup script
sudo bash deployment/security/security_setup.sh production

# Verify security configuration
sudo bash deployment/security/security-audit.sh --env production

```

### SSL/TLS Certificate

Set up SSL/TLS certificates:

```bash
# Set up certificates
sudo bash deployment/nginx/scripts/setup-ssl.sh --environment production

# Test SSL configuration
curl <https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com>

```

### Web Application Firewall

Configure ModSecurity WAF:

```bash
sudo bash deployment/security/setup-modsecurity.sh --mode prevention

```

## Verification

After installation, verify the application is working correctly:

### Health Check

```bash
# Check application health endpoint
curl <http://localhost:5000/api/health>

```

### Smoke Tests

```bash
# Run basic smoke tests
./scripts/deployment/smoke-test.sh production

```

### Full Test Suite

```bash
# Run the full test suite
pytest

```

## Troubleshooting

### Common Installation Issues

| Problem | Solution |
| --- | --- |
| Database connection error | Check database credentials and network connectivity |
| Missing dependencies | Run `pip install -r requirements.txt` to ensure all dependencies are installed |
| Permission errors | Ensure the application user has appropriate permissions for all directories |
| Port conflicts | Check if another service is using the required ports |
| SSL certificate errors | Verify certificate files are correctly installed and paths are properly configured |

### Log Files

Check the following log files for error messages:

- Application logs: `/var/log/cloud-platform/app.log`
- NGINX logs: `/var/log/nginx/error.log`
- System logs: `journalctl -u cloud-platform.service`

### Getting Help

If you encounter issues not covered in this guide:

- Check the Troubleshooting Guide
- Search the [Issue Tracker](https://github.com/username/cloud-platform/issues)
- Contact support at [support@example.com](mailto:support@example.com)

## Next Steps

After successful installation, you may want to:

- Configure monitoring
- Set up backup and recovery
- Configure user authentication
- Set up automated deployments

For additional configuration options, see the Configuration Guide.