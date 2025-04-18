# Deployment CLI

The deployment CLI provides commands for deploying, updating, and managing the Cloud Infrastructure Platform across different cloud providers and environments.

## Overview

The CLI is organized into the following command groups:

- `aws`: AWS deployment commands
- `azure`: Azure deployment commands
- `gcp`: Google Cloud Platform deployment commands
- `k8s`: Kubernetes deployment commands
- `docker`: Docker container commands
- `general`: Provider-agnostic deployment commands

## Prerequisites

- Python 3.8+
- Required cloud provider SDKs installed:
  - AWS CLI (for AWS deployments)
  - Azure CLI (for Azure deployments)
  - Google Cloud SDK (for GCP deployments)
- Docker and Docker Compose (for container operations)
- kubectl (for Kubernetes deployments)

## Usage

### General Commands

```bash
# Prepare application for deployment
flask deploy general prepare --env production

# List available environments
flask deploy general list

# Validate configuration files
flask deploy general validate --env production
```

### AWS Deployments

```bash
# Deploy to AWS using CloudFormation
flask deploy aws deploy --env production --region us-west-2

# Check AWS deployment status
flask deploy aws status --env production

# Tear down AWS deployment
flask deploy aws teardown --env production
```
### Azure Deployments

```bash
# Deploy to Azure using ARM templates
flask deploy azure deploy --env production --resource-group my-resource-group

# Check Azure deployment status
flask deploy azure status --env production

# Tear down Azure deployment
flask deploy azure teardown --env production
```

### GCP Deployments

```bash
# Deploy to GCP using Deployment Manager
flask deploy gcp deploy --env production --project my-gcp-project

# Check GCP deployment status
flask deploy gcp status --env production

# Tear down GCP deployment
flask deploy gcp teardown --env production
```

### Kubernetes Deployments

```bash
# Deploy to Kubernetes cluster
flask deploy k8s deploy --env production --namespace my-namespace

# Check Kubernetes deployment status
flask deploy k8s status --env production

# Tear down Kubernetes deployment
flask deploy k8s teardown --env production
```

### Docker Operations

```bash
# Build Docker image
flask deploy docker build --env production --push --registry my-registry

# Run Docker Compose operations
flask deploy docker compose --env production --action up

# Clean up Docker resources
flask deploy docker prune
```
