# Models Package

The models package provides the data model layer for the Cloud Infrastructure Platform using SQLAlchemy ORM. It implements a structured domain-driven design approach to organize database models.

## Overview

This package defines the application's data model layer with a focus on:
- Domain separation through subdirectories
- Common base functionality through inheritance
- Comprehensive type annotations and documentation
- Security and audit features

## Directory Structure

- **base.py** - Base model classes and mixins
- **auth/** - User authentication and activity tracking
- **cloud/** - Cloud infrastructure resources and monitoring
- **content/** - Content management (posts, pages)
- **communication/** - Notifications and subscriptions
- **ics/** - Industrial Control Systems models
- **security/** - Security, auditing, and system configuration

## Key Features

- **Structured Organization**: Models are grouped by domain for better maintainability
- **Common Base Model**: All models inherit from `BaseModel` for consistent behavior
- **Type Annotations**: Comprehensive typing for IDE support and type checking
- **Audit Tracking**: `AuditableMixin` provides security audit capabilities
- **Serialization**: Standard `to_dict()` methods for API responses
- **Event Listeners**: Automatic timestamp tracking and audit logging

## Usage

Models can be imported directly from the package:

```python
from models import User, Post, CloudResource

# Create a new user
user = User(username="username", email="user@example.com")
user.save()

# Query resources by type
resources = CloudResource.get_by_type("vm", active_only=True)

```

## Security Considerations

- Sensitive fields are encrypted at rest
- Password fields use strong hashing
- Security-critical operations are audit-logged
- Access to models is controlled through the `AuditableMixin`
- Model validations prevent invalid or harmful data
