# Models Package

The models package provides the data model layer for the Cloud Infrastructure Platform using SQLAlchemy ORM. It implements a structured domain-driven design approach to organize database models.

## Overview

This package defines the application's data model layer with a focus on:

- Domain separation through subdirectories
- Common base functionality through inheritance
- Comprehensive type annotations and documentation
- Security and audit features

## Directory Structure

```plaintext
models/
├── __init__.py              # Package exports and event listeners
├── base.py                  # Base model classes and mixins
├── README.md                # Documentation (this file)
├── auth/                    # Authentication and user management
│   ├── __init__.py          # Auth module exports
│   ├── permission.py        # Permission model for RBAC
│   ├── role.py              # Role model for access control
│   ├── user.py              # User account model
│   ├── user_activity.py     # User activity logging
│   └── user_session.py      # User session tracking
├── cloud/                   # Cloud infrastructure models
│   ├── __init__.py          # Cloud module exports
│   ├── cloud_alert.py       # Alert configurations
│   ├── cloud_metric.py      # Resource metrics and monitoring
│   ├── cloud_provider.py    # Cloud provider configurations
│   └── cloud_resource.py    # Infrastructure resources
├── communication/           # Communication-related models
│   ├── __init__.py          # Communication module exports
│   ├── newsletter.py        # Newsletter subscribers and lists
│   ├── notification.py      # User notifications
│   ├── subscriber.py        # Subscriber management
│   └── webhook.py           # Webhook subscriptions
├── content/                 # Content management models
│   ├── __init__.py          # Content module exports
│   ├── category.py          # Content categorization
│   ├── post.py              # Blog/news post content
│   └── tag.py               # Content tagging
├── ics/                     # Industrial Control Systems
│   ├── __init__.py          # ICS module exports
│   ├── ics_control_log.py   # Control operation logging
│   ├── ics_device.py        # ICS device inventory
│   └── ics_reading.py       # Sensor readings and telemetry
├── security/                # Security-related models
│   ├── __init__.py          # Security module exports
│   ├── audit_log.py         # Security audit records
│   ├── security_incident.py # Security incidents
│   └── system_config.py     # Security configurations
└── storage/                 # Storage-related models
    ├── __init__.py          # Storage module exports
    └── file_upload.py       # File upload tracking

```

## Key Components

1. **Base Classes (`base.py`)**:
    - `BaseModel`: Core base class that all models inherit from
    - `TimestampMixin`: Provides automatic timestamp tracking
    - `AuditableMixin`: Adds security auditing capabilities
2. **Authentication (`auth/`)**:
    - User management and authentication
    - Role-based access control (RBAC)
    - Permission management
    - Session tracking and management
    - User activity logging
3. **Cloud Infrastructure (`cloud/`)**:
    - Cloud provider configurations (AWS, Azure, GCP)
    - Resource management (VMs, storage, etc.)
    - Metrics collection and alerting
    - Cost tracking and monitoring
4. **Communication (`communication/`)**:
    - Newsletter management
    - User notification systems
    - Subscriber management
    - Webhook integrations
5. **Content Management (`content/`)**:
    - Blog posts and content articles
    - Content categorization
    - Hierarchical category structure
    - Content tagging
6. **Industrial Control Systems (`ics/`)**:
    - Device inventory management
    - Sensor reading collection
    - Control operation logging
7. **Security (`security/`)**:
    - Security incident tracking
    - Comprehensive audit logging
    - System configuration management
    - Security controls
8. **Storage (`storage/`)**:
    - File upload tracking and management
    - File scanning and validation

## Notable Files

- **`__init__.py`**: Main package initialization with event listeners for audit logging
- **`base.py`**: Contains the core base classes and mixins
- **`auth/permission.py`**: Fine-grained permission model for RBAC
- **`auth/role.py`**: Role model with permission inheritance
- **`security/audit_log.py`**: Comprehensive security auditing system
- **`cloud/cloud_resource.py`**: Cloud resource management with cost tracking
- **`security/system_config.py`**: System-wide configuration storage

## Implementation Notes

- All models inherit from `BaseModel` which provides common CRUD operations
- Security-sensitive models also use the `AuditableMixin` for automatic audit logging
- Most models implement a `to_dict()` method for serialization
- Many models include comprehensive validation and error handling
- Several domains implement specialized features:
  - Cloud models include cost and security monitoring
  - Security models have built-in alerting and incident management
  - Content models support hierarchical structures
  - Storage models include file validation and security scanning
  - Auth models implement full RBAC with permission inheritance

## Key Features

- **Structured Organization**: Models are grouped by domain for better maintainability
- **Common Base Model**: All models inherit from `BaseModel` for consistent behavior
- **Type Annotations**: Comprehensive typing for IDE support and type checking
- **Audit Tracking**: `AuditableMixin` provides security audit capabilities
- **Serialization**: Standard `to_dict()` methods for API responses
- **Event Listeners**: Automatic timestamp tracking and audit logging
- **Role-Based Access Control**: Complete RBAC implementation with roles and permissions

## Base Model Structure

All models inherit from the `BaseModel` class, which provides:

- Core CRUD operations (save, update, delete)
- Timestamp tracking (created_at, updated_at)
- Type annotations for better IDE support
- Common query methods
- JSON serialization via `to_dict()`

```python
from models.base import BaseModel

class MyModel(BaseModel):
    __tablename__ = 'my_model'

    # Define fields...

    # Define relationships...

```

## Usage Examples

### Basic Model Operations

```python
from models import User, Post, CloudResource

# Create a new user
user = User(username="username", email="user@example.com")
user.save()

# Query resources by type
resources = CloudResource.get_by_type("vm", active_only=True)

# Update an existing model
post = Post.query.filter_by(slug="welcome-post").first()
post.title = "Updated Title"
post.save()

# Delete a model instance
user_session = UserSession.query.get(session_id)
user_session.delete()

```

### Working with Relationships

```python
# Create related objects
category = Category(name="Technology")
category.save()

post = Post(title="New Tech Post", category_id=category.id)
post.save()

# Query with joins
tech_posts = Post.query.join(Category).filter(
    Category.name == "Technology"
).all()

# Using relationship properties
for subscriber in newsletter_list.subscribers:
    print(f"Sending to: {subscriber.email}")

```

### Role-Based Access Control

```python
# Create a permission
view_reports = Permission(name="reports:view", description="View system reports")
view_reports.save()

# Create a role with permissions
analyst_role = Role(name="Analyst", description="Data analyst")
analyst_role.add_permission(view_reports)
analyst_role.save()

# Assign role to user
user = User.query.filter_by(email="analyst@example.com").first()
user.assign_role(analyst_role)

# Check permissions
if user.has_permission("reports:view"):
    print("User can view reports")

```

### Security-Enhanced Models

```python
# Create an audited model instance
incident = SecurityIncident(
    title="Unauthorized Access Attempt",
    severity="HIGH",
    description="Multiple failed login attempts detected"
)
incident.save()  # Automatically logs the creation event

```

## Security Considerations

- **Encrypted Fields**: Sensitive fields are encrypted at rest using AES-256
- **Password Protection**: Password fields use Argon2 hashing with appropriate work factors
- **Audit Logging**: Security-critical operations are automatically logged
- **Access Control**: Model access is controlled through the `AuditableMixin`
- **Input Validation**: Field validations prevent invalid or harmful data
- **SQL Injection Prevention**: All queries use parameterized statements
- **Session Management**: Secure session handling with proper timeout and rotation
- **Permission Model**: Fine-grained permission system with resource:action pattern
- **Role Hierarchy**: Supports role inheritance for complex permission structures

## Contributing New Models

When adding new models:

1. Determine the appropriate domain subdirectory
2. Inherit from appropriate base classes
3. Include comprehensive docstrings
4. Add type annotations for all fields and methods
5. Implement required validation logic
6. Add the model to **init**.py exports
7. Consider security implications and add to audit listeners if needed
8. Write unit tests for the model's functionality

## Related Documentation

- Database Migration Guide
- Security Controls
- API Documentation
- Authentication Guide
