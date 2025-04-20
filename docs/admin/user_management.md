# User Management Guide

This document provides administrators with detailed instructions for managing users in the Cloud Infrastructure Platform.

## Table of Contents

- [Overview](#overview)
- [User Roles and Permissions](#user-roles-and-permissions)
- [User Management Interface](#user-management-interface)
- [User Lifecycle Management](#user-lifecycle-management)
- [Authentication Management](#authentication-management)
- [Security Considerations](#security-considerations)
- [Bulk Operations](#bulk-operations)
- [Audit and Compliance](#audit-and-compliance)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [CLI Reference](#cli-reference)

## Overview

The user management system in Cloud Infrastructure Platform allows administrators to create, update, disable, and manage user accounts, control access permissions, and enforce security policies. Proper user management is essential for maintaining platform security and ensuring appropriate resource access.

## User Roles and Permissions

### Core Roles

The platform includes the following predefined roles:

| Role | Description | Capabilities |
|------|-------------|-------------|
| **Admin** | Full system access | All platform features including user management, security settings, and system configuration |
| **Operator** | Operational access | Resource management, monitoring, and operational tasks; cannot modify system settings |
| **User** | Standard access | Basic resource access and self-service features |

### Permission Model

Permissions are assigned based on:

1. **Role-based permissions**: Core capabilities determined by user role
2. **Resource-specific permissions**: Granular access controls for specific resources
3. **Action-based permissions**: Rights to perform specific actions (view, create, modify, delete)

### Custom Roles

For organizations requiring specialized roles:

1. Navigate to **Administration → User Management → Roles**
2. Click **Create Role**
3. Specify role name, description, and base permissions
4. Save the custom role

## User Management Interface

### Accessing User Management

1. Log in with administrative credentials
2. Navigate to **Administration → User Management**
3. View the user management dashboard

### User List View

The user list displays:

- Username and email
- Role assignment
- Account status (active, inactive, locked)
- Last login time
- Multi-factor authentication status

### User Detail View

Select any user to access detailed information:

- Personal information
- Contact details
- Security settings
- Permission assignments
- Resource access history
- Audit logs specific to the user

## User Lifecycle Management

### Creating Users

#### Through Web Interface

1. Navigate to **Administration → User Management**
2. Click **Create User**
3. Fill required fields:
   - Email address (username)
   - First and last name
   - Role assignment
   - Initial password (or generate random)
4. Set additional options:
   - Require password change on first login
   - Enable/disable MFA requirement
   - Account expiration (if applicable)
5. Click **Create User**

#### Using CLI

```bash
# Interactive creation with prompts
flask user create

# Non-interactive creation with all parameters
flask user create --username=admin --email=admin@example.com --password=secret --role=admin

```

### Modifying Users

1. Find the user in the user management interface
2. Click **Edit**
3. Modify user details as required
4. Click **Save Changes**

### Deactivating Users

To temporarily disable access:

1. Find the user in the user management interface
2. Click **Deactivate Account**
3. Confirm the action

### Deleting Users

For permanent removal (use with caution):

1. Find the user in the user management interface
2. Click **Delete User**
3. Review the impact assessment (resources owned by user)
4. Confirm permanent deletion

### User Self-Registration

If enabled, users can self-register:

1. Navigate to **Administration → User Management → Settings**
2. Under **Self-Registration** section:
    - Enable/disable self-registration
    - Set default role for new registrations
    - Configure domain restrictions for registrations
    - Set approval requirements

## Authentication Management

### Password Policies

Configure password requirements:

1. Navigate to **Administration → Security Settings → Authentication**
2. Under **Password Policy** section:
    - Minimum length
    - Complexity requirements
    - Expiration period
    - Password history restrictions
    - Account lockout thresholds

### Multi-Factor Authentication

Manage MFA settings:

1. Navigate to **Administration → Security Settings → Authentication**
2. Under **Multi-Factor Authentication** section:
    - Enable/disable MFA enforcement
    - Select allowed MFA methods
    - Set rules for MFA requirement (all users, specific roles, etc.)

### Enforcing MFA for a User

1. Find the user in the user management interface
2. Click **Edit**
3. Toggle **Require MFA** setting
4. Save changes

### Password Resets

### Initiated by Administrator

1. Find the user in the user management interface
2. Click **Reset Password**
3. Choose to:
    - Set a temporary password
    - Generate a random password
    - Send password reset link
4. Confirm the action

### Using CLI

```bash
# Reset password with interactive prompt
flask user reset-password --username=john.doe

# Reset password non-interactively
flask user reset-password --username=john.doe --password=newpassword --temporary

```

## Security Considerations

### Session Management

Control user sessions:

1. Navigate to **Administration → Security Settings → Sessions**
2. Configure:
    - Session timeout duration
    - Concurrent session limits
    - IP binding options
    - Forced re-authentication for sensitive operations

### Monitoring User Activity

View user activity:

1. Navigate to **Administration → Audit & Logs → User Activity**
2. Filter by:
    - User
    - Activity type
    - Time range
    - IP address

### Blocking Users

For suspected compromise or policy violations:

1. Find the user in the user management interface
2. Click **Lock Account**
3. Specify reason and duration
4. User will be prevented from logging in until unlocked

### Force Logout

To terminate active user sessions:

1. Find the user in the user management interface
2. Click **Force Logout**
3. All active sessions for the user will be terminated

## Bulk Operations

### Import Users

To add multiple users:

1. Navigate to **Administration → User Management**
2. Click **Import Users**
3. Download the CSV template
4. Fill in user details
5. Upload completed CSV
6. Review and confirm the import

### Export Users

To export user data:

1. Navigate to **Administration → User Management**
2. Apply any filters as needed
3. Click **Export**
4. Choose format (CSV, JSON)
5. Download the file

### Bulk Actions

Apply actions to multiple users:

1. In the user list, select users using checkboxes
2. Click **Bulk Actions**
3. Choose action:
    - Change role
    - Activate/deactivate accounts
    - Enforce MFA
    - Delete accounts
4. Confirm the action

## Audit and Compliance

### User Management Audit Log

Review all user management actions:

1. Navigate to **Administration → Audit & Logs → System Audit**
2. Filter for user management events
3. View details of each action:
    - Administrator who performed the action
    - Action performed
    - Affected user(s)
    - Timestamp
    - IP address

### Compliance Reporting

Generate compliance reports:

1. Navigate to **Administration → Reports → Compliance**
2. Select report type:
    - User access review
    - Permission changes
    - Password policy compliance
    - MFA adoption status
3. Specify time period
4. Generate and download report

## Troubleshooting

### Common Issues

| Problem | Solution |
| --- | --- |
| User unable to log in | Verify account status, check for typos in email, ensure password is correct, check for account lockout |
| MFA setup issues | Reset MFA for the user, verify they are using a compatible authentication app |
| Permission errors | Check role assignments, verify resource-specific permissions, check for conflicting policies |
| Password reset emails not received | Verify email address, check spam folder, ensure email delivery service is working |

### Account Lockouts

To unlock a locked account:

1. Find the user in the user management interface
2. Click **Unlock Account**
3. Optionally reset password
4. Account will be immediately unlocked

## Best Practices

1. **Least privilege principle**: Assign the minimum necessary permissions
2. **Regular access reviews**: Audit user permissions quarterly
3. **Enforce strong authentication**: Require MFA for all administrator accounts
4. **Prompt offboarding**: Deactivate accounts immediately when no longer needed
5. **Password hygiene**: Enforce strong password policies
6. **Separation of duties**: Ensure no single user has excessive permissions
7. **Documentation**: Maintain records of permission changes and justifications
8. **Training**: Ensure administrators understand security implications of user management

## CLI Reference

The platform includes a comprehensive CLI for user management:

### User Commands

```bash
# List all users
flask user list

# Show detailed information for a user
flask user info --username=john.doe

# Create a new user
flask user create --username=jane.smith --email=jane@example.com --role=operator

# Update user information
flask user update --username=john.doe --role=admin

# Change user password
flask user change-password --username=john.doe

# Enable/disable MFA
flask user mfa --username=john.doe --enable

# Lock/unlock account
flask user lock --username=john.doe
flask user unlock --username=john.doe

# Delete user
flask user delete --username=john.doe

```

### Bulk Operations

```bash
# Import users from CSV
flask user import --file=users.csv

# Export users to CSV
flask user export --output=users.csv

# Apply role to multiple users
flask user bulk-update --role=operator --filter="department=engineering"

```

For additional CLI commands and options, refer to the CLI Documentation.