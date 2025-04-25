# ICS API

The ICS (Industrial Control Systems) API module provides secure endpoints for monitoring, managing, and controlling industrial control systems within the Cloud Infrastructure Platform.

## Contents

- Overview
- Key Components
- Directory Structure
- API Endpoints
- Configuration
- Security Features
- Usage Examples
- Related Documentation

## Overview

The ICS API implements RESTful endpoints for interacting with industrial control systems while enforcing strict security controls. It provides a unified interface for device management, sensor readings, real-time monitoring, and control operations. The API follows security best practices including comprehensive authentication, authorization checks, input validation, and audit logging.

## Key Components

- **`__init__.py`**: Module initialization and blueprint creation
  - Defines the ICS blueprint
  - Sets up security constraints specific to ICS operations
  - Registers middleware for specialized ICS traffic monitoring
  - Configures metrics for ICS API endpoints

- **`routes.py`**: API endpoint implementations
  - Device listing and management endpoints
  - Reading collection and analysis endpoints
  - Control operation endpoints with security safeguards
  - Status monitoring and historical data endpoints

- **`devices.py`**: Device management functionality
  - Device registration and configuration
  - Device status monitoring
  - Device metadata management
  - Connection management for various protocols

- **`readings.py`**: Sensor reading operations
  - Reading collection and storage
  - Reading validation and anomaly detection
  - Historical data retrieval
  - Statistical analysis and aggregation

- **`control.py`**: Control operation functionality
  - Command validation and safety checks
  - Control operation execution with proper permissions
  - Command logging and auditing
  - Safety override implementations

- **`schemas.py`**: Data validation schemas
  - Input validation for all API operations
  - Response formatting for consistency
  - Schema versioning support

## Directory Structure

```plaintext
api/ics/
├── __init__.py         # Module initialization and blueprint creation
├── README.md           # This documentation
├── routes.py           # Primary API endpoint implementations
├── devices.py          # Device management functionality
├── readings.py         # Sensor reading operations
├── control.py          # Control operation functionality
├── schemas.py          # Data validation schemas
└── decorators.py       # ICS-specific security decorators
```

## API Endpoints

| Endpoint | Method | Description | Access Level |
|----------|--------|-------------|-------------|
| `/api/ics/devices` | GET | List all ICS devices | Operator, Admin |
| `/api/ics/devices` | POST | Register a new ICS device | Admin |
| `/api/ics/devices/{id}` | GET | Get specific device details | Operator, Admin |
| `/api/ics/devices/{id}` | PATCH | Update device configuration | Admin |
| `/api/ics/readings` | GET | Get latest readings from devices | Operator, Admin |
| `/api/ics/readings` | POST | Record new device readings | System, Admin |
| `/api/ics/devices/{id}/readings` | GET | Get readings for specific device | Operator, Admin |
| `/api/ics/devices/{id}/history` | GET | Get historical data for a device | Operator, Admin |
| `/api/ics/control` | POST | Send control commands to devices | Operator, Admin |
| `/api/ics/status` | GET | Get overall ICS system status | Operator, Admin |

## Configuration

The ICS API uses several configuration settings that can be adjusted in the application config:

```python
# ICS security settings
'ICS_RESTRICTED_IPS': ['10.0.0.0/8', '172.16.0.0/12'],  # IP ranges allowed to access ICS endpoints
'ICS_CONTROL_REQUIRES_MFA': True,       # Require MFA for control operations
'ICS_CONTROL_CONFIRMATION': True,       # Require explicit confirmation for critical operations
'ICS_ANOMALY_DETECTION_ENABLED': True,  # Enable automatic anomaly detection
'ICS_COMMAND_TIMEOUT': 30,              # Command timeout in seconds
'ICS_MAX_COMMANDS_PER_MINUTE': 20,      # Rate limit for control commands

# Reading configuration
'ICS_READING_RETENTION_DAYS': 365,      # How long to keep detailed readings
'ICS_READING_AGGREGATION_ENABLED': True, # Enable automatic reading aggregation
'ICS_READING_BATCH_SIZE': 100,          # Maximum readings per batch submission

# Rate limiting settings
'RATELIMIT_ICS_DEFAULT': "60 per minute",
'RATELIMIT_ICS_CONTROL': "20 per minute",
'RATELIMIT_ICS_READINGS_GET': "100 per minute",
'RATELIMIT_ICS_READINGS_POST': "50 per minute"
```

## Security Features

- **Specialized IP Restrictions**: ICS endpoints can be restricted to specific IP ranges
- **Enhanced Authentication**: Stricter authentication requirements for control operations
- **Multi-Factor Authentication**: MFA requirement for critical control operations
- **Command Validation**: Validation of control parameters against safe operating limits
- **Comprehensive Audit Logging**: Detailed logging of all control operations
- **Safety Overrides**: Automatic rejection of unsafe commands
- **Anomaly Detection**: Automatic detection of anomalous readings or behavior
- **Input Validation**: Thorough validation of all input parameters
- **Rate Limiting**: Prevents API abuse with endpoint-specific limits
- **Action Confirmation**: Two-step confirmation for critical operations
- **Secure Error Handling**: Prevents information leakage in error responses

## Usage Examples

### List ICS Devices

```http
GET /api/ics/devices
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 1,
      "name": "Temperature Sensor A1",
      "device_type": "sensor",
      "location": "Building 1, Floor 2",
      "protocol": "modbus",
      "status": "online",
      "last_communication": "2023-06-15T16:55:22Z"
    },
    {
      "id": 2,
      "name": "Pressure Controller B3",
      "device_type": "controller",
      "location": "Building 2, Floor 1",
      "protocol": "bacnet",
      "status": "online",
      "last_communication": "2023-06-15T16:54:45Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total_pages": 1,
    "total_items": 2
  }
}
```

### Get Device Readings

```http
GET /api/ics/readings?device_id=1&reading_type=temperature&limit=2
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:

```json
{
  "data": [
    {
      "id": 5001,
      "device_id": 1,
      "reading_type": "temperature",
      "value": 22.5,
      "unit": "C",
      "timestamp": "2023-06-15T16:45:00Z",
      "is_anomaly": false
    },
    {
      "id": 5000,
      "device_id": 1,
      "reading_type": "temperature",
      "value": 22.4,
      "unit": "C",
      "timestamp": "2023-06-15T16:30:00Z",
      "is_anomaly": false
    }
  ],
  "meta": {
    "device_id": 1,
    "device_name": "Temperature Sensor A1",
    "reading_type": "temperature",
    "total_readings": 2880
  }
}
```

### Control ICS Device

```http
POST /api/ics/control
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-MFA-Token: 123456

{
  "device_id": 2,
  "action": "update_settings",
  "parameters": {
    "target_pressure": 32.5,
    "unit": "psi"
  }
}
```

Response:

```json
{
  "success": true,
  "device_id": 2,
  "log_id": 4572,
  "status": "accepted",
  "message": "Control command accepted",
  "timestamp": "2023-06-15T17:05:12Z"
}
```

## Related Documentation

- ICS Device Management
- ICS Security Guidelines
- Control System Integration
- ICS Data Models
- API Reference
- Security Best Practices
