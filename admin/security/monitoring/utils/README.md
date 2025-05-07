# Security Monitoring Utilities

This directory contains utility functions and helper modules that support the security monitoring tools in the Cloud Infrastructure Platform. These utilities provide standardized functionality for log parsing, alert formatting, event normalization, and indicator matching.

## Contents

- [Overview](#overview)
- [Key Components](#key-components)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Integration](#integration)
- [Best Practices & Security](#best-practices--security)
- [Common Features](#common-features)
- [Related Documentation](#related-documentation)

## Overview

The security monitoring utilities implement reusable functionality for handling security data, processing events, formatting outputs, and matching security indicators. These utilities ensure consistent data handling across the security monitoring tools while following security best practices for sensitive data management. They provide standardized interfaces for common security monitoring operations and maintain proper separation of concerns within the monitoring architecture.

## Key Components

- **`alert_formatter.py`**: Security alert formatting functions
  - Consistent alert formatting across monitoring tools
  - Multiple output format support (JSON, HTML, plain text)
  - Severity-based visual indicators
  - Template-based formatting with variables
  - Secure handling of sensitive information
  - MIME type support for different delivery methods

- **`event_normalizer.py`**: Event normalization functions
  - Standardization of event fields from different sources
  - Timestamp normalization and timezone handling
  - Field mapping for vendor-specific formats
  - Schema validation for normalized events
  - Enrichment of events with contextual information
  - Filtering of irrelevant or noise events

- **`indicator_matcher.py`**: IOC matching functions
  - Pattern matching for indicators of compromise
  - Support for multiple indicator types (IP, domain, hash, regex)
  - Fuzzy matching capabilities for approximate matches
  - Confidence scoring for matches
  - Caching of frequently used indicators
  - Optimized matching algorithms for large datasets

- **`log_parser.py`**: Security log parsing utilities
  - Multi-format log parsing (syslog, JSON, CEF, LEEF)
  - Extraction of security-relevant fields
  - Handling of multi-line log entries
  - Parser combinators for complex log formats
  - Performance optimization for high-volume logs
  - Error recovery for malformed log entries

## Directory Structure

```plaintext
admin/security/monitoring/utils/
├── README.md             # This documentation
├── __init__.py           # Package initialization
├── alert_formatter.py    # Security alert formatting functions
├── event_normalizer.py   # Event normalization functions
├── indicator_matcher.py  # IOC matching functions
└── log_parser.py         # Security log parsing utilities
```

## Usage

These utilities are meant to be imported by the security monitoring tools:

```python
# Example usage in a security monitoring script
import sys
import os

# Add the parent directory to the path to import the utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.log_parser import parse_security_log
from utils.event_normalizer import normalize_event
from utils.indicator_matcher import match_indicators
from utils.alert_formatter import format_security_alert

# Parse a security log file
log_entries = parse_security_log(
    log_file='/var/log/secure',
    format='syslog'
)

# Process each log entry
for entry in log_entries:
    # Normalize the event
    normalized_event = normalize_event(entry, source_type='syslog')

    # Match against known indicators of compromise
    matches = match_indicators(normalized_event, indicator_set='active_threats')

    # If matches are found, generate an alert
    if matches:
        alert = format_security_alert(
            event=normalized_event,
            matches=matches,
            severity='high',
            format='json'
        )

        # Send the alert (implementation depends on your notification system)
        send_alert(alert)
```

## Integration

These utilities integrate with other components of the security monitoring system:

### Alert Formatter

```python
from utils.alert_formatter import format_security_alert

# Format an alert for the security dashboard
dashboard_alert = format_security_alert(
    event=event_data,
    matches=indicator_matches,
    severity='critical',
    format='html',
    template='dashboard_alert'
)

# Format an alert for email notification
email_alert = format_security_alert(
    event=event_data,
    matches=indicator_matches,
    severity='high',
    format='html',
    template='email_notification',
    include_remediation=True
)
```

### Event Normalizer

```python
from utils.event_normalizer import normalize_event, normalize_batch

# Normalize a single event
normalized_event = normalize_event(
    raw_event=raw_log_entry,
    source_type='windows_event',
    add_context=True
)

# Normalize a batch of events
normalized_events = normalize_batch(
    raw_events=raw_log_entries,
    source_type='firewall',
    add_geo_data=True
)
```

### Indicator Matcher

```python
from utils.indicator_matcher import match_indicators, load_indicator_set

# Load a set of indicators from a file or database
indicators = load_indicator_set('active_threats')

# Match event data against indicators
matches = match_indicators(
    event=normalized_event,
    indicators=indicators,
    match_types=['ip', 'domain', 'hash'],
    threshold=0.75
)

# Check if an IP address matches any known threats
ip_matches = match_ip_address(
    ip='192.168.1.100',
    indicators=indicators,
    threshold=0.9
)
```

### Log Parser

```python
from utils.log_parser import parse_security_log, parse_log_line, detect_log_format

# Parse an entire log file
log_entries = parse_security_log(
    log_file='/var/log/auth.log',
    format='syslog',
    start_time='2023-07-15T00:00:00Z',
    end_time='2023-07-15T23:59:59Z'
)

# Parse a single log line
parsed_entry = parse_log_line(
    line='Jul 15 15:23:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 59812 ssh2',
    format='syslog'
)

# Auto-detect the format of a log file
log_format = detect_log_format('/var/log/messages')
```

## Best Practices & Security

- **Data Sanitization**: All user inputs and external data are sanitized before processing
- **Error Handling**: Comprehensive error handling with proper logging
- **Input Validation**: Validation of all parameters before processing
- **Memory Management**: Efficient memory usage for processing large datasets
- **Performance Optimization**: Optimized algorithms for high-volume log processing
- **Secure Defaults**: Secure default settings requiring explicit opt-out
- **Sensitive Data Handling**: Proper handling and masking of sensitive information
- **Separation of Concerns**: Clear separation of functionality between modules
- **Threat Model Awareness**: Utilities are designed with security threats in mind
- **Versioning**: Proper versioning of utilities for compatibility tracking

## Common Features

All utilities share these common features:

- **Caching**: Intelligent caching for performance optimization
- **Configurability**: Configurable behavior through parameters
- **Documentation**: Comprehensive inline documentation and examples
- **Error Logging**: Standardized error logging with appropriate levels
- **Input Validation**: Thorough validation of all inputs
- **Modularity**: Clearly defined interfaces and responsibilities
- **Performance Metrics**: Collection of performance metrics for monitoring
- **Testing Support**: Comprehensive test coverage
- **Thread Safety**: Thread-safe implementations for concurrent usage
- **Type Annotations**: Python type annotations for better IDE support

## Related Documentation

- Security Monitoring Overview
- Security Event Correlation
- Threat Intelligence Integration
- Security Monitoring Configuration
- Detection Rules Documentation
- Security Monitoring Templates
- Security Event Standards
- Indicator of Compromise Guidelines
- Log Collection Architecture
- Alert Management Framework
