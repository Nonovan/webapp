# User Activity Monitoring

## Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Usage Guidelines](#usage-guidelines)
- [Integration with Core Security](#integration-with-core-security)
- [Data Sources](#data-sources)
- [API Reference](#api-reference)
- [Common Workflows](#common-workflows)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

The User Activity Monitoring module provides forensic capabilities for reviewing, analyzing, and extracting user activity patterns during security incident investigations. It integrates with the Cloud Infrastructure Platform's activity tracking systems to provide a comprehensive view of user actions before, during, and after security incidents. This tool helps identify suspicious behavior patterns, establish timelines of events, and collect evidence related to potential insider threats or compromised accounts.

## Key Capabilities

- **Activity Timeline Creation**: Construct chronological timelines of user activities across multiple systems
- **Anomaly Detection**: Identify deviations from normal user behavior patterns
- **Behavior Analytics**: Apply statistical analysis to detect suspicious activity patterns
- **Cross-System Correlation**: Link activities across different applications and systems
- **Evidence Collection**: Extract and preserve user activity logs in a forensically sound manner
- **Session Analysis**: Reconstruct user sessions to visualize complete interaction sequences
- **User Access Pattern Analysis**: Analyze resource access patterns for suspicious behavior

## Usage Guidelines

### Command Line Interface

```bash
# Collect user activity data for a specific user
./user_activity_monitor.py collect --user-id john.doe --timeframe 48h --output /secure/evidence/IR-2023-042/user_activity

# Generate user activity timeline
./user_activity_monitor.py timeline --user-id john.doe --timeframe 72h --format json \
    --output /secure/evidence/IR-2023-042/user_timeline.json

# Detect anomalies in user behavior
./user_activity_monitor.py analyze --user-id john.doe --baseline 30d --detection-window 48h \
    --sensitivity high --output /secure/evidence/IR-2023-042/anomaly_report.json
```

### Python API

```python
from admin.security.incident_response_kit.forensic_tools.user_activity_monitor import (
    collect_user_activity,
    analyze_user_behavior,
    generate_activity_timeline,
    detect_access_anomalies
)

# Collect comprehensive user activity
evidence = collect_user_activity(
    user_id="john.doe",
    time_period=timedelta(hours=48),
    activity_types=["login", "resource_access", "configuration_change", "security_event"],
    include_metadata=True,
    output_dir="/secure/evidence/IR-2023-042/user_activity"
)

# Generate user activity timeline
timeline = generate_activity_timeline(
    user_id="john.doe",
    time_period=timedelta(hours=72),
    include_related_events=True,
    add_context=True
)

# Analyze user behavior for anomalies
anomalies = analyze_user_behavior(
    user_id="john.doe",
    baseline_period=timedelta(days=30),
    analysis_window=timedelta(hours=48),
    detection_sensitivity="high"
)
```

## Integration with Core Security

The user activity monitoring tools integrate with the core security framework to access authenticated user activity data:

```python
from models.auth import UserActivity
from core.security import cs_monitoring

# Get basic user activity summary
activity_summary = UserActivity.get_user_activity_summary(
    user_id=user_id,
    days=30
)

# Check for suspicious activity indicators
suspicious_activity = cs_monitoring.detect_suspicious_activity(hours=24)

# Get recent resource access events for specific user
recent_access = UserActivity.get_recent_activities(
    user_id=user_id,
    activity_type=UserActivity.ACTIVITY_RESOURCE_ACCESS,
    limit=100
)

# Identify potential hotspots of activity
hotspots = UserActivity.get_activity_hotspots(days=7)
```

## Data Sources

The module collects and analyzes data from multiple sources:

1. **User Activity Logs**
   - Authentication events (login/logout)
   - Resource access events
   - Configuration changes
   - Security events
   - Administrative actions

2. **Session Information**
   - Session duration
   - IP addresses
   - User agents
   - Geographic locations
   - Device information

3. **System Logs**
   - Authentication logs
   - Application logs
   - Security event logs
   - Web server access logs
   - Database query logs

4. **Network Data**
   - Connection patterns
   - Data transfer volumes
   - Protocol usage
   - Connection frequencies
   - Geographic access patterns

## API Reference

### Core Functions

- **`collect_user_activity(user_id, time_period, activity_types=None, include_metadata=True, output_dir=None)`**: Collects and preserves user activity data
  - Returns: Evidence collection object with details about collected data
  - Parameters:
    - `user_id`: User identifier
    - `time_period`: Time period to collect (timedelta object or hours)
    - `activity_types`: Types of activities to collect (defaults to all)
    - `include_metadata`: Whether to include context metadata
    - `output_dir`: Directory to save evidence files

- **`generate_activity_timeline(user_id, time_period, include_related_events=False, add_context=True, output_format='json')`**: Creates chronological timeline of user activities
  - Returns: Timeline object containing chronological events
  - Parameters:
    - `user_id`: User identifier
    - `time_period`: Time period to analyze (timedelta object or hours)
    - `include_related_events`: Include events from related systems
    - `add_context`: Add contextual information to timeline events
    - `output_format`: Format for timeline output ('json', 'csv', 'md')

- **`analyze_user_behavior(user_id, baseline_period, analysis_window, detection_sensitivity='medium')`**: Performs behavioral analysis to detect anomalies
  - Returns: Analysis results with detected anomalies
  - Parameters:
    - `user_id`: User identifier
    - `baseline_period`: Period for establishing normal behavior
    - `analysis_window`: Window for analysis
    - `detection_sensitivity`: Sensitivity level ('low', 'medium', 'high')

- **`detect_access_anomalies(user_id, resource_type=None, resource_id=None, baseline_days=30, detection_hours=24)`**: Detects unusual resource access patterns
  - Returns: List of anomalous access events
  - Parameters:
    - `user_id`: User identifier
    - `resource_type`: Optional resource type filter
    - `resource_id`: Optional specific resource filter
    - `baseline_days`: Baseline period in days
    - `detection_hours`: Detection window in hours

- **`detect_authorization_anomalies(user_id, detection_hours=24, sensitivity='medium')`**: Identifies unusual permission usage patterns
  - Returns: List of unusual authorization events
  - Parameters:
    - `user_id`: User identifier
    - `detection_hours`: Analysis window in hours
    - `sensitivity`: Detection sensitivity level

### Helper Functions

- **`extract_login_patterns(user_id, days=30)`**: Extracts authentication patterns for the user
  - Returns: Dictionary with login pattern information
  - Parameters:
    - `user_id`: User identifier
    - `days`: Analysis period in days

- **`find_concurrent_sessions(user_id, detection_hours=24)`**: Identifies potentially concurrent user sessions
  - Returns: List of concurrent session events
  - Parameters:
    - `user_id`: User identifier
    - `detection_hours`: Detection window in hours

- **`get_resource_access_summary(user_id, days=30)`**: Summarizes resource access by type
  - Returns: Dictionary with resource access summary
  - Parameters:
    - `user_id`: User identifier
    - `days`: Analysis period in days

- **`correlate_activities(user_id, related_indicator=None, time_window=None)`**: Correlates user activities with other events
  - Returns: List of correlated events
  - Parameters:
    - `user_id`: User identifier
    - `related_indicator`: Related IoC or event to correlate with
    - `time_window`: Time window around indicator for correlation

- **`export_activity_evidence(user_id, time_period, format='json', evidence_dir=None, chain_of_custody=True)`**: Exports user activity data in forensic format
  - Returns: Path to evidence file with metadata
  - Parameters:
    - `user_id`: User identifier
    - `time_period`: Time period for evidence
    - `format`: Output format ('json', 'csv', 'evtx')
    - `evidence_dir`: Directory for evidence output
    - `chain_of_custody`: Whether to include chain of custody documentation

### Classes

- **`UserActivityCollection`**: Container for collected user activity data with integrity verification
  - Methods:
    - `add_activity(activity_data)`: Add an activity event to the collection
    - `filter(criteria)`: Filter activities based on criteria
    - `get_timeline()`: Generate chronological timeline
    - `export(format, output_path)`: Export data in specified format
    - `verify_integrity()`: Verify data hasn't been modified

- **`UserBehaviorAnalysis`**: Analysis engine for user behavior patterns
  - Methods:
    - `establish_baseline()`: Create baseline of normal behavior
    - `detect_anomalies()`: Detect deviations from baseline
    - `score_risk(events)`: Calculate risk scores for events
    - `generate_report()`: Create analysis report

- **`ActivityTimeline`**: Timeline representation of user activities
  - Methods:
    - `add_event(event)`: Add event to timeline
    - `add_context(context_data)`: Add contextual information
    - `filter_by_time(start, end)`: Filter timeline to time range
    - `export(format)`: Export timeline in specified format

### Constants

- **`ACTIVITY_TYPES`**: Activity type constants
  - `LOGIN`: Authentication events
  - `LOGOUT`: Session termination events
  - `RESOURCE_ACCESS`: Resource access events
  - `CONFIG_CHANGE`: Configuration changes
  - `ADMIN_ACTION`: Administrative actions
  - `SECURITY_EVENT`: Security-related events

- **`DETECTION_SENSITIVITY`**: Sensitivity levels for anomaly detection
  - `LOW`: Detect only significant anomalies (fewer false positives)
  - `MEDIUM`: Balanced detection threshold
  - `HIGH`: Detect subtle anomalies (may have more false positives)

- **`ANALYSIS_FEATURES`**: Features used in behavioral analysis
  - `TIME_PATTERN`: Timing patterns of activities
  - `RESOURCE_PATTERN`: Resource access patterns
  - `VOLUME_PATTERN`: Activity volume patterns
  - `LOCATION_PATTERN`: Geographic access patterns

- **`EVIDENCE_FORMATS`**: Supported evidence export formats
  - `JSON`: Structured JSON format
  - `CSV`: Comma-separated values
  - `EVTX`: Windows Event Log XML format
  - `MARKDOWN`: Markdown documentation format

## Common Workflows

### Incident Investigation

1. **Initial Evidence Collection**

   ```python
   # Collect all user activity for past 48 hours
   evidence = collect_user_activity(
       user_id=suspect_user,
       time_period=timedelta(hours=48),
       include_metadata=True,
       output_dir=evidence_path
   )
   ```

2. **Timeline Construction**

   ```python
   # Create timeline including related system events
   timeline = generate_activity_timeline(
       user_id=suspect_user,
       time_period=timedelta(hours=48),
       include_related_events=True,
       add_context=True
   )

   # Export timeline to incident report
   timeline.export(
       format='markdown',
       output_path=f"{evidence_path}/user_timeline.md"
   )
   ```

3. **Behavior Analysis**

   ```python
   # Analyze for anomalous behavior
   anomalies = analyze_user_behavior(
       user_id=suspect_user,
       baseline_period=timedelta(days=30),
       analysis_window=timedelta(hours=48),
       detection_sensitivity='high'
   )

   # Generate anomaly report
   if anomalies.has_critical_anomalies():
       anomalies.generate_report(
           output_path=f"{evidence_path}/anomaly_report.json"
       )
   ```

4. **Correlation with Other Indicators**

   ```python
   # Correlate user activity with suspicious indicator
   correlated_events = correlate_activities(
       user_id=suspect_user,
       related_indicator="192.168.1.100",
       time_window=timedelta(hours=1)
   )
   ```

### User Behavior Analytics for Threat Hunting

1. **Baseline Normal Behavior**

   ```python
   # Create baseline of normal behavior for user
   baseline = UserBehaviorAnalysis(user_id=target_user)
   baseline.establish_baseline(days=90)
   baseline.save(f"{baseline_path}/{target_user}_baseline.json")
   ```

2. **Detect Access Anomalies**

   ```python
   # Check for unusual resource access
   access_anomalies = detect_access_anomalies(
       user_id=target_user,
       baseline_days=90,
       detection_hours=24
   )
   ```

3. **Login Pattern Analysis**

   ```python
   # Extract user's normal login patterns
   login_patterns = extract_login_patterns(
       user_id=target_user,
       days=90
   )

   # Look for concurrent sessions
   concurrent_sessions = find_concurrent_sessions(
       user_id=target_user,
       detection_hours=24
   )
   ```

4. **Resource Access Summary**

   ```python
   # Get summary of resources accessed
   access_summary = get_resource_access_summary(
       user_id=target_user,
       days=30
   )
   ```

## Best Practices & Security

- **Data Privacy**: Filter out personal information not relevant to the investigation
- **Forensic Integrity**: Maintain chain of custody for all collected evidence
- **Legal Compliance**: Ensure monitoring complies with applicable privacy regulations
- **Principle of Least Privilege**: Only collect activity data necessary for the investigation
- **Documentation**: Maintain detailed documentation of all monitoring and analysis actions
- **Time Synchronization**: Ensure consistent timestamps across all data sources
- **Context Preservation**: Preserve context for all activities to ensure accurate interpretation
- **Analysis Validation**: Cross-validate findings using multiple data sources
- **Secure Storage**: Store all collected activity data in encrypted form
- **Activity Logs**: Log all uses of this monitoring tool for audit purposes
- **Authorization**: Require proper authorization before using these monitoring tools
- **Data Retention**: Follow appropriate retention policies for collected data

## Related Documentation

- User Activity Model Reference
- Core Security Monitoring Documentation
- Incident Response Playbooks
- Insider Threat Indicators Guide
- Evidence Collection Procedures
- Forensic Tools Documentation
- Chain of Custody Requirements
- Privilege Escalation Detection Guide
