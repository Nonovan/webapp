/**
 * Reference Schema for Cloud Infrastructure Platform
 *
 * This file provides a reference for the complete database schema.
 * It is not used directly for migrations (those are managed by Alembic),
 * but serves as documentation and can be used for new database setup if needed.
 */

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    first_name VARCHAR(64),
    last_name VARCHAR(64),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(32),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_users_email ON users(email);
CREATE INDEX ix_users_username ON users(username);
CREATE INDEX ix_users_role ON users(role);

-- Posts/Content table
CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(120) NOT NULL,
    content TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (author_id) REFERENCES users(id)
);

CREATE INDEX ix_posts_author_id ON posts(author_id);

-- Newsletter subscribers
CREATE TABLE newsletter_subscribers (
    id SERIAL PRIMARY KEY,
    email VARCHAR(120) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    subscription_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_newsletter_subscribers_email ON newsletter_subscribers(email);

-- Notifications
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    message VARCHAR(255) NOT NULL,
    read BOOLEAN NOT NULL DEFAULT FALSE,
    notification_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_notifications_user_id ON notifications(user_id);

-- Audit logs
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    user_id INTEGER,
    description VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    details TEXT,
    severity VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX ix_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX ix_audit_logs_severity ON audit_logs(severity);
CREATE INDEX ix_audit_logs_created_at ON audit_logs(created_at);

-- Security incidents
CREATE TABLE security_incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(128) NOT NULL,
    incident_type VARCHAR(50) NOT NULL,
    description VARCHAR(255) NOT NULL,
    details TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    source VARCHAR(50),
    ip_address VARCHAR(45),
    resolution TEXT,
    assigned_to INTEGER,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

CREATE INDEX ix_security_incidents_incident_type ON security_incidents(incident_type);
CREATE INDEX ix_security_incidents_severity ON security_incidents(severity);
CREATE INDEX ix_security_incidents_status ON security_incidents(status);

-- User sessions
CREATE TABLE user_sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255),
    login_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_active TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX ix_user_sessions_is_active ON user_sessions(is_active);

-- Cloud providers
CREATE TABLE cloud_providers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    provider_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    credentials JSONB,
    regions JSONB,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by_id INTEGER NOT NULL,
    last_verification TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (created_by_id) REFERENCES users(id),
    UNIQUE (name, provider_type)
);

CREATE INDEX ix_cloud_providers_provider_type ON cloud_providers(provider_type);
CREATE INDEX ix_cloud_providers_status ON cloud_providers(status);

-- System configurations
CREATE TABLE system_configs (
    id SERIAL PRIMARY KEY,
    key VARCHAR(64) NOT NULL UNIQUE,
    value JSONB,
    description VARCHAR(255),
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_system_configs_key ON system_configs(key);

-- Cloud resources
CREATE TABLE cloud_resources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    provider_id INTEGER NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    region VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by_id INTEGER,
    metadata JSONB,
    config JSONB,
    tags JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (provider_id) REFERENCES cloud_providers(id),
    FOREIGN KEY (created_by_id) REFERENCES users(id)
);

CREATE INDEX ix_cloud_resources_resource_type ON cloud_resources(resource_type);
CREATE INDEX ix_cloud_resources_region ON cloud_resources(region);
CREATE INDEX ix_cloud_resources_status ON cloud_resources(status);

-- Cloud metrics
CREATE TABLE cloud_metrics (
    id SERIAL PRIMARY KEY,
    resource_id INTEGER NOT NULL,
    metric_name VARCHAR(64) NOT NULL,
    metric_value FLOAT NOT NULL,
    unit VARCHAR(32),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    dimensions JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (resource_id) REFERENCES cloud_resources(id)
);

CREATE INDEX ix_cloud_metrics_resource_id ON cloud_metrics(resource_id);
CREATE INDEX ix_cloud_metrics_metric_name ON cloud_metrics(metric_name);
CREATE INDEX ix_cloud_metrics_timestamp ON cloud_metrics(timestamp);

-- Cloud alerts
CREATE TABLE cloud_alerts (
    id SERIAL PRIMARY KEY,
    resource_id INTEGER,
    alert_type VARCHAR(64) NOT NULL,
    title VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    acknowledged_by INTEGER,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    notification_sent BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (resource_id) REFERENCES cloud_resources(id),
    FOREIGN KEY (acknowledged_by) REFERENCES users(id)
);

CREATE INDEX ix_cloud_alerts_alert_type ON cloud_alerts(alert_type);
CREATE INDEX ix_cloud_alerts_status ON cloud_alerts(status);
CREATE INDEX ix_cloud_alerts_severity ON cloud_alerts(severity);

-- ICS devices
CREATE TABLE ics_devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    device_type VARCHAR(64) NOT NULL,
    location VARCHAR(128),
    ip_address VARCHAR(45),
    protocol VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'online',
    last_communication TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    settings JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_ics_devices_status ON ics_devices(status);
CREATE INDEX ix_ics_devices_device_type ON ics_devices(device_type);

-- ICS readings
CREATE TABLE ics_readings (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL,
    reading_type VARCHAR(64) NOT NULL,
    value FLOAT NOT NULL,
    unit VARCHAR(32),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    is_anomaly BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (device_id) REFERENCES ics_devices(id)
);

CREATE INDEX ix_ics_readings_device_id ON ics_readings(device_id);
CREATE INDEX ix_ics_readings_reading_type ON ics_readings(reading_type);
CREATE INDEX ix_ics_readings_timestamp ON ics_readings(timestamp);
CREATE INDEX ix_ics_readings_is_anomaly ON ics_readings(is_anomaly);

-- ICS control logs
CREATE TABLE ics_control_logs (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    action VARCHAR(64) NOT NULL,
    value VARCHAR(255),
    previous_value VARCHAR(255),
    ip_address VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (device_id) REFERENCES ics_devices(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_ics_control_logs_device_id ON ics_control_logs(device_id);
CREATE INDEX ix_ics_control_logs_user_id ON ics_control_logs(user_id);
CREATE INDEX ix_ics_control_logs_action ON ics_control_logs(action);

-- Webhook subscriptions
CREATE TABLE webhook_subscriptions (
    id VARCHAR(36) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    target_url VARCHAR(512) NOT NULL,
    event_types JSONB NOT NULL,
    description VARCHAR(255),
    headers JSONB,
    secret VARCHAR(64) NOT NULL,
    max_retries INTEGER NOT NULL DEFAULT 3,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_webhook_subscriptions_user_id ON webhook_subscriptions(user_id);
CREATE INDEX ix_webhook_subscriptions_is_active ON webhook_subscriptions(is_active);

-- Webhook deliveries
CREATE TABLE webhook_deliveries (
    id SERIAL PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    response_code INTEGER,
    response_body TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    FOREIGN KEY (subscription_id) REFERENCES webhook_subscriptions(id)
);

CREATE INDEX ix_webhook_deliveries_subscription_id ON webhook_deliveries(subscription_id);
CREATE INDEX ix_webhook_deliveries_event_type ON webhook_deliveries(event_type);
CREATE INDEX ix_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX ix_webhook_deliveries_created_at ON webhook_deliveries(created_at);

-- User activities
CREATE TABLE user_activities (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    activity_type VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(64),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_user_activities_user_id ON user_activities(user_id);
CREATE INDEX ix_user_activities_activity_type ON user_activities(activity_type);
CREATE INDEX ix_user_activities_created_at ON user_activities(created_at);

-- File uploads
CREATE TABLE file_uploads (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type VARCHAR(128) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    storage_path VARCHAR(512) NOT NULL,
    public_url VARCHAR(512),
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB,
    scanned_at TIMESTAMP WITH TIME ZONE,
    scan_result VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_file_uploads_user_id ON file_uploads(user_id);
CREATE INDEX ix_file_uploads_mime_type ON file_uploads(mime_type);
CREATE INDEX ix_file_uploads_file_hash ON file_uploads(file_hash);

-- Security scans
CREATE TABLE security_scans (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    scheduled_for TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    options JSONB,
    result_summary JSONB,
    created_by_id INTEGER,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (created_by_id) REFERENCES users(id)
);

CREATE INDEX ix_security_scans_scan_type ON security_scans(scan_type);
CREATE INDEX ix_security_scans_status ON security_scans(status);
CREATE INDEX ix_security_scans_priority ON security_scans(priority);

-- Security scan findings
CREATE TABLE security_findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    title VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    resource_type VARCHAR(64),
    resource_id VARCHAR(128),
    location VARCHAR(255),
    details JSONB,
    remediation_steps TEXT,
    assigned_to_id INTEGER,
    assigned_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (scan_id) REFERENCES security_scans(id),
    FOREIGN KEY (assigned_to_id) REFERENCES users(id)
);

CREATE INDEX ix_security_findings_scan_id ON security_findings(scan_id);
CREATE INDEX ix_security_findings_severity ON security_findings(severity);
CREATE INDEX ix_security_findings_status ON security_findings(status);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    vulnerability_type VARCHAR(64) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    affected_resources JSONB,
    remediation_steps TEXT,
    exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    exploited_in_wild BOOLEAN NOT NULL DEFAULT FALSE,
    asset_criticality VARCHAR(20),
    remediation_deadline TIMESTAMP WITH TIME ZONE,
    assigned_to_id INTEGER,
    external_references JSONB,
    tags JSONB,
    resolution_summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (assigned_to_id) REFERENCES users(id)
);

CREATE INDEX ix_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX ix_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX ix_vulnerabilities_vulnerability_type ON vulnerabilities(vulnerability_type);

-- File integrity baselines
CREATE TABLE file_integrity_baselines (
    id SERIAL PRIMARY KEY,
    baseline_name VARCHAR(128) NOT NULL,
    baseline_path VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_hash VARCHAR(128) NOT NULL,
    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'sha256',
    created_by_id INTEGER,
    is_critical BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (created_by_id) REFERENCES users(id)
);

CREATE INDEX ix_file_integrity_baselines_file_path ON file_integrity_baselines(file_path);
CREATE INDEX ix_file_integrity_baselines_is_critical ON file_integrity_baselines(is_critical);
CREATE INDEX ix_file_integrity_baselines_baseline_name ON file_integrity_baselines(baseline_name);

-- File integrity events
CREATE TABLE file_integrity_events (
    id SERIAL PRIMARY KEY,
    file_path VARCHAR(512) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    expected_hash VARCHAR(128),
    current_hash VARCHAR(128),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    details JSONB,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by_id INTEGER,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (resolved_by_id) REFERENCES users(id)
);

CREATE INDEX ix_file_integrity_events_file_path ON file_integrity_events(file_path);
CREATE INDEX ix_file_integrity_events_event_type ON file_integrity_events(event_type);
CREATE INDEX ix_file_integrity_events_severity ON file_integrity_events(severity);
CREATE INDEX ix_file_integrity_events_detected_at ON file_integrity_events(detected_at);

-- Database maintenance history
CREATE TABLE database_maintenance (
    id SERIAL PRIMARY KEY,
    maintenance_type VARCHAR(64) NOT NULL,
    target_object VARCHAR(128),
    target_schema VARCHAR(64),
    performed_by VARCHAR(128),
    details JSONB,
    operation_count INTEGER,
    duration_ms INTEGER,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_database_maintenance_maintenance_type ON database_maintenance(maintenance_type);
CREATE INDEX ix_database_maintenance_started_at ON database_maintenance(started_at);
CREATE INDEX ix_database_maintenance_success ON database_maintenance(success);

-- Database migration history
CREATE TABLE migration_history (
    id SERIAL PRIMARY KEY,
    revision_id VARCHAR(40) NOT NULL,
    revision_name VARCHAR(255),
    applied_by VARCHAR(128),
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    is_downgrade BOOLEAN NOT NULL DEFAULT FALSE,
    execution_time_ms INTEGER,
    success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX ix_migration_history_revision_id ON migration_history(revision_id);
CREATE INDEX ix_migration_history_applied_at ON migration_history(applied_at);

-- Security baselines
CREATE TABLE security_baselines (
    id SERIAL PRIMARY KEY,
    baseline_name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    version VARCHAR(32) NOT NULL,
    controls JSONB NOT NULL,
    created_by_id INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    approved_at TIMESTAMP WITH TIME ZONE,
    approved_by_id INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (created_by_id) REFERENCES users(id),
    FOREIGN KEY (approved_by_id) REFERENCES users(id)
);

CREATE INDEX ix_security_baselines_baseline_name ON security_baselines(baseline_name);
CREATE INDEX ix_security_baselines_status ON security_baselines(status);

-- Compliance checks
CREATE TABLE compliance_checks (
    id SERIAL PRIMARY KEY,
    check_name VARCHAR(128) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    standard VARCHAR(64),
    control_id VARCHAR(64),
    check_type VARCHAR(64) NOT NULL,
    implementation JSONB NOT NULL,
    remediation_steps TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_compliance_checks_check_name ON compliance_checks(check_name);
CREATE INDEX ix_compliance_checks_severity ON compliance_checks(severity);
CREATE INDEX ix_compliance_checks_standard ON compliance_checks(standard);

-- Compliance results
CREATE TABLE compliance_results (
    id SERIAL PRIMARY KEY,
    check_id INTEGER NOT NULL,
    resource_id VARCHAR(128),
    resource_type VARCHAR(64),
    status VARCHAR(20) NOT NULL,
    details JSONB,
    evidence TEXT,
    scan_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (check_id) REFERENCES compliance_checks(id)
);

CREATE INDEX ix_compliance_results_check_id ON compliance_results(check_id);
CREATE INDEX ix_compliance_results_scan_id ON compliance_results(scan_id);
CREATE INDEX ix_compliance_results_status ON compliance_results(status);

-- Roles and permissions for more granular RBAC
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_roles_name ON roles(name);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,
    resource_type VARCHAR(64),
    action VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_permissions_name ON permissions(name);
CREATE INDEX ix_permissions_resource_type_action ON permissions(resource_type, action);

CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE (role_id, permission_id)
);

CREATE INDEX ix_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX ix_role_permissions_permission_id ON role_permissions(permission_id);

-- Update users table to use role_id instead of role string
-- This requires data migration in real deployments
ALTER TABLE users ADD COLUMN role_id INTEGER;
ALTER TABLE users ADD CONSTRAINT fk_users_role_id FOREIGN KEY (role_id) REFERENCES roles(id);
CREATE INDEX ix_users_role_id ON users(role_id);

-- User-specific permissions (overrides role permissions)
CREATE TABLE user_permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    granted_by_id INTEGER,
    valid_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by_id) REFERENCES users(id),
    UNIQUE (user_id, permission_id)
);

CREATE INDEX ix_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX ix_user_permissions_permission_id ON user_permissions(permission_id);

-- Circuit breakers for service resilience
CREATE TABLE circuit_breakers (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'closed',
    failure_count INTEGER NOT NULL DEFAULT 0,
    failure_threshold INTEGER NOT NULL DEFAULT 5,
    reset_timeout INTEGER NOT NULL DEFAULT 60, -- seconds
    last_failure TIMESTAMP WITH TIME ZONE,
    last_success TIMESTAMP WITH TIME ZONE,
    last_status_change TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (service_name, endpoint)
);

CREATE INDEX ix_circuit_breakers_service_name ON circuit_breakers(service_name);
CREATE INDEX ix_circuit_breakers_status ON circuit_breakers(status);

-- System metrics for performance tracking
CREATE TABLE system_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(128) NOT NULL,
    metric_value FLOAT NOT NULL,
    unit VARCHAR(32),
    labels JSONB,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_system_metrics_metric_name ON system_metrics(metric_name);
CREATE INDEX ix_system_metrics_timestamp ON system_metrics(timestamp);

-- Rate limiting data
CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_size INTEGER NOT NULL, -- seconds
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (key, resource, window_start)
);

CREATE INDEX ix_rate_limits_key_resource ON rate_limits(key, resource);
CREATE INDEX ix_rate_limits_window_start ON rate_limits(window_start);

-- Add database comments
COMMENT ON TABLE audit_logs IS 'Security audit events with user attribution and details';
COMMENT ON TABLE cloud_alerts IS 'Alerts from cloud resource monitoring';
COMMENT ON TABLE cloud_providers IS 'Integrated cloud service provider configurations';
COMMENT ON TABLE cloud_resources IS 'Resources managed across cloud providers';
COMMENT ON TABLE ics_devices IS 'Industrial Control System device inventory';
COMMENT ON TABLE security_scans IS 'Security scan jobs and their results';
COMMENT ON TABLE user_sessions IS 'User login sessions with security metadata';
COMMENT ON TABLE file_integrity_baselines IS 'File integrity monitoring baseline signatures';
COMMENT ON TABLE file_integrity_events IS 'File integrity violation events';
COMMENT ON TABLE vulnerabilities IS 'Security vulnerabilities with tracking information';
