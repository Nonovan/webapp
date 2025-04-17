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