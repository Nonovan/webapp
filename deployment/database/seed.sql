/**
 * Seed data for Cloud Infrastructure Platform database
 *
 * This script populates a newly created database with essential data
 * required for the application to function properly. It avoids creating
 * duplicate records by checking for existence first.
 */

-- Transaction to ensure all-or-nothing execution
BEGIN;

-- Create admin user if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM users WHERE username = 'admin') THEN
        -- Insert admin user with bcrypt-hashed password 'Admin123!'
        -- Note: In production, this password should be changed immediately
        INSERT INTO users (
            username, email, password_hash, role, first_name, last_name,
            is_active, mfa_enabled, created_at, updated_at
        ) VALUES (
            'admin', 'admin@example.com',
            '$2a$12$1UPWf.JUlnP8X5/TbLiDu.1I5aGnF2hMHNXv0HHlOj8wW4vV9Ij4K',
            'admin', 'System', 'Administrator',
            true, false, NOW(), NOW()
        );
    END IF;
END;
$$;

-- Create basic system configurations if they don't exist
INSERT INTO system_configs (key, value, description, is_encrypted, created_at, updated_at)
VALUES
    ('security_level', '"high"', 'Application security level (low, medium, high)', false, NOW(), NOW()),
    ('max_login_attempts', '5', 'Maximum failed login attempts before account lockout', false, NOW(), NOW()),
    ('session_timeout', '30', 'Session timeout in minutes', false, NOW(), NOW()),
    ('maintenance_mode', 'false', 'Enable site maintenance mode', false, NOW(), NOW()),
    ('password_policy', '{"min_length": 8, "require_uppercase": true, "require_lowercase": true, "require_number": true, "require_special": true}', 'Password policy requirements', false, NOW(), NOW()),
    ('file_integrity_monitoring.enabled', 'true', 'Enable file integrity monitoring', false, NOW(), NOW()),
    ('file_integrity_monitoring.interval', '3600', 'File integrity check interval in seconds', false, NOW(), NOW()),
    ('file_integrity_monitoring.critical_paths', '["etc/passwd", "etc/shadow", "etc/ssl", "etc/security"]', 'Paths considered critical for security monitoring', false, NOW(), NOW()),
    ('compliance.standards.enabled', '["PCI-DSS", "HIPAA", "ISO27001"]', 'Enabled compliance standards', false, NOW(), NOW()),
    ('backup.auto_backup', 'true', 'Enable automatic database backups', false, NOW(), NOW()),
    ('backup.retention_days', '30', 'Number of days to retain backups', false, NOW(), NOW()),
    ('monitoring.metrics_retention_days', '90', 'Days to retain performance metrics', false, NOW(), NOW()),
    ('alerts.notification_channels', '["email", "slack"]', 'Alert notification channels', false, NOW(), NOW())
ON CONFLICT (key) DO NOTHING;

-- Create roles and permissions for RBAC
-- Insert roles
INSERT INTO roles (name, description, is_system_role, created_at, updated_at)
VALUES
    ('admin', 'Administrator with full system access', true, NOW(), NOW()),
    ('user', 'Regular user with limited access', true, NOW(), NOW()),
    ('analyst', 'Security analyst with read access to security data', true, NOW(), NOW()),
    ('operator', 'System operator with operational permissions', true, NOW(), NOW()),
    ('auditor', 'Security auditor with read access to audit logs', true, NOW(), NOW()),
    ('compliance_manager', 'Manages compliance requirements and assessments', true, NOW(), NOW()),
    ('security_officer', 'Oversees security operations and incidents', true, NOW(), NOW()),
    ('read_only', 'Read-only access to non-sensitive data', true, NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Insert permissions
INSERT INTO permissions (name, description, resource_type, action, created_at)
VALUES
    -- User management
    ('user:read', 'View user information', 'user', 'read', NOW()),
    ('user:write', 'Create and update users', 'user', 'write', NOW()),
    ('user:delete', 'Delete users', 'user', 'delete', NOW()),

    -- System configuration
    ('system:configure', 'Configure system settings', 'system', 'configure', NOW()),
    ('system:monitor', 'Monitor system status', 'system', 'monitor', NOW()),

    -- Cloud resources
    ('cloud:read', 'View cloud resources', 'cloud', 'read', NOW()),
    ('cloud:write', 'Create and update cloud resources', 'cloud', 'write', NOW()),
    ('cloud:manage', 'Manage cloud resources', 'cloud', 'manage', NOW()),
    ('cloud:delete', 'Delete cloud resources', 'cloud', 'delete', NOW()),

    -- ICS resources
    ('ics:read', 'View ICS data', 'ics', 'read', NOW()),
    ('ics:write', 'Create and update ICS data', 'ics', 'write', NOW()),
    ('ics:control', 'Control ICS devices', 'ics', 'control', NOW()),

    -- Audit log access
    ('audit:read', 'View audit logs', 'audit', 'read', NOW()),
    ('audit:export', 'Export audit logs', 'audit', 'export', NOW()),

    -- Security features
    ('security:read', 'View security settings', 'security', 'read', NOW()),
    ('security:manage', 'Manage security settings', 'security', 'manage', NOW()),
    ('security:incidents:read', 'View security incidents', 'security_incident', 'read', NOW()),
    ('security:incidents:manage', 'Manage security incidents', 'security_incident', 'manage', NOW()),

    -- File integrity monitoring
    ('fim:read', 'View file integrity monitoring data', 'fim', 'read', NOW()),
    ('fim:configure', 'Configure file integrity monitoring', 'fim', 'configure', NOW()),

    -- Compliance
    ('compliance:read', 'View compliance data', 'compliance', 'read', NOW()),
    ('compliance:manage', 'Manage compliance settings', 'compliance', 'manage', NOW()),

    -- Webhook management
    ('webhooks:read', 'View webhook configurations', 'webhooks', 'read', NOW()),
    ('webhooks:manage', 'Manage webhook configurations', 'webhooks', 'manage', NOW())
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to admin role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'admin'
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to security_officer role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'security_officer'
AND p.name IN (
    'security:read', 'security:manage', 'security:incidents:read',
    'security:incidents:manage', 'audit:read', 'fim:read', 'fim:configure',
    'compliance:read', 'system:monitor', 'user:read'
)
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to compliance_manager role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'compliance_manager'
AND p.name IN (
    'compliance:read', 'compliance:manage', 'audit:read', 'audit:export',
    'security:read', 'fim:read', 'system:monitor'
)
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to auditor role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'auditor'
AND p.name IN ('audit:read', 'audit:export', 'security:incidents:read', 'compliance:read', 'system:monitor')
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to analyst role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'analyst'
AND p.name IN ('security:read', 'security:incidents:read', 'system:monitor', 'fim:read', 'audit:read')
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to operator role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'operator'
AND p.name IN (
    'cloud:read', 'cloud:manage', 'ics:read', 'ics:control',
    'system:monitor', 'security:read'
)
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to read_only role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'read_only'
AND p.name IN ('cloud:read', 'ics:read', 'system:monitor')
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Assign permissions to user role
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'user'
AND p.name IN ('cloud:read', 'ics:read', 'webhooks:read', 'webhooks:manage')
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    WHERE rp.role_id = r.id AND rp.permission_id = p.id
);

-- Update admin user to use role_id instead of role string
DO $$
DECLARE
    admin_role_id INTEGER;
BEGIN
    SELECT id INTO admin_role_id FROM roles WHERE name = 'admin';
    IF admin_role_id IS NOT NULL THEN
        UPDATE users SET role_id = admin_role_id WHERE username = 'admin' AND (role_id IS NULL OR role = 'admin');
    END IF;
END $$;

-- Add security incident types
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'incident_types') THEN
        CREATE TABLE incident_types (
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE,
            description TEXT,
            severity VARCHAR(20) NOT NULL DEFAULT 'medium',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        );
    END IF;
END $$;

-- Insert incident types if table exists or use security_incidents table
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'incident_types') THEN
        INSERT INTO incident_types (name, description, severity, created_at, updated_at)
        VALUES
            ('brute_force', 'Multiple failed login attempts indicating possible brute force attack', 'high', NOW(), NOW()),
            ('suspicious_access', 'Access from unusual locations or during unusual hours', 'medium', NOW(), NOW()),
            ('data_leak', 'Potential data exfiltration or unauthorized data access', 'critical', NOW(), NOW()),
            ('malware_detected', 'Malware or suspicious code detected in the system', 'high', NOW(), NOW()),
            ('config_change', 'Unauthorized or suspicious configuration changes', 'medium', NOW(), NOW()),
            ('privilege_escalation', 'Attempts to elevate privileges or access unauthorized resources', 'critical', NOW(), NOW()),
            ('file_integrity', 'File integrity violation detected', 'high', NOW(), NOW()),
            ('dos_attack', 'Denial of service attack detected', 'critical', NOW(), NOW()),
            ('ransomware', 'Possible ransomware activity detected', 'critical', NOW(), NOW())
        ON CONFLICT (name) DO NOTHING;
    ELSIF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'security_incidents') THEN
        -- If using security_incidents table directly, add a sample incident
        INSERT INTO security_incidents (
            title, incident_type, description, severity, status, source,
            created_at, updated_at
        ) VALUES (
            'Initial System Setup',
            'system_initialization',
            'Sample security incident created during initial system setup',
            'info',
            'closed',
            'system',
            NOW(),
            NOW()
        );
    END IF;
END $$;

-- Add security baselines
INSERT INTO security_baselines (
    baseline_name, description, version, controls, status,
    created_at, updated_at
)
SELECT
    'default',
    'Default security baseline for all systems',
    '1.0',
    '{
        "firewall": {"enabled": true, "default_policy": "deny"},
        "authentication": {"mfa_required": true, "password_policy": "strong"},
        "encryption": {"disk_encryption": true, "tls_version": "1.2+"},
        "logging": {"retention_days": 90, "centralized": true}
    }'::jsonb,
    'active',
    NOW(),
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'security_baselines')
AND NOT EXISTS (SELECT 1 FROM security_baselines WHERE baseline_name = 'default');

-- Add compliance checks
INSERT INTO compliance_checks (
    check_name, description, severity, standard, control_id, check_type,
    implementation, remediation_steps, enabled, created_at, updated_at
)
SELECT
    'storage-encryption',
    'Verify that sensitive data storage is encrypted',
    'high',
    'PCI-DSS',
    '3.4',
    'automated',
    '{
        "query": "SELECT COUNT(*) FROM system_configs WHERE key = ''storage_encryption.enabled'' AND value = ''false''",
        "expected": "0"
    }'::jsonb,
    'Enable storage encryption in system configurations and for all sensitive data stores',
    true,
    NOW(),
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'compliance_checks')
AND NOT EXISTS (SELECT 1 FROM compliance_checks WHERE check_name = 'storage-encryption');

-- Add a circuit breaker configuration
INSERT INTO circuit_breakers (
    service_name, endpoint, status, failure_threshold, reset_timeout,
    last_status_change, created_at, updated_at
)
SELECT
    'external-api',
    'https://api.example.com/v1/data',
    'closed',
    5,
    60,
    NOW(),
    NOW(),
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'circuit_breakers')
AND NOT EXISTS (
    SELECT 1 FROM circuit_breakers
    WHERE service_name = 'external-api' AND endpoint = 'https://api.example.com/v1/data'
);

-- Add initial file integrity baseline metadata
INSERT INTO file_integrity_baselines (
    baseline_name, baseline_path, file_path, file_hash,
    hash_algorithm, is_critical, created_at, updated_at
)
SELECT
    'initial_baseline',
    '/etc/system/integrity',
    '/etc/passwd',
    'placeholder_hash_replace_during_actual_initialization',
    'sha256',
    true,
    NOW(),
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'file_integrity_baselines')
AND NOT EXISTS (
    SELECT 1 FROM file_integrity_baselines
    WHERE baseline_name = 'initial_baseline' AND file_path = '/etc/passwd'
);

-- Record database maintenance event
INSERT INTO database_maintenance (
    maintenance_type, target_object, target_schema, performed_by,
    details, operation_count, duration_ms, started_at, completed_at, success,
    created_at
)
SELECT
    'initial_setup',
    'all',
    'all',
    'system',
    '{"action": "initial_database_setup", "source": "seed.sql"}'::jsonb,
    1,
    0,
    NOW(),
    NOW(),
    true,
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'database_maintenance');

-- Record migration history entry
INSERT INTO migration_history (
    revision_id, revision_name, applied_by, applied_at, is_downgrade,
    execution_time_ms, success
)
SELECT
    'initial',
    'initial_seed_data',
    'system',
    NOW(),
    false,
    0,
    true
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'migration_history')
AND NOT EXISTS (
    SELECT 1 FROM migration_history WHERE revision_id = 'initial'
);

-- Record seed execution in audit log if applicable
INSERT INTO audit_logs (
    event_type, user_id, description, details, severity, created_at
)
SELECT
    'SYSTEM_SEED',
    (SELECT id FROM users WHERE username = 'admin' LIMIT 1),
    'Database seeded with initial data',
    'Initial system configuration and reference data inserted',
    'INFO',
    NOW()
WHERE EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'audit_logs');

COMMIT;
