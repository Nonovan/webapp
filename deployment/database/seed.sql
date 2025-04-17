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
    ('password_policy', '{"min_length": 8, "require_uppercase": true, "require_lowercase": true, "require_number": true, "require_special": true}', 'Password policy requirements', false, NOW(), NOW())
ON CONFLICT (key) DO NOTHING;

-- Example roles and permissions (if applicable to your schema)
-- This assumes you have roles and permissions tables
-- Modify this section to match your actual schema

/*
-- Insert roles
INSERT INTO roles (name, description, created_at, updated_at)
VALUES 
    ('admin', 'Administrator with full system access', NOW(), NOW()),
    ('user', 'Regular user with limited access', NOW(), NOW()),
    ('analyst', 'Data analyst with read access to analytics', NOW(), NOW()),
    ('operator', 'System operator with operational permissions', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Insert permissions
INSERT INTO permissions (name, description, created_at, updated_at)
VALUES
    ('user:read', 'View user information', NOW(), NOW()),
    ('user:write', 'Create and update users', NOW(), NOW()),
    ('user:delete', 'Delete users', NOW(), NOW()),
    ('system:configure', 'Configure system settings', NOW(), NOW()),
    ('cloud:manage', 'Manage cloud resources', NOW(), NOW()),
    ('ics:read', 'View ICS data', NOW(), NOW()),
    ('ics:control', 'Control ICS devices', NOW(), NOW()),
    ('audit:read', 'View audit logs', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name IN ('user:read', 'user:write', 'user:delete', 'system:configure', 'cloud:manage', 'ics:read', 'ics:control', 'audit:read')
AND NOT EXISTS (
    SELECT 1 FROM role_permissions rp
    JOIN roles r2 ON rp.role_id = r2.id
    JOIN permissions p2 ON rp.permission_id = p2.id
    WHERE r2.name = 'admin' AND p2.name = p.name
);
*/

-- Add default security incident types
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

-- Insert incident types if table exists
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
            ('privilege_escalation', 'Attempts to elevate privileges or access unauthorized resources', 'critical', NOW(), NOW())
        ON CONFLICT (name) DO NOTHING;
    END IF;
END $$;

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