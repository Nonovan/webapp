/**
 * Initial PostgreSQL Database Setup for Cloud Infrastructure Platform
 *
 * This script creates the necessary databases, roles, and permissions
 * for the different environments of the application.
 */

-- Create database roles with appropriate permissions
-- Make sure the roles don't already exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cloud_platform_app') THEN
    CREATE ROLE cloud_platform_app WITH LOGIN PASSWORD 'replace_with_secure_password';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cloud_platform_readonly') THEN
    CREATE ROLE cloud_platform_readonly WITH LOGIN PASSWORD 'replace_with_secure_password';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cloud_platform_admin') THEN
    CREATE ROLE cloud_platform_admin WITH LOGIN PASSWORD 'replace_with_secure_password' SUPERUSER;
  END IF;
END
$$;

-- Create databases for different environments
-- Check if databases exist before creating them
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloud_platform_production') THEN
    CREATE DATABASE cloud_platform_production;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloud_platform_staging') THEN
    CREATE DATABASE cloud_platform_staging;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloud_platform_development') THEN
    CREATE DATABASE cloud_platform_development;
  END IF;
END
$$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_production TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_staging TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_development TO cloud_platform_app;

GRANT CONNECT ON DATABASE cloud_platform_production TO cloud_platform_readonly;
GRANT CONNECT ON DATABASE cloud_platform_staging TO cloud_platform_readonly;
GRANT CONNECT ON DATABASE cloud_platform_development TO cloud_platform_readonly;

-- Set ownership for production database
ALTER DATABASE cloud_platform_production OWNER TO cloud_platform_app;

-- Connect to the production database to set up extensions and schemas
\c cloud_platform_production

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set default privileges
ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

-- Set search path
ALTER DATABASE cloud_platform_production SET search_path TO public, cloud, ics, security, audit;

-- Repeat for staging
\c cloud_platform_staging

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DATABASE cloud_platform_staging SET search_path TO public, cloud, ics, security, audit;

-- Repeat for development
\c cloud_platform_development

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;

ALTER DATABASE cloud_platform_development SET search_path TO public, cloud, ics, security, audit;