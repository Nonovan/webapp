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
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cloud_platform_monitor') THEN
    CREATE ROLE cloud_platform_monitor WITH LOGIN PASSWORD 'replace_with_secure_password';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'cloud_platform_backup') THEN
    CREATE ROLE cloud_platform_backup WITH LOGIN PASSWORD 'replace_with_secure_password';
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
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloud_platform_dr') THEN
    CREATE DATABASE cloud_platform_dr;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cloud_platform_test') THEN
    CREATE DATABASE cloud_platform_test;
  END IF;
END
$$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_production TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_staging TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_development TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_dr TO cloud_platform_app;
GRANT ALL PRIVILEGES ON DATABASE cloud_platform_test TO cloud_platform_app;

GRANT CONNECT ON DATABASE cloud_platform_production TO cloud_platform_readonly, cloud_platform_monitor;
GRANT CONNECT ON DATABASE cloud_platform_staging TO cloud_platform_readonly, cloud_platform_monitor;
GRANT CONNECT ON DATABASE cloud_platform_development TO cloud_platform_readonly, cloud_platform_monitor;
GRANT CONNECT ON DATABASE cloud_platform_dr TO cloud_platform_readonly, cloud_platform_monitor;
GRANT CONNECT ON DATABASE cloud_platform_test TO cloud_platform_readonly;

-- Give backup role appropriate permissions
GRANT CONNECT ON DATABASE cloud_platform_production TO cloud_platform_backup;
GRANT CONNECT ON DATABASE cloud_platform_staging TO cloud_platform_backup;
GRANT CONNECT ON DATABASE cloud_platform_dr TO cloud_platform_backup;

-- Set ownership for databases
ALTER DATABASE cloud_platform_production OWNER TO cloud_platform_app;
ALTER DATABASE cloud_platform_staging OWNER TO cloud_platform_app;
ALTER DATABASE cloud_platform_development OWNER TO cloud_platform_app;
ALTER DATABASE cloud_platform_dr OWNER TO cloud_platform_app;
ALTER DATABASE cloud_platform_test OWNER TO cloud_platform_app;

-- Connect to the production database to set up extensions and schemas
\c cloud_platform_production

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";  -- For time range queries
CREATE EXTENSION IF NOT EXISTS "hstore";      -- For key-value storage

-- Create schemas
CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS metrics;
CREATE SCHEMA IF NOT EXISTS compliance;

-- Set default privileges
ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA compliance
GRANT SELECT ON TABLES TO cloud_platform_readonly;

-- Grant additional permissions to the monitor role for metrics and monitoring
ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_monitor;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_monitor;

-- Grant backup user permissions
GRANT pg_read_all_data TO cloud_platform_backup;

-- Set search path
ALTER DATABASE cloud_platform_production SET search_path TO public, cloud, ics, security, audit, metrics, compliance;

-- Repeat for staging
\c cloud_platform_staging

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "hstore";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS metrics;
CREATE SCHEMA IF NOT EXISTS compliance;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA compliance
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_monitor;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_monitor;

GRANT pg_read_all_data TO cloud_platform_backup;

ALTER DATABASE cloud_platform_staging SET search_path TO public, cloud, ics, security, audit, metrics, compliance;

-- Repeat for development
\c cloud_platform_development

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "hstore";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS metrics;
CREATE SCHEMA IF NOT EXISTS compliance;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA compliance
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DATABASE cloud_platform_development SET search_path TO public, cloud, ics, security, audit, metrics, compliance;

-- Setup for DR environment
\c cloud_platform_dr

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "hstore";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS metrics;
CREATE SCHEMA IF NOT EXISTS compliance;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA cloud
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA ics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA security
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA audit
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA compliance
GRANT SELECT ON TABLES TO cloud_platform_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA public
GRANT SELECT ON TABLES TO cloud_platform_monitor;

ALTER DEFAULT PRIVILEGES FOR ROLE cloud_platform_app IN SCHEMA metrics
GRANT SELECT ON TABLES TO cloud_platform_monitor;

GRANT pg_read_all_data TO cloud_platform_backup;

ALTER DATABASE cloud_platform_dr SET search_path TO public, cloud, ics, security, audit, metrics, compliance;

-- Setup for test environment (minimal setup)
\c cloud_platform_test

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";
CREATE EXTENSION IF NOT EXISTS "hstore";

CREATE SCHEMA IF NOT EXISTS cloud;
CREATE SCHEMA IF NOT EXISTS ics;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS metrics;
CREATE SCHEMA IF NOT EXISTS compliance;

ALTER DATABASE cloud_platform_test SET search_path TO public, cloud, ics, security, audit, metrics, compliance;

-- Configure session management and security settings across all databases

-- Production
\c cloud_platform_production
ALTER DATABASE cloud_platform_production SET statement_timeout = '30s';
ALTER DATABASE cloud_platform_production SET idle_in_transaction_session_timeout = '60s';
ALTER DATABASE cloud_platform_production SET log_statement = 'ddl';
ALTER DATABASE cloud_platform_production SET log_min_duration_statement = 1000;  -- 1 sec

-- Staging
\c cloud_platform_staging
ALTER DATABASE cloud_platform_staging SET statement_timeout = '60s';
ALTER DATABASE cloud_platform_staging SET idle_in_transaction_session_timeout = '300s';
ALTER DATABASE cloud_platform_staging SET log_statement = 'ddl';
ALTER DATABASE cloud_platform_staging SET log_min_duration_statement = 1000;  -- 1 sec

-- Development
\c cloud_platform_development
ALTER DATABASE cloud_platform_development SET statement_timeout = '120s';
ALTER DATABASE cloud_platform_development SET idle_in_transaction_session_timeout = '600s';
ALTER DATABASE cloud_platform_development SET log_statement = 'mod';
ALTER DATABASE cloud_platform_development SET log_min_duration_statement = 500;  -- 500 ms

-- DR
\c cloud_platform_dr
ALTER DATABASE cloud_platform_dr SET statement_timeout = '30s';
ALTER DATABASE cloud_platform_dr SET idle_in_transaction_session_timeout = '60s';
ALTER DATABASE cloud_platform_dr SET log_statement = 'ddl';
ALTER DATABASE cloud_platform_dr SET log_min_duration_statement = 1000;  -- 1 sec
