#!/usr/bin/env python
"""
Database initialization script for Cloud Infrastructure Platform

This script initializes a new database with the required schema and initial data.
It can be used for setting up new environments or resetting development databases.
"""

import os
import sys
import argparse
import subprocess
from configparser import ConfigParser
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Initialize database for Cloud Infrastructure Platform")
    parser.add_argument("--env", default="development", choices=["development", "staging", "production"],
                        help="Target environment (default: development)")
    parser.add_argument("--config", default="deployment/database/db_config.ini", help="Path to database config file")
    parser.add_argument("--schema-only", action="store_true", help="Only create schema, skip sample data")
    parser.add_argument("--drop-existing", action="store_true", help="Drop existing database before creating")
    return parser.parse_args()

def read_config(config_path, env):
    """Read database configuration from file."""
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
        
    config = ConfigParser()
    config.read(config_path)
    
    try:
        db_config = {
            "host": config.get(env, "host"),
            "port": config.get(env, "port"),
            "user": config.get(env, "admin_user"),
            "password": config.get(env, "admin_password"),
            "dbname": config.get(env, "dbname")
        }
        app_user = config.get(env, "app_user")
        app_password = config.get(env, "app_password")
        return db_config, app_user, app_password
    except Exception as e:
        print(f"Error reading config: {e}")
        sys.exit(1)

def create_database(db_config, app_user, app_password, drop_existing=False):
    """Create a new database with appropriate permissions."""
    # Connect to default postgres database to create new database
    conn_params = db_config.copy()
    conn_params["dbname"] = "postgres"
    
    try:
        # Connect to postgres database
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        dbname = db_config["dbname"]
        
        # Drop database if requested and exists
        if drop_existing:
            cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{dbname}'")
            exists = cursor.fetchone()
            if exists:
                print(f"Dropping existing database '{dbname}'...")
                cursor.execute(f"DROP DATABASE IF EXISTS {dbname}")
        
        # Create database
        print(f"Creating database '{dbname}'...")
        cursor.execute(f"CREATE DATABASE {dbname}")
        
        # Create app user if not exists
        cursor.execute(f"SELECT 1 FROM pg_roles WHERE rolname = '{app_user}'")
        user_exists = cursor.fetchone()
        if not user_exists:
            print(f"Creating application user '{app_user}'...")
            cursor.execute(f"CREATE USER {app_user} WITH PASSWORD '{app_password}'")
        
        # Grant privileges
        print(f"Granting privileges to '{app_user}'...")
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {dbname} TO {app_user}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error creating database: {e}")
        sys.exit(1)
    
    # Now connect to the new database to run initialization script
    conn_params = db_config.copy()
    
    try:
        # Connect to the newly created database
        conn = psycopg2.connect(**conn_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Enable extensions
        print("Enabling extensions...")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS uuid-ossp")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        
        cursor.close()
        conn.close()
        
        print(f"Database '{dbname}' initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        sys.exit(1)

def apply_migrations():
    """Apply database migrations"""
    print("Applying migrations...")
    try:
        subprocess.run(["flask", "db", "upgrade"], check=True)
        print("Migrations applied successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error applying migrations: {e}")
        sys.exit(1)

def seed_data():
    """Seed initial data"""
    print("Seeding initial data...")
    try:
        subprocess.run(["python", "scripts/seed_data.py"], check=True)
        print("Data seeded successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error seeding data: {e}")
        sys.exit(1)

def main():
    """Main function"""
    args = parse_args()
    
    print(f"Initializing {args.env} database...")
    
    # Read database configuration
    db_config, app_user, app_password = read_config(args.config, args.env)
    
    # Create database
    success = create_database(db_config, app_user, app_password, args.drop_existing)
    if not success:
        return
    
    # Apply migrations
    success = apply_migrations()
    if not success:
        return
    
    # Seed initial data if not schema-only
    if not args.schema_only:
        success = seed_data()
        if not success:
            return
            
    print(f"Database initialization for {args.env} completed successfully")

if __name__ == "__main__":
    main()
