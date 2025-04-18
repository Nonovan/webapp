# Database Scripts

This directory contains scripts for managing the Cloud Infrastructure Platform database.

## Available Scripts

- `seed_data.py` - Seeds the database with initial and optional development data
- `backup_db.sh` - Creates database backups
- `restore_db.sh` - Restores database from backups
- `database-manager.sh` - Comprehensive utility for database operations (backup, restore, verify, list, rotate, seed)
- `init_db.py` - Initializes a new database instance with proper structure and permissions

## Usage

Most scripts accept an environment parameter:

```bash
./backup_db.sh [environment]  # Default: production
./restore_db.sh [backup_file] [environment]
./database-manager.sh backup --env production
```