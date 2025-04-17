#!/usr/bin/env python3
"""Seed demo data for development environment"""
from app import create_app
from core.seeder import seed_database, seed_development_data
import sys

app = create_app()
with app.app_context():
    print("Seeding database with initial data...")
    success = seed_database()
    
    if '--dev' in sys.argv:
        print("Adding development test data...")
        success = seed_development_data() and success
    
    if success:
        print("✅ Data seeding completed successfully")
        sys.exit(0)
    else:
        print("❌ Data seeding failed")
        sys.exit(1)