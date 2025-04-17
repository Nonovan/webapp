#!/bin/bash
# Set up development environment for Cloud Infrastructure Platform
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask db upgrade
flask create-admin
echo "Development environment setup complete!"