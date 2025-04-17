#!/bin/bash
# Production deployment script
echo "Starting deployment..."

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt

# Run migrations
flask db upgrade

# Clear cache
flask cache clear

# Restart services
sudo systemctl restart cloud-platform-gunicorn
sudo systemctl restart cloud-platform-celery

echo "Deployment completed successfully"