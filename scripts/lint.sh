#!/bin/bash
echo "Running flake8..."
flake8 app.py api/ blueprints/ core/ models/ extensions/ services/

echo "Running isort..."
isort --profile black app.py api/ blueprints/ core/ models/ extensions/ services/

echo "Running black..."
black app.py api/ blueprints/ core/ models/ extensions/ services/

echo "Running bandit security checks..."
bandit -r app.py api/ blueprints/ core/ models/ extensions/ services/