#!/usr/bin/env python3
"""Run security audits on the application"""
import subprocess
import sys
import os

def run_bandit():
    """Run Bandit security scanner"""
    print("Running Bandit security scanner...")
    result = subprocess.run(["bandit", "-r", ".", "-x", "venv,tests,migrations"], 
                           capture_output=True, text=True)
    print(result.stdout)
    return result.returncode
    
def check_dependencies():
    """Check dependencies for security vulnerabilities"""
    print("Checking dependencies for security vulnerabilities...")
    result = subprocess.run(["safety", "check", "-r", "requirements.txt"],
                          capture_output=True, text=True)
    print(result.stdout)
    return result.returncode

exit_code = run_bandit() + check_dependencies()
sys.exit(exit_code)