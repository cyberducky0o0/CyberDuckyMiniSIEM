#!/usr/bin/env python3
"""
Upload Sample Data Script

This script uploads the comprehensive Zscaler sample data to the CyberDucky Mini SIEM
and triggers all anomaly detection and visualization features.

Usage:
    python scripts/upload_sample_data.py

Requirements:
    - Backend must be running on http://localhost:5000
    - User must be registered (default: admin/admin)
"""

import os
import sys
import time
import requests
from pathlib import Path

# Configuration
API_BASE_URL = os.getenv('API_BASE_URL', 'http://localhost:5000/api')
EMAIL = os.getenv('SIEM_EMAIL', 'admin@cyberducky.local')
PASSWORD = os.getenv('SIEM_PASSWORD', 'admin123')
SAMPLE_FILE = 'backend/sample_data/comprehensive_zscaler_sample.csv'

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")

def print_step(step_num, text):
    """Print formatted step"""
    print(f"\n[{step_num}] {text}")
    print("-" * 60)

def register_user():
    """Register a new user (if not exists)"""
    print_step(1, "Registering user...")

    try:
        response = requests.post(
            f"{API_BASE_URL}/auth/register",
            json={
                "email": EMAIL,
                "password": PASSWORD,
                "first_name": "Admin",
                "last_name": "User"
            },
            timeout=10
        )

        if response.status_code == 201:
            print(f"User '{EMAIL}' registered successfully")
            return True
        elif response.status_code == 400 and ("already" in response.text.lower() or "registered" in response.text.lower()):
            print(f"User '{EMAIL}' already exists")
            return True
        else:
            print(f"Registration failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f" Registration error: {e}")
        return False

def login():
    """Login and get JWT token"""
    print_step(2, "Logging in...")

    try:
        response = requests.post(
            f"{API_BASE_URL}/auth/login",
            json={
                "email": EMAIL,
                "password": PASSWORD
            },
            timeout=10
        )
        
        if response.status_code == 200:
            token = response.json().get('access_token')
            print(f" Login successful")
            print(f"   Token: {token[:20]}...")
            return token
        else:
            print(f" Login failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f" Login error: {e}")
        return None

def upload_file(token):
    """Upload sample data file"""
    print_step(3, "Uploading sample data...")
    
    # Check if file exists
    if not os.path.exists(SAMPLE_FILE):
        print(f" Sample file not found: {SAMPLE_FILE}")
        return None
    
    file_size = os.path.getsize(SAMPLE_FILE)
    print(f"   File: {SAMPLE_FILE}")
    print(f"   Size: {file_size:,} bytes ({file_size / 1024:.2f} KB)")
    
    try:
        with open(SAMPLE_FILE, 'rb') as f:
            files = {'file': (os.path.basename(SAMPLE_FILE), f, 'text/csv')}
            data = {'log_type': 'zscaler'}
            headers = {'Authorization': f'Bearer {token}'}
            
            print("   Uploading... (this may take a few seconds)")
            response = requests.post(
                f"{API_BASE_URL}/upload",
                files=files,
                data=data,
                headers=headers,
                timeout=60
            )
        
        if response.status_code == 201:
            result = response.json()
            log_file = result.get('log_file', {})
            file_id = log_file.get('id')
            log_count = log_file.get('log_count', 0)
            print(f" Upload successful!")
            print(f"   File ID: {file_id}")
            print(f"   Logs parsed: {log_count}")
            return file_id
        else:
            print(f" Upload failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f" Upload error: {e}")
        return None

def check_anomalies(token, file_id):
    """Check anomaly detection results"""
    print_step(4, "Checking anomaly detection...")
    
    print("   Waiting for anomaly detection to complete...")
    time.sleep(5)  # Give it a few seconds to process
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{API_BASE_URL}/anomalies/{file_id}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            anomalies = response.json()
            total = len(anomalies)
            
            # Count by severity
            severity_counts = {}
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print(f" Anomaly detection complete!")
            print(f"   Total anomalies: {total}")
            for severity, count in sorted(severity_counts.items()):
                print(f"   - {severity.capitalize()}: {count}")
            
            return total
        else:
            print(f" Failed to fetch anomalies: {response.status_code}")
            return 0
    except Exception as e:
        print(f" Error checking anomalies: {e}")
        return 0

def check_llm_status(token):
    """Check if LLM service is available"""
    print_step(5, "Checking LLM service...")
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{API_BASE_URL}/llm/status",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            status = response.json()
            available = status.get('available', False)
            models = status.get('models', [])
            
            if available:
                print(f" LLM service is available")
                print(f"   Models: {', '.join(models)}")
                return True
            else:
                print(f"  LLM service is not available")
                print(f"   Note: High/critical anomalies won't get AI explanations")
                return False
        else:
            print(f"  LLM status check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"  LLM status error: {e}")
        return False

def print_summary(file_id, anomaly_count, llm_available):
    """Print summary and next steps"""
    print_header(" Upload Complete!")
    
    print(" Summary:")
    print(f"   - File ID: {file_id}")
    print(f"   - Anomalies detected: {anomaly_count}")
    print(f"   - LLM available: {'Yes' if llm_available else 'No'}")
    
    print("\n Next Steps:")
    print(f"   1. View dashboard: http://localhost:5173")
    print(f"   2. View anomalies: GET /api/anomalies/{file_id}")
    print(f"   3. View visualizations:")
    print(f"      - Risk trendline: GET /api/visualization/risk-trendline/{file_id}")
    print(f"      - Z-score heatmap: GET /api/visualization/z-score-heatmap/{file_id}")
    print(f"      - Anomaly scatter: GET /api/visualization/anomaly-scatter/{file_id}")
    print(f"   4. Generate investigation report:")
    print(f"      POST /api/llm/investigation-report")
    print(f"      {{'log_file_id': '{file_id}', 'user': 'john.doe'}}")
    
    print("\n Documentation:")
    print(f"   - Sample data guide: backend/sample_data/SAMPLE_DATA_GUIDE.md")
    print(f"   - Feature summary: COMPLETE_FEATURE_SUMMARY.md")
    print(f"   - SOC analyst guide: SOC_ANALYST_QUICK_REFERENCE.md")
    
    print("\n" + "=" * 60 + "\n")

def main():
    """Main execution"""
    print_header(" CyberDucky Mini SIEM - Sample Data Upload")
    
    print("Configuration:")
    print(f"   API URL: {API_BASE_URL}")
    print(f"   Email: {EMAIL}")
    print(f"   Sample file: {SAMPLE_FILE}")
    
    # Step 1: Register user
    if not register_user():
        print("\n Failed to register user. Exiting.")
        sys.exit(1)
    
    # Step 2: Login
    token = login()
    if not token:
        print("\n Failed to login. Exiting.")
        sys.exit(1)
    
    # Step 3: Upload file
    file_id = upload_file(token)
    if not file_id:
        print("\n Failed to upload file. Exiting.")
        sys.exit(1)
    
    # Step 4: Check anomalies
    anomaly_count = check_anomalies(token, file_id)
    
    # Step 5: Check LLM
    llm_available = check_llm_status(token)
    
    # Print summary
    print_summary(file_id, anomaly_count, llm_available)
    
    print(" All done! Your SIEM is ready for analysis.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Upload cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

