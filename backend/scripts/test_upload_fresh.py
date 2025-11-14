#!/usr/bin/env python3
"""
Quick test script to upload sample data with a fresh file
"""
import requests
import os

API_BASE_URL = 'http://localhost:5000/api'
EMAIL = 'admin@cyberducky.local'
PASSWORD = 'admin123'
SAMPLE_FILE = 'backend/sample_data/comprehensive_zscaler_sample.csv'

# Login
response = requests.post(
    f"{API_BASE_URL}/auth/login",
    json={"email": EMAIL, "password": PASSWORD},
    timeout=10
)
token = response.json()['access_token']
print(f"✅ Logged in, token: {token[:20]}...")

# Upload file
with open(SAMPLE_FILE, 'rb') as f:
    files = {'file': (f'test_{os.urandom(4).hex()}.csv', f, 'text/csv')}
    data = {'log_type': 'zscaler'}
    headers = {'Authorization': f'Bearer {token}'}
    
    response = requests.post(
        f"{API_BASE_URL}/upload",
        files=files,
        data=data,
        headers=headers,
        timeout=60
    )

result = response.json()
print(f"\n✅ Upload response: {result}")

if 'log_file' in result:
    log_file = result['log_file']
    print(f"\n📊 Results:")
    print(f"   File ID: {log_file.get('id')}")
    print(f"   Logs parsed: {log_file.get('parsed_entries', 0)}")
    print(f"   Total lines: {log_file.get('total_entries', 0)}")
    print(f"   Failed: {log_file.get('failed_entries', 0)}")
    print(f"   Status: {log_file.get('status')}")

