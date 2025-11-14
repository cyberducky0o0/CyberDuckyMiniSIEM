#!/usr/bin/env python3
"""
Test script to verify dashboard API endpoints
"""
import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:5000"
EMAIL = "admin@cyberducky.local"
PASSWORD = "admin123"

def login():
    """Login and get JWT token"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": EMAIL, "password": PASSWORD}
    )
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        print(f"❌ Login failed: {response.text}")
        sys.exit(1)

def test_endpoint(name, endpoint, token):
    """Test a single dashboard endpoint"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ {name}")
        return data
    else:
        print(f"❌ {name}: {response.status_code} - {response.text[:200]}")
        return None

def main():
    print("=" * 80)
    print("🧪 Testing Dashboard API Endpoints")
    print("=" * 80)
    
    # Login
    print("\n🔐 Logging in...")
    token = login()
    print(f"✅ Login successful")
    
    # Test dashboard endpoints
    print("\n📊 Testing Dashboard Endpoints:")
    print("-" * 80)
    
    # Test overview
    overview = test_endpoint("Dashboard Overview", "/api/dashboard/overview", token)
    if overview:
        print(f"  - Total Files: {overview.get('total_files', 0)}")
        print(f"  - Total Entries: {overview.get('total_entries', 0)}")
        print(f"  - Total Anomalies: {overview.get('total_anomalies', 0)}")
        print(f"  - Critical Anomalies: {overview.get('critical_anomalies', 0)}")
        print(f"  - Avg Risk Score: {overview.get('avg_risk_score', 0):.2f}")
        print(f"  - Unique Users: {overview.get('unique_users', 0)}")
        print(f"  - Unique IPs: {overview.get('unique_ips', 0)}")
        print(f"  - Threat Count: {overview.get('threat_count', 0)}")
    
    # Test anomaly trends
    print()
    trends = test_endpoint("Anomaly Trends", "/api/dashboard/anomaly-trends", token)
    if trends:
        print(f"  - Time Series Buckets: {len(trends.get('time_series', []))}")
        print(f"  - By Severity: {trends.get('by_severity', {})}")
        print(f"  - Top Anomaly Types: {len(trends.get('by_type', []))}")
    
    # Test top threats
    print()
    threats = test_endpoint("Top Threats", "/api/dashboard/top-threats", token)
    if threats:
        print(f"  - Top Threats: {len(threats.get('threats', []))}")
        print(f"  - Top Categories: {len(threats.get('categories', []))}")
        print(f"  - Top Users: {len(threats.get('users', []))}")
        print(f"  - Top IPs: {len(threats.get('ips', []))}")
        
        if threats.get('threats'):
            print(f"\n  Top 3 Threats:")
            for i, threat in enumerate(threats['threats'][:3], 1):
                print(f"    {i}. {threat['name']} - {threat['count']} occurrences (Avg Risk: {threat['avg_risk']:.1f})")
    
    print("\n" + "=" * 80)
    print("✅ Testing Complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()

