#!/usr/bin/env python3
"""
Test script to verify all visualization endpoints are working
"""
import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:5000"
EMAIL = "admin@cyberducky.local"
PASSWORD = "admin123"
FILE_ID = "ebc21bf1-3b4d-4bc8-a05d-c2c1818a09d0"  # From sample data upload

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
    """Test a single visualization endpoint"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}{endpoint}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ {name}")
        return data
    else:
        print(f"❌ {name}: {response.status_code} - {response.text[:100]}")
        return None

def main():
    print("=" * 80)
    print("🧪 Testing Visualization API Endpoints")
    print("=" * 80)
    
    # Login
    print("\n🔐 Logging in...")
    token = login()
    print(f"✅ Login successful")
    
    # Test all visualization endpoints
    print("\n📊 Testing Visualization Endpoints:")
    print("-" * 80)
    
    endpoints = [
        ("Risk Trendline", f"/api/visualization/risk-trendline/{FILE_ID}"),
        ("Z-Score Heatmap", f"/api/visualization/z-score-heatmap/{FILE_ID}"),
        ("Anomaly Scatter", f"/api/visualization/anomaly-scatter/{FILE_ID}"),
        ("Box Plot", f"/api/visualization/boxplot-per-user/{FILE_ID}"),
        ("Density Plot", f"/api/visualization/density-plot/{FILE_ID}"),
        ("Control Chart", f"/api/visualization/ewma-control-chart/{FILE_ID}"),
        ("Event Timeline", f"/api/visualization/event-timeline/{FILE_ID}"),
        ("Anomaly Time Series", f"/api/visualization/anomaly-time-series/{FILE_ID}"),
        ("Statistical Summary", f"/api/visualization/statistical-summary/{FILE_ID}"),
        ("Requests Per Minute", f"/api/visualization/requests-per-minute/{FILE_ID}"),
        ("All Visualizations", f"/api/visualization/all-visualizations/{FILE_ID}"),
    ]
    
    results = {}
    for name, endpoint in endpoints:
        data = test_endpoint(name, endpoint, token)
        results[name] = data is not None
    
    # Summary
    print("\n" + "=" * 80)
    print("📈 Summary:")
    print("-" * 80)
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All visualization endpoints are working!")
    else:
        print("\n⚠️  Some endpoints failed. Check the output above.")
    
    # Test specific data points
    print("\n" + "=" * 80)
    print("🔍 Data Validation:")
    print("-" * 80)
    
    # Test risk trendline data
    risk_data = test_endpoint("Risk Trendline (detailed)", f"/api/visualization/risk-trendline/{FILE_ID}", token)
    if risk_data:
        print(f"  - Timestamps: {len(risk_data.get('timestamps', []))} data points")
        print(f"  - Mean Risk Score: {risk_data.get('mean', 'N/A')}")
        print(f"  - Std Dev: {risk_data.get('std_dev', 'N/A')}")
    
    # Test anomaly time series
    anomaly_ts = test_endpoint("Anomaly Time Series (detailed)", f"/api/visualization/anomaly-time-series/{FILE_ID}", token)
    if anomaly_ts and 'time_series' in anomaly_ts:
        ts_data = anomaly_ts['time_series']
        print(f"  - Time Buckets: {len(ts_data)}")
        if ts_data and len(ts_data) > 0:
            # Check if the first item has the expected fields
            first_item = ts_data[0]
            if 'total' in first_item:
                total_anomalies = sum(item.get('total', 0) for item in ts_data)
                print(f"  - Total Anomalies: {total_anomalies}")
            else:
                print(f"  - Sample data: {first_item}")
    
    # Test statistical summary
    stats = test_endpoint("Statistical Summary (detailed)", f"/api/visualization/statistical-summary/{FILE_ID}", token)
    if stats:
        print(f"  - Total Anomalies: {stats.get('total_anomalies', 'N/A')}")
        print(f"  - Avg Risk Score: {stats.get('avg_risk_score', 'N/A')}")
        print(f"  - Max Risk Score: {stats.get('max_risk_score', 'N/A')}")
        print(f"  - Unique Users: {stats.get('unique_users', 'N/A')}")
    
    print("\n" + "=" * 80)
    print("✅ Testing Complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()

