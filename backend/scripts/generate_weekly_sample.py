#!/usr/bin/env python3
"""
Generate a week-long Zscaler NSS Web Log sample file
with realistic patterns and anomalies spread across 7 days
"""

import csv
import random
from datetime import datetime, timedelta

# Configuration
OUTPUT_FILE = 'backend/sample_data/zscaler_weekly_sample.csv'
START_DATE = datetime(2025, 11, 6, 8, 0, 0)  # Start: Nov 6, 2025 at 8 AM
DAYS = 7
LOGS_PER_DAY = 500  # ~3,500 total logs

# Users and departments
USERS = [
    ('john.doe', 'Engineering', 'San Francisco', 'SF-HQ', '192.168.1.100'),
    ('jane.smith', 'Finance', 'New York', 'NY-HQ', '192.168.2.50'),
    ('bob.johnson', 'Sales', 'Chicago', 'CHI-OFFICE', '192.168.3.75'),
    ('alice.williams', 'HR', 'San Francisco', 'SF-HQ', '192.168.1.120'),
    ('charlie.brown', 'IT', 'San Francisco', 'SF-HQ', '192.168.1.150'),
    ('david.miller', 'Engineering', 'Austin', 'AUS-OFFICE', '192.168.4.80'),
    ('emma.davis', 'Marketing', 'New York', 'NY-HQ', '192.168.2.90'),
    ('frank.wilson', 'Sales', 'Los Angeles', 'LA-OFFICE', '192.168.5.110'),
    ('grace.moore', 'Finance', 'Chicago', 'CHI-OFFICE', '192.168.3.95'),
    ('henry.taylor', 'IT', 'Austin', 'AUS-OFFICE', '192.168.4.120'),
]

# Normal websites
NORMAL_SITES = [
    ('https://google.com', 'Search Engines', '93.184.216.34', 10, 'GET', 200),
    ('https://github.com', 'Professional Services', '151.101.1.140', 15, 'GET', 200),
    ('https://gmail.com', 'Webmail', '172.217.14.206', 12, 'GET', 200),
    ('https://outlook.office365.com', 'Webmail', '13.107.42.14', 14, 'GET', 200),
    ('https://linkedin.com', 'Professional Networking', '104.16.132.229', 11, 'GET', 200),
    ('https://stackoverflow.com', 'Professional Services', '185.199.108.153', 13, 'GET', 200),
    ('https://slack.com', 'Business', '54.230.159.120', 16, 'GET', 200),
    ('https://zoom.us', 'Business', '170.114.52.2', 14, 'GET', 200),
    ('https://salesforce.com', 'Business', '136.147.174.25', 17, 'GET', 200),
    ('https://dropbox.com', 'Cloud Storage', '162.125.19.131', 18, 'POST', 200),
]

# Cloud storage uploads (higher risk)
CLOUD_UPLOADS = [
    ('https://drive.google.com', 'Cloud Storage', '172.217.14.206', 25, 'POST', 200, 'pdf', 'Q4_Report.pdf'),
    ('https://onedrive.live.com', 'Cloud Storage', '13.107.42.14', 28, 'POST', 200, 'xlsx', 'Financial_Data.xlsx'),
    ('https://dropbox.com', 'Cloud Storage', '162.125.19.131', 30, 'POST', 200, 'zip', 'Source_Code.zip'),
    ('https://box.com', 'Cloud Storage', '107.152.27.200', 27, 'POST', 200, 'docx', 'Contract.docx'),
]

# Malicious sites (threats)
MALICIOUS_SITES = [
    ('https://malicious-phishing-site.com', 'Phishing', '198.41.128.143', 95, 'GET', 403, 'Phishing', 'Phishing Site', 'Phishing', 'Malicious'),
    ('https://malware-download.net', 'Malware', '185.220.101.45', 98, 'GET', 403, 'Malware', 'Trojan Downloader', 'Trojan', 'Malicious'),
    ('https://c2-command-server.org', 'Command and Control', '45.142.120.10', 99, 'POST', 403, 'C2', 'Botnet C2', 'C2', 'Malicious'),
    ('https://cryptominer-pool.xyz', 'Cryptomining', '104.21.48.200', 92, 'GET', 403, 'Cryptomining', 'Mining Pool', 'Cryptominer', 'Malicious'),
    ('https://data-exfil-server.com', 'Data Exfiltration', '167.172.44.200', 97, 'POST', 403, 'Data Leak', 'Exfiltration Attempt', 'Data Theft', 'Malicious'),
]

# Suspicious sites (allowed but risky)
SUSPICIOUS_SITES = [
    ('https://torrent-site.org', 'File Sharing', '104.21.48.200', 65, 'GET', 200),
    ('https://proxy-bypass.net', 'Proxy Avoidance', '172.67.154.100', 70, 'GET', 200),
    ('https://anonymous-vpn.com', 'VPN', '104.18.24.200', 68, 'GET', 200),
    ('https://pastebin.com', 'File Sharing', '104.20.208.21', 55, 'GET', 200),
]

def generate_log_entry(timestamp, user_data, site_data, is_upload=False):
    """Generate a single log entry"""
    username, department, location, location_id, client_ip = user_data
    
    if is_upload:
        url, category, server_ip, risk, method, status, file_type, file_name = site_data
        threat_category = 'None'
        threat_name = 'None'
        action = 'Allowed'
        malware_category = 'None'
        malware_class = 'None'
        upload_file_type = file_type
        upload_file_name = file_name
        request_size = random.randint(5000000, 50000000)  # 5-50 MB uploads
        response_size = random.randint(500, 2000)
    elif len(site_data) > 6:  # Malicious site
        url, category, server_ip, risk, method, status, threat_category, threat_name, malware_category, malware_class = site_data
        action = 'Blocked'
        upload_file_type = 'None'
        upload_file_name = 'None'
        request_size = random.randint(400, 600)
        response_size = 0
    else:  # Normal or suspicious site
        url, category, server_ip, risk, method, status = site_data
        threat_category = 'None'
        threat_name = 'None'
        action = 'Allowed'
        malware_category = 'None'
        malware_class = 'None'
        upload_file_type = 'None'
        upload_file_name = 'None'
        request_size = random.randint(400, 1200)
        response_size = random.randint(1500, 4000)
    
    total_size = request_size + response_size
    
    return {
        'datetime': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'user': username,
        'department': department,
        'location': location,
        'location_id': location_id,
        'client_ip': client_ip,
        'server_ip': server_ip,
        'url': url,
        'url_category': category,
        'threat_category': threat_category,
        'threat_name': threat_name,
        'action': action,
        'risk_score': risk,
        'dlp_engine': 'None',
        'dlp_dictionaries': 'None',
        'file_type': 'None',
        'app_name': 'Web Browser',
        'app_class': 'Internet Services' if action == 'Allowed' else 'Security Risk',
        'cloud_app': 'Yes' if 'Cloud Storage' in category or 'Webmail' in category else 'No',
        'activity': 'Upload' if is_upload else 'Browsing',
        'http_method': method,
        'http_status': status,
        'user_agent': 'Mozilla/5.0',
        'request_size': request_size,
        'response_size': response_size,
        'total_size': total_size,
        'upload_file_type': upload_file_type,
        'upload_file_name': upload_file_name,
        'download_file_type': 'None',
        'download_file_name': 'None',
        'md5_hash': 'None',
        'sha256_hash': 'None',
        'malware_category': malware_category,
        'malware_class': malware_class,
        'device_owner': username,
    }

def is_business_hours(dt):
    """Check if timestamp is during business hours (8 AM - 6 PM, Mon-Fri)"""
    return dt.weekday() < 5 and 8 <= dt.hour < 18

def generate_weekly_logs():
    """Generate a week's worth of logs with realistic patterns"""
    logs = []
    current_time = START_DATE

    print(f"Generating {DAYS} days of Zscaler logs...")
    print(f"Start: {START_DATE}")
    print(f"End: {START_DATE + timedelta(days=DAYS)}")
    print(f"Target: ~{LOGS_PER_DAY * DAYS} total logs")
    print("=" * 80)

    for day in range(DAYS):
        day_start = START_DATE + timedelta(days=day)
        day_logs = 0

        # Generate logs throughout the day
        for _ in range(LOGS_PER_DAY):
            # Random time during the day (weighted towards business hours)
            if random.random() < 0.8:  # 80% during business hours
                hour = random.randint(8, 17)
            else:  # 20% outside business hours
                hour = random.choice(list(range(0, 8)) + list(range(18, 24)))

            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            timestamp = day_start.replace(hour=hour, minute=minute, second=second)

            # Select random user
            user_data = random.choice(USERS)

            # Determine activity type based on probabilities
            rand = random.random()

            if rand < 0.75:  # 75% normal browsing
                site_data = random.choice(NORMAL_SITES)
                log = generate_log_entry(timestamp, user_data, site_data)

            elif rand < 0.85:  # 10% cloud uploads
                site_data = random.choice(CLOUD_UPLOADS)
                log = generate_log_entry(timestamp, user_data, site_data, is_upload=True)

            elif rand < 0.92:  # 7% suspicious sites
                site_data = random.choice(SUSPICIOUS_SITES)
                log = generate_log_entry(timestamp, user_data, site_data)

            else:  # 8% malicious attempts (blocked)
                site_data = random.choice(MALICIOUS_SITES)
                log = generate_log_entry(timestamp, user_data, site_data)

            logs.append(log)
            day_logs += 1

        print(f"Day {day + 1} ({day_start.strftime('%Y-%m-%d')}): {day_logs} logs generated")

    # Add some anomaly patterns
    print("\nAdding anomaly patterns...")

    # Pattern 1: Data exfiltration attempt (Day 3, late night)
    exfil_time = START_DATE + timedelta(days=2, hours=23, minutes=15)
    exfil_user = USERS[0]  # john.doe
    for i in range(20):
        timestamp = exfil_time + timedelta(minutes=i)
        site_data = ('https://data-exfil-server.com', 'Data Exfiltration', '167.172.44.200', 97, 'POST', 403, 'Data Leak', 'Exfiltration Attempt', 'Data Theft', 'Malicious')
        logs.append(generate_log_entry(timestamp, exfil_user, site_data))
    print("  ✓ Added data exfiltration pattern (20 attempts)")

    # Pattern 2: Phishing campaign (Day 4, morning)
    phish_time = START_DATE + timedelta(days=3, hours=9, minutes=30)
    for i in range(15):
        user_data = random.choice(USERS)
        timestamp = phish_time + timedelta(minutes=i * 2)
        site_data = MALICIOUS_SITES[0]  # Phishing site
        logs.append(generate_log_entry(timestamp, user_data, site_data))
    print("  ✓ Added phishing campaign pattern (15 attempts)")

    # Pattern 3: Unusual upload volume (Day 5, afternoon)
    upload_time = START_DATE + timedelta(days=4, hours=14, minutes=0)
    upload_user = USERS[1]  # jane.smith
    for i in range(30):
        timestamp = upload_time + timedelta(minutes=i)
        site_data = random.choice(CLOUD_UPLOADS)
        logs.append(generate_log_entry(timestamp, upload_user, site_data, is_upload=True))
    print("  ✓ Added unusual upload volume pattern (30 uploads)")

    # Pattern 4: C2 beaconing (Day 6, throughout the day)
    c2_user = USERS[4]  # charlie.brown
    c2_start = START_DATE + timedelta(days=5, hours=8)
    for i in range(48):  # Every 15 minutes for 12 hours
        timestamp = c2_start + timedelta(minutes=i * 15)
        site_data = MALICIOUS_SITES[2]  # C2 server
        logs.append(generate_log_entry(timestamp, c2_user, site_data))
    print("  ✓ Added C2 beaconing pattern (48 beacons)")

    # Sort all logs by timestamp
    logs.sort(key=lambda x: x['datetime'])

    return logs

def main():
    """Main function"""
    logs = generate_weekly_logs()

    print("\n" + "=" * 80)
    print(f"Writing {len(logs)} logs to {OUTPUT_FILE}...")

    # Write to CSV
    fieldnames = [
        'datetime', 'user', 'department', 'location', 'location_id', 'client_ip',
        'server_ip', 'url', 'url_category', 'threat_category', 'threat_name',
        'action', 'risk_score', 'dlp_engine', 'dlp_dictionaries', 'file_type',
        'app_name', 'app_class', 'cloud_app', 'activity', 'http_method',
        'http_status', 'user_agent', 'request_size', 'response_size', 'total_size',
        'upload_file_type', 'upload_file_name', 'download_file_type',
        'download_file_name', 'md5_hash', 'sha256_hash', 'malware_category',
        'malware_class', 'device_owner'
    ]

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(logs)

    print(f"✅ Successfully created {OUTPUT_FILE}")
    print(f"   Total logs: {len(logs)}")
    print(f"   Date range: {logs[0]['datetime']} to {logs[-1]['datetime']}")
    print(f"   File size: ~{len(logs) * 500 / 1024:.1f} KB")

    # Statistics
    blocked = sum(1 for log in logs if log['action'] == 'Blocked')
    uploads = sum(1 for log in logs if log['activity'] == 'Upload')
    high_risk = sum(1 for log in logs if log['risk_score'] >= 70)

    print("\n📊 Statistics:")
    print(f"   Blocked requests: {blocked} ({blocked/len(logs)*100:.1f}%)")
    print(f"   Upload activities: {uploads} ({uploads/len(logs)*100:.1f}%)")
    print(f"   High risk (≥70): {high_risk} ({high_risk/len(logs)*100:.1f}%)")

if __name__ == '__main__':
    main()

