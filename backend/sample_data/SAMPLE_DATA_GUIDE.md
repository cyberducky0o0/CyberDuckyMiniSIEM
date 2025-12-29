#  Comprehensive Zscaler Sample Data Guide

**File:** `comprehensive_zscaler_sample.csv`  
**Total Events:** 221  
**Time Range:** 2025-11-01 08:15:23 to 2025-11-02 17:02:22 (33 hours)  
**Users:** 11 (john.doe, jane.smith, bob.johnson, alice.williams, charlie.brown, david.miller, emily.davis, frank.wilson, grace.taylor, henry.anderson, isabel.thomas, suspicious.user, malicious.actor)

---

##  Purpose

This sample dataset is designed to trigger **ALL** anomaly detection methods and populate **ALL** visualizations in the CyberDucky Mini SIEM. It contains realistic threat scenarios for SOC analyst training and system demonstration.

---

##  Anomalies Triggered

### 1. Rule-Based Anomalies (7 Methods)

####  High-Risk Domain Access (Critical)
**Lines:** 9-13, 54-63  
**User:** john.doe  
**Details:**
- Multiple phishing site accesses (malicious-phishing-site.com, another-phishing.com, fake-login-page.com)
- C2 command server attempts (c2-command-server.onion) - 11 consecutive attempts
- Malware download attempt (suspicious-download.com)
- Spyware download (spyware-download.com)

**Expected Anomalies:** 15+ critical severity

####  Unusual Data Upload (High)
**Lines:** 14, 64, 111  
**Users:** jane.smith, grace.taylor  
**Details:**
- 50MB upload (company_database_backup.zip) - Line 14
- 150MB upload (confidential_financials.zip) - Line 64
- 100MB upload (source_code_backup.zip) - Line 111

**Expected Anomalies:** 3 high severity

####  Multiple Blocked Requests (Medium)
**Lines:** 9-13 (john.doe - 6 blocks), 54-63 (john.doe - 11 blocks), 139-150 (malicious.actor - 12 blocks)  
**Details:**
- john.doe: 17 total blocked requests (phishing + C2 + malware)
- malicious.actor: 12 blocked requests (brute force attempt)

**Expected Anomalies:** 2+ medium severity

####  Suspicious User Agent (Medium)
**Lines:** 54-63 (curl/7.68.0), 139-150 (python-requests/2.28.0)  
**Users:** john.doe, malicious.actor  
**Details:**
- john.doe using curl for C2 communication
- malicious.actor using python-requests for automated attacks

**Expected Anomalies:** 23+ medium severity (11 curl + 12 python-requests)

####  Off-Hours Activity (Low)
**Lines:** 100-114  
**Users:** All users  
**Details:**
- Activity between 18:00 - 06:00 (outside 9 AM - 6 PM)
- 15 events during off-hours
- Includes suspicious large upload by grace.taylor at 02:25 AM

**Expected Anomalies:** 15+ low severity

####  Rapid Successive Requests (Medium)
**Lines:** 66-79 (suspicious.user - 15 requests in 46 seconds)  
**Details:**
- suspicious.user making 15 requests to gmail.com in under 1 minute
- 3-second intervals between requests

**Expected Anomalies:** 1+ medium severity

####  Threat Category Detection (Critical)
**Lines:** 9-13 (Phishing), 54-63 (Botnet/C2), 13 (Malware), 201 (Spyware)  
**Users:** john.doe  
**Details:**
- Phishing: 6 events
- Botnet/C2: 11 events
- Malware: 1 event (Trojan Downloader)
- Spyware: 1 event (Keylogger)

**Expected Anomalies:** 19 critical severity

---

### 2. Statistical Anomalies (7 Methods)

####  Unusual Requests per IP (Critical/High/Medium)
**IP:** 10.0.0.50 (suspicious.user), 198.51.100.75 (malicious.actor), 192.168.1.100 (john.doe)  
**Details:**
- suspicious.user: 15 requests in 46 seconds (Z-score >> 3)
- malicious.actor: 12 requests in 33 seconds (Z-score >> 3)
- john.doe: 11 C2 requests in 10 minutes + 20 new domains in 20 minutes

**Expected Anomalies:** 3+ (critical/high severity based on Z-score)

####  User Risk Score Spike (High)
**Users:** john.doe, jane.smith, grace.taylor  
**Details:**
- john.doe: Risk jumps from 10-20 (normal) to 95-99 (phishing/malware)
- jane.smith: Risk jumps from 12-20 to 65 (large upload)
- grace.taylor: Risk jumps from 15-20 to 55 (off-hours large upload)

**Expected Anomalies:** 3+ high severity

####  Data Upload Anomaly (High)
**Lines:** 14, 64, 111  
**Details:**
- 50MB, 100MB, 150MB uploads (all in 99th percentile)
- Normal uploads are 1-4MB

**Expected Anomalies:** 3 high severity

####  New Domains Anomaly (Medium)
**User:** john.doe  
**Lines:** 161-180  
**Details:**
- Accessed 20 new domains in 20 minutes (newdomain1.com through newdomain20.com)
- Normal users access 0-2 new domains per day
- Mean + 3σ threshold exceeded

**Expected Anomalies:** 1 medium severity

####  Persistent High Risk (Critical)
**User:** john.doe  
**Lines:** 54-63  
**Details:**
- EWMA of risk score stays at 99 for 10 minutes (C2 beaconing)
- Threshold: EWMA > 80 for > 1 hour (this is 10 min, but high enough to flag)

**Expected Anomalies:** 1 critical severity

####  Burst of Blocked Requests (High)
**Users:** john.doe, malicious.actor  
**Details:**
- john.doe: 11 blocked requests in 10 minutes (C2 burst)
- malicious.actor: 12 blocked requests in 33 seconds (brute force burst)

**Expected Anomalies:** 2 high severity

####  Risk Trend Correlation (Medium)
**User:** john.doe  
**Details:**
- john.doe's risk trend diverges significantly from peer group (Engineering dept)
- Pearson correlation coefficient drops below threshold

**Expected Anomalies:** 1 medium severity

---

### 3. Cross-Source Anomalies (5 Methods)

####  Impossible Travel (Critical)
**User:** john.doe  
**Lines:** 125-127  
**Details:**
- Login from San Francisco (192.168.1.100) at 09:02:22
- Login from Tokyo (203.0.113.50) at 09:15:37 (13 minutes later)
- Distance: ~5,000 miles, Time: 13 minutes (impossible)

**Expected Anomalies:** 1 critical severity

####  Brute Force Detection (High)
**User:** malicious.actor  
**Lines:** 139-150  
**Details:**
- 12 failed login attempts (blocked requests) in 33 seconds
- Threshold: > 5 failed logins in 5 minutes

**Expected Anomalies:** 1 high severity

####  Data Exfiltration (Critical)
**Users:** jane.smith, grace.taylor  
**Lines:** 64, 111  
**Details:**
- jane.smith: 150MB upload to file-sharing-anonymous.com (external)
- grace.taylor: 100MB upload to drive.google.com at 02:25 AM (off-hours)

**Expected Anomalies:** 2 critical severity

####  Lateral Movement (High)
**Note:** Not explicitly triggered in this dataset (requires access to multiple internal IPs)  
**Workaround:** Can be simulated by adding events with multiple destination IPs in short time

**Expected Anomalies:** 0 (not in current dataset)

####  Privilege Escalation (Critical)
**Note:** Not explicitly triggered in this dataset (requires admin actions after normal user activity)  
**Workaround:** Can be simulated by adding admin actions for a user

**Expected Anomalies:** 0 (not in current dataset)

---

##  Visualizations Populated

### 1. Risk Score Trendline 
**Users:** All users, especially john.doe, jane.smith, grace.taylor  
**Data Points:** 221 events over 33 hours  
**Features:**
- Actual risk scores (10-99 range)
- Moving average (smoothed line)
- EWMA (exponentially weighted)
- Upper/lower control limits (±2σ bands)
- Visible spikes for john.doe (phishing, C2, malware)

### 2. Z-Score Heatmap 
**Dimensions:** 11 users × 33 hourly buckets  
**Metrics:** risk_score, upload_bytes, request_count  
**Features:**
- Dark red cells for john.doe during attack periods
- Moderate red for jane.smith, grace.taylor during uploads
- Light colors for normal users
- Time-based patterns visible (off-hours activity)

### 3. Boxplots per User 
**Users:** All 11 users  
**Metrics:** risk_score, upload_bytes, request_count  
**Features:**
- john.doe: Outliers at 95-99 (phishing, malware)
- jane.smith: Outlier at 65 (large upload)
- grace.taylor: Outlier at 55 (off-hours upload)
- Normal users: Tight distributions (10-25 range)

### 4. Anomaly Scatter Plot 
**Axes:** X=risk_score, Y=upload_bytes  
**Color:** Combined anomaly score  
**Features:**
- Upper-right outliers: jane.smith (65, 150MB), grace.taylor (55, 100MB)
- High-risk, low-upload: john.doe (95-99, 0 bytes) - phishing/malware
- Clusters of normal activity (10-25, 0-4MB)

### 5. Density Plot 
**Metrics:** risk_score distribution  
**Comparison:** Normal vs. john.doe  
**Features:**
- Normal distribution: Peak at 15-20, narrow spread
- john.doe distribution: Bimodal (normal 10-20, attack 95-99)
- KDE curves show clear separation

### 6. Control Chart 
**Metric:** risk_score over time  
**Features:**
- Center line (CL): ~18 (mean)
- Upper control limit (UCL): ~35 (mean + 2σ)
- Lower control limit (LCL): ~5 (mean - 2σ)
- Out-of-control points: john.doe (95-99), jane.smith (65), grace.taylor (55)

### 7. Timeline Analysis 
**Users:** All users, especially john.doe  
**Features:**
- Event timeline with anomaly markers
- john.doe: Phishing cluster (08:30-08:36), C2 cluster (14:35-14:45), new domains (11:55-12:14)
- jane.smith: Large upload at 14:52
- grace.taylor: Off-hours upload at 02:25
- malicious.actor: Brute force at 10:35

---

##  Investigation Scenarios

### Scenario 1: Compromised Account (john.doe)
**Timeline:**
1. **08:30-08:36** - Multiple phishing site accesses (6 blocked)
2. **14:35-14:45** - C2 beaconing attempts (11 blocked, curl user agent)
3. **11:55-12:14** - Reconnaissance (20 new domains accessed)
4. **09:15** - Impossible travel (San Francisco → Tokyo in 13 min)
5. **14:42** - Spyware download attempt (blocked)

**Indicators:**
- High-risk domain access
- Suspicious user agent (curl)
- Rapid successive requests
- Impossible travel
- Threat category detections (phishing, botnet, malware, spyware)

**Recommendation:** Immediate account lockout, password reset, endpoint forensics

### Scenario 2: Data Exfiltration (jane.smith)
**Timeline:**
1. **08:38** - 50MB upload (company_database_backup.zip)
2. **14:52** - 150MB upload (confidential_financials.zip) to file-sharing-anonymous.com

**Indicators:**
- Unusual data upload (99th percentile)
- Risk score spike (12 → 65)
- External file sharing site

**Recommendation:** Block domain, investigate user, review uploaded files

### Scenario 3: Insider Threat (grace.taylor)
**Timeline:**
1. **02:25 AM** - 100MB upload (source_code_backup.zip) during off-hours

**Indicators:**
- Off-hours activity
- Large upload (99th percentile)
- Risk score spike (15 → 55)

**Recommendation:** Interview user, review access logs, check for data loss

### Scenario 4: Brute Force Attack (malicious.actor)
**Timeline:**
1. **10:35** - 12 failed login attempts in 33 seconds (python-requests user agent)

**Indicators:**
- Rapid successive requests
- Suspicious user agent (automated)
- Multiple blocked requests
- External IP (Russia)

**Recommendation:** Block IP, enable rate limiting, alert security team

### Scenario 5: Reconnaissance (john.doe)
**Timeline:**
1. **11:55-12:14** - 20 new domains accessed in 20 minutes

**Indicators:**
- New domains anomaly (mean + 3σ exceeded)
- Risk score gradual increase (35 → 54)

**Recommendation:** Investigate domains, check for C2 infrastructure

---

##  Expected Metrics

### Anomaly Counts (Estimated)
- **Critical:** 35-40 (phishing, C2, malware, spyware, impossible travel, exfiltration)
- **High:** 10-15 (large uploads, brute force, bursts, risk spikes)
- **Medium:** 25-30 (suspicious UA, rapid requests, new domains, correlation)
- **Low:** 15-20 (off-hours activity)
- **Total:** 85-105 anomalies

### User Risk Profiles
- **john.doe:** High-risk (compromised account)
- **jane.smith:** Medium-risk (data exfiltration)
- **grace.taylor:** Medium-risk (insider threat)
- **malicious.actor:** Critical-risk (external attacker)
- **suspicious.user:** Medium-risk (automated activity)
- **Others:** Low-risk (normal activity)

### Visualization Data Points
- **Trendline:** 221 data points
- **Heatmap:** 11 users × 33 hours = 363 cells
- **Boxplots:** 11 users × 3 metrics = 33 plots
- **Scatter:** 221 points
- **Density:** 2 distributions (normal vs. anomalous)
- **Control Chart:** 221 points with 3 control limits
- **Timeline:** 221 events with 85-105 anomaly markers

---

##  How to Use

### 1. Upload the Sample Data
```bash
curl -X POST http://localhost:5000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@backend/sample_data/comprehensive_zscaler_sample.csv" \
  -F "log_type=zscaler"
```

### 2. Wait for Processing
- Parsing: ~5-10 seconds
- Anomaly detection: ~30-60 seconds
- LLM enrichment: ~2-5 minutes (for critical/high anomalies)

### 3. View Results
- **Dashboard:** http://localhost:5173
- **Anomalies:** `GET /api/anomalies/<log_file_id>`
- **Visualizations:** `GET /api/visualization/*`
- **LLM Analysis:** `POST /api/llm/investigation-report`

### 4. Explore Scenarios
- Filter by user: john.doe, jane.smith, grace.taylor
- Filter by severity: critical, high
- Filter by type: high_risk_domain, data_upload, impossible_travel
- View timeline for john.doe to see attack progression

---

##  Notes

- **Realistic Data:** All events use realistic timestamps, IPs, domains, and user agents
- **Diverse Threats:** Covers phishing, malware, C2, exfiltration, brute force, reconnaissance
- **Statistical Validity:** Sufficient data points for meaningful statistical analysis
- **Visualization Coverage:** Populates all 7 visualization types with interesting patterns
- **LLM-Ready:** High/critical anomalies will trigger AI analysis automatically

---

**Created:** 2025-11-01  
**Version:** 1.0  
**Total Events:** 221  
**Total Anomalies:** ~85-105 (estimated)

