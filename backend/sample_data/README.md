#  Sample Data for CyberDucky Mini SIEM

This directory contains comprehensive sample Zscaler NSS Web Logs designed to demonstrate all features of the CyberDucky Mini SIEM.

---

##  Files

### `comprehensive_zscaler_sample.csv`
**Purpose:** Complete sample dataset with realistic threat scenarios  
**Events:** 221 log entries  
**Time Range:** 33 hours (2025-11-01 to 2025-11-02)  
**Users:** 11 users with various activity patterns  
**Anomalies:** ~85-105 expected anomalies across all severity levels

**Triggers:**
-  All 7 rule-based detection methods
-  All 7 statistical detection methods
-  3 of 5 cross-source detection methods
-  All 7 visualization types
-  LLM analysis for critical/high anomalies

### `SAMPLE_DATA_GUIDE.md`
**Purpose:** Detailed documentation of sample data  
**Contents:**
- Anomaly breakdown by type and severity
- User scenarios (compromised account, data exfiltration, insider threat, brute force)
- Expected metrics and visualization data
- Investigation workflows
- Usage instructions

---

##  Quick Start

### Option 1: Automated Upload (Recommended)

```bash
# From project root
python backend/scripts/upload_sample_data.py
```

This script will:
1. Register/login user (admin/admin)
2. Upload the sample CSV file
3. Wait for anomaly detection
4. Check LLM service status
5. Display summary and next steps

### Option 2: Manual Upload via API

```bash
# 1. Register user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# 2. Login and get token
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}' \
  | jq -r '.access_token')

# 3. Upload file
curl -X POST http://localhost:5000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@backend/sample_data/comprehensive_zscaler_sample.csv" \
  -F "log_type=zscaler"
```

### Option 3: Frontend Upload

1. Open http://localhost:5173
2. Login with admin/admin
3. Navigate to Upload page
4. Select `comprehensive_zscaler_sample.csv`
5. Choose "Zscaler" as log type
6. Click Upload

---

##  What You'll See

### Anomalies Detected

| Severity | Count | Examples |
|----------|-------|----------|
| **Critical** | 35-40 | Phishing, C2 communication, malware, impossible travel |
| **High** | 10-15 | Large uploads, brute force, risk spikes |
| **Medium** | 25-30 | Suspicious user agents, rapid requests, new domains |
| **Low** | 15-20 | Off-hours activity |
| **Total** | **85-105** | All detection methods triggered |

### Visualizations Populated

1. **Risk Score Trendline** - Shows spikes for john.doe during attacks
2. **Z-Score Heatmap** - Dark red cells for anomalous users/times
3. **Boxplots per User** - Outliers visible for john.doe, jane.smith, grace.taylor
4. **Anomaly Scatter Plot** - Upper-right outliers for high-risk + large uploads
5. **Density Plot** - Bimodal distribution for john.doe (normal + attack)
6. **Control Chart** - Out-of-control points for critical anomalies
7. **Timeline Analysis** - Attack progression visible for john.doe

### LLM Analysis

High and critical anomalies will automatically receive AI-powered explanations:
- Plain English descriptions
- Actionable recommendations
- Urgency levels
- Next steps for investigation

---

##  User Scenarios

### 1. john.doe (Compromised Account) - **HIGH RISK**
**Activity:**
- Multiple phishing site accesses
- C2 beaconing attempts (curl user agent)
- Reconnaissance (20 new domains)
- Impossible travel (SF → Tokyo in 13 min)
- Malware/spyware download attempts

**Anomalies:** 40+ (critical/high)

### 2. jane.smith (Data Exfiltration) - **MEDIUM RISK**
**Activity:**
- 50MB upload (company_database_backup.zip)
- 150MB upload to file-sharing site (confidential_financials.zip)

**Anomalies:** 2-3 (high)

### 3. grace.taylor (Insider Threat) - **MEDIUM RISK**
**Activity:**
- 100MB upload at 2:25 AM (off-hours)
- Source code backup to cloud storage

**Anomalies:** 2-3 (high/medium)

### 4. malicious.actor (External Attacker) - **CRITICAL RISK**
**Activity:**
- 12 failed login attempts in 33 seconds
- Python-requests user agent (automated)
- External IP from Russia

**Anomalies:** 12+ (critical/medium)

### 5. suspicious.user (Bot Activity) - **MEDIUM RISK**
**Activity:**
- 15 requests in 46 seconds
- Rapid successive requests to gmail.com

**Anomalies:** 1-2 (medium)

### 6. Others (Normal Users) - **LOW RISK**
**Activity:**
- Regular business applications
- Normal risk scores (10-25)
- Occasional off-hours activity

**Anomalies:** 15-20 (low - off-hours only)

---

##  Expected Metrics

### Detection Coverage
- **Rule-Based:** 7/7 methods triggered 
- **Statistical:** 7/7 methods triggered 
- **Cross-Source:** 3/5 methods triggered 
- **LLM Analysis:** Automatic for critical/high 

### Data Distribution
- **Normal Events:** ~130 (59%)
- **Suspicious Events:** ~50 (23%)
- **Malicious Events:** ~40 (18%)

### Time Distribution
- **Business Hours (9 AM - 6 PM):** ~190 events (86%)
- **Off-Hours:** ~30 events (14%)

### User Distribution
- **High-Risk Users:** 2 (john.doe, malicious.actor)
- **Medium-Risk Users:** 3 (jane.smith, grace.taylor, suspicious.user)
- **Low-Risk Users:** 6 (normal activity)

---

##  Investigation Workflows

### Workflow 1: Investigate Compromised Account
```bash
# 1. Get file ID from upload response
FILE_ID="<your-file-id>"

# 2. Filter anomalies for john.doe
curl -X GET "http://localhost:5000/api/logs/$FILE_ID/filter?user=john.doe" \
  -H "Authorization: Bearer $TOKEN"

# 3. View timeline
curl -X GET "http://localhost:5000/api/visualization/timeline/$FILE_ID?user=john.doe" \
  -H "Authorization: Bearer $TOKEN"

# 4. Generate investigation report
curl -X POST "http://localhost:5000/api/llm/investigation-report" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"log_file_id\": \"$FILE_ID\", \"user\": \"john.doe\"}"
```

### Workflow 2: Investigate Data Exfiltration
```bash
# 1. Filter large uploads
curl -X GET "http://localhost:5000/api/anomalies/$FILE_ID/type/data_upload" \
  -H "Authorization: Bearer $TOKEN"

# 2. View scatter plot (risk vs. upload size)
curl -X GET "http://localhost:5000/api/visualization/anomaly-scatter/$FILE_ID" \
  -H "Authorization: Bearer $TOKEN"

# 3. Correlate by user
curl -X POST "http://localhost:5000/api/analysis/correlate/user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"jane.smith\"}"
```

### Workflow 3: Threat Hunting
```bash
# 1. View heatmap to identify patterns
curl -X GET "http://localhost:5000/api/visualization/z-score-heatmap/$FILE_ID?metric=risk_score" \
  -H "Authorization: Bearer $TOKEN"

# 2. Detect attack patterns
curl -X POST "http://localhost:5000/api/llm/detect-pattern/$FILE_ID" \
  -H "Authorization: Bearer $TOKEN"

# 3. Filter critical anomalies
curl -X GET "http://localhost:5000/api/anomalies/$FILE_ID/severity/critical" \
  -H "Authorization: Bearer $TOKEN"
```

---

##  Documentation

- **SAMPLE_DATA_GUIDE.md** - Detailed breakdown of sample data
- **COMPLETE_FEATURE_SUMMARY.md** - Full system feature list
- **SOC_ANALYST_QUICK_REFERENCE.md** - Quick reference for analysts
- **ARCHITECTURE.md** - System architecture overview
- **STATISTICAL_ANOMALY_DETECTION.md** - Statistical methods explained

---

##  Troubleshooting

### Upload Fails
- Check backend is running: `docker-compose ps`
- Check logs: `docker-compose logs backend --tail=50`
- Verify file exists: `ls -lh backend/sample_data/comprehensive_zscaler_sample.csv`

### No Anomalies Detected
- Wait 30-60 seconds for processing
- Check anomaly service logs
- Verify detection thresholds in config

### LLM Not Working
- Check Ollama status: `curl http://localhost:11434/api/tags`
- Verify model downloaded: `docker exec cyberducky_ollama ollama list`
- Check LLM service: `curl http://localhost:5000/api/llm/status -H "Authorization: Bearer $TOKEN"`

### Visualizations Empty
- Ensure anomalies are detected first
- Check file_id is correct
- Verify sufficient data points (need > 10 events)

---

##  Learning Objectives

After uploading and analyzing this sample data, you should be able to:

1.  Identify compromised accounts using multiple indicators
2.  Detect data exfiltration patterns
3.  Recognize insider threat behaviors
4.  Investigate brute force attacks
5.  Use visualizations for threat hunting
6.  Leverage AI for anomaly explanation
7.  Generate investigation reports
8.  Correlate events across multiple dimensions

---

**Created:** 2025-11-01  
**Version:** 1.0  
**Maintained by:** CyberDucky Team

