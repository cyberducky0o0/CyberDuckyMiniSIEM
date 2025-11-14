# 📅 Weekly Zscaler Sample Log File

## Overview

**File:** `zscaler_weekly_sample.csv`  
**Size:** ~1.1 MB  
**Total Logs:** 3,613 entries  
**Date Range:** November 6-12, 2025 (7 days)  
**Format:** Zscaler NSS Web Logs (CSV)

---

## 📊 Dataset Characteristics

### Time Distribution
- **7 full days** of continuous logging
- **80% of logs** during business hours (8 AM - 6 PM, Mon-Fri)
- **20% of logs** outside business hours and weekends
- **~500 logs per day** baseline + anomaly patterns

### User Activity
- **10 users** across 5 departments:
  - Engineering (3 users)
  - Finance (2 users)
  - Sales (2 users)
  - IT (2 users)
  - HR (1 user)
  - Marketing (1 user)

### Activity Breakdown
- **75%** Normal browsing (Google, GitHub, Gmail, Slack, etc.)
- **10%** Cloud storage uploads (Drive, OneDrive, Dropbox, Box)
- **7%** Suspicious sites (torrents, proxies, VPNs)
- **8%** Malicious attempts (phishing, malware, C2, cryptomining)

### Risk Distribution
- **Blocked requests:** 343 (9.5%)
- **Upload activities:** 375 (10.4%)
- **High risk (≥70):** 413 (11.4%)

---

## 🚨 Embedded Anomaly Patterns

This sample file includes **4 realistic attack patterns** for testing anomaly detection:

### 1. **Data Exfiltration Attempt** 🔴
- **When:** Day 3 (Nov 8), 11:15 PM - 11:35 PM
- **Who:** john.doe (Engineering)
- **What:** 20 consecutive POST requests to data-exfil-server.com
- **Risk Score:** 97 (Critical)
- **Detection:** Unusual late-night activity, high-risk domain, repeated blocked attempts

### 2. **Phishing Campaign** 🎣
- **When:** Day 4 (Nov 9), 9:30 AM - 10:00 AM
- **Who:** Multiple users (organization-wide)
- **What:** 15 attempts to access malicious-phishing-site.com
- **Risk Score:** 95 (Critical)
- **Detection:** Burst of phishing attempts, multiple users affected

### 3. **Unusual Upload Volume** 📤
- **When:** Day 5 (Nov 10), 2:00 PM - 2:30 PM
- **Who:** jane.smith (Finance)
- **What:** 30 large file uploads to cloud storage (5-50 MB each)
- **Risk Score:** 25-30 (Medium)
- **Detection:** Abnormal upload frequency, large data volume

### 4. **C2 Beaconing** 🤖
- **When:** Day 6 (Nov 11), 8:00 AM - 8:00 PM (12 hours)
- **Who:** charlie.brown (IT)
- **What:** 48 POST requests to c2-command-server.org (every 15 minutes)
- **Risk Score:** 99 (Critical)
- **Detection:** Regular interval pattern, persistent blocked attempts, C2 domain

---

## 🎯 Use Cases

### For SOC Analysts
- **Time Series Analysis:** Visualize activity patterns over a full week
- **Anomaly Detection:** Test detection of the 4 embedded attack patterns
- **User Behavior Analytics:** Track individual user activity over time
- **Trend Analysis:** Identify daily/hourly patterns and deviations

### For Testing
- **Dashboard Widgets:** Test all time-based visualizations with realistic data
- **Anomaly Time Series:** Should show spikes on Days 3, 4, 5, and 6
- **Event Timeline:** Should display 7 days of activity with clear patterns
- **Risk Trendline:** Should show elevated risk during anomaly periods
- **Statistical Detection:** Test Z-score, EWMA, percentile, and burst detection

---

## 📈 Expected Detection Results

When this file is uploaded and analyzed, you should see:

### Anomalies Detected
- **~300-400 total anomalies** (depending on detection sensitivity)
- **Critical:** ~90-120 (phishing, C2, data exfiltration)
- **High:** ~150-200 (malware attempts, suspicious uploads)
- **Medium:** ~60-80 (unusual patterns, risky sites)

### Time Series Patterns
- **Day 1-2:** Baseline normal activity
- **Day 3:** Spike at 11 PM (data exfiltration)
- **Day 4:** Morning spike (phishing campaign)
- **Day 5:** Afternoon spike (unusual uploads)
- **Day 6:** Sustained elevation (C2 beaconing throughout day)
- **Day 7:** Return to baseline

### Top Threats
1. C2 Beaconing (48 attempts)
2. Data Exfiltration (20 attempts)
3. Phishing (15 attempts)
4. Malware Downloads
5. Cryptomining

---

## 🔧 How to Use

### Upload via UI
1. Navigate to **Upload** page
2. Select `zscaler_weekly_sample.csv`
3. Click **Upload**
4. Wait for processing (~30-60 seconds)
5. View **Analysis** page to see results

### Expected Processing Time
- **Parsing:** ~10-15 seconds (3,613 entries)
- **Anomaly Detection:** ~15-30 seconds
- **LLM Analysis:** ~10-20 seconds (if enabled)
- **Total:** ~35-65 seconds

---

## 📝 Notes

- All timestamps are in **2025-11-06 to 2025-11-12** range
- All IP addresses are **realistic but fictional**
- All usernames and domains are **fictional**
- Malicious domains are **fictional** (safe to use)
- File follows **Zscaler NSS Web Log format** (35 fields)

---

## 🎨 Visualization Highlights

This dataset is specifically designed to showcase:

✅ **Anomaly Time Series** - Clear spikes on Days 3, 4, 5, 6  
✅ **Event Timeline** - 7 days of hourly/daily buckets  
✅ **Risk Trendline** - EWMA showing risk elevation  
✅ **Requests Per Minute** - Burst detection patterns  
✅ **User Activity Heatmap** - Multi-user behavior  
✅ **Threat Distribution** - Diverse threat types  

---

**Generated by:** `backend/scripts/generate_weekly_sample.py`  
**Last Updated:** November 12, 2025

