# SOC Analyst Quick Reference Guide

## Overview

CyberDucky Mini SIEM is designed specifically for SOC analysts to quickly investigate security incidents from Zscaler web proxy logs.

## Quick Start

### 1. Upload Logs

1. Click **"Upload Logs"** in navigation
2. Select **"Zscaler NSS Web Logs"**
3. Choose your CSV file
4. Click **"Upload"**
5. Wait for processing (progress bar shows status)

### 2. View Overview Dashboard

1. Click **"Overview Dashboard"** in navigation
2. See aggregated metrics across **all** your log files:
   - Total log files
   - Total log entries
   - Total anomalies detected
   - Critical anomalies
   - Average risk score
   - High-risk entries
   - Unique users
   - Unique IPs
   - Threats detected

### 3. Investigate Threats

**Click on any metric or table row to drill down:**

- **Total Anomalies** → View all anomalies across all files
- **Threats Detected** → View all high-risk entries (risk ≥ 70)
- **Top Threats table row** → View all entries for that threat
- **Top Risky Users table row** → View all entries for that user
- **Top Risky IPs table row** → View all entries for that IP

## Key Features

### Unified Analysis

**Purpose:** Investigate a specific user, IP, or threat across **all** log files

**How to Access:**
- Click on any user in "Top Risky Users" table
- Click on any IP in "Top Risky IP Addresses" table
- Click on any threat in "Top Threats Detected" table
- Click on "Total Anomalies" or "Threats Detected" widgets

**What You See:**
- **Active Filters** - Shows what you're filtering by
- **Statistics** - Total entries, anomalies, high-risk count, avg risk
- **File Breakdown** - Which files contributed data
- **Anomalies Table** - All anomalies matching your filters
- **Log Entries Table** - Up to 100 most recent entries

**Example Workflow:**
```
1. See "john.doe" has high risk score in Top Risky Users
2. Click on "john.doe" row
3. View all of john.doe's activity across all files
4. See anomalies detected for john.doe
5. Investigate specific log entries
6. Determine if threat is real or false positive
```

### File Analysis

**Purpose:** Deep-dive into a single log file

**How to Access:**
- Click on a file in "Recent Log Files" table on Overview Dashboard
- Navigate to "Dashboard" and select a file

**What You See:**
- **File Information** - Filename, upload date, status, entry count
- **Statistics** - Anomalies, threats, risk scores
- **7 Visualizations:**
  1. Anomaly Time Series
  2. Risk Score Trendline
  3. Event Timeline
  4. Requests Per Minute
  5. Z-Score Heatmap
  6. Category Distribution
  7. Top Threats
- **Anomalies Table** - All anomalies in this file
- **Log Entries Table** - All entries in this file

### Advanced Analytics

**Purpose:** Statistical analysis and pattern detection

**Available on:** Overview Dashboard (bottom section)

**Visualizations:**
1. **Anomaly Trends Over Time** - Line chart showing anomaly counts by hour
2. **Risk Score Distribution** - Histogram of risk scores
3. **Top URL Categories** - Bar chart of most accessed categories
4. **User Activity Heatmap** - Activity patterns by user and time
5. **Threat Category Breakdown** - Pie chart of threat types

## Anomaly Types

### Critical Severity

| Type | Description | Recommended Action |
|------|-------------|-------------------|
| **Malware Detected** | Known malware signature | Isolate device, scan for infection |
| **C2 Beaconing** | Regular communication with C2 server | Block IP, investigate device |
| **Data Exfiltration** | Large upload to external destination | Block transfer, investigate data |

### High Severity

| Type | Description | Recommended Action |
|------|-------------|-------------------|
| **Phishing Attempt** | Access to phishing site | Block URL, notify user |
| **Suspicious Activity** | Unusual behavior pattern | Investigate further |
| **High Risk Access** | Access to high-risk category | Review and validate |

### Medium Severity

| Type | Description | Recommended Action |
|------|-------------|-------------------|
| **Rate Anomaly** | Unusual request rate | Monitor for escalation |
| **Risk Spike** | Sudden increase in risk score | Investigate cause |
| **Unusual Destination** | Access to uncommon destination | Validate business need |

### Low Severity

| Type | Description | Recommended Action |
|------|-------------|-------------------|
| **Minor Deviation** | Small statistical anomaly | Log for reference |
| **Informational** | FYI only | No action needed |

## Detection Methods

### Rule-Based Detection

**Fast, High Confidence**

- Malware signatures
- Known phishing domains
- Blocked categories
- Policy violations

**Indicators:**
- `detection_method: rule_based`
- `confidence: 0.85 - 0.95`

### Statistical Detection

**Medium Speed, Medium Confidence**

- Z-score analysis (outliers)
- EWMA (trend deviations)
- IQR (interquartile range)
- Correlation analysis

**Indicators:**
- `detection_method: statistical`
- `confidence: 0.60 - 0.80`

### AI-Powered Detection

**Slow, Context-Aware**

- LLM analysis (Ollama + phi3:mini)
- Natural language threat assessment
- Contextual risk scoring

**Indicators:**
- `detection_method: llm_based`
- `confidence: 0.50 - 0.90`

## Investigation Workflow

### 1. Triage

**Goal:** Identify high-priority threats

**Steps:**
1. Open Overview Dashboard
2. Check "Critical Anomalies" count
3. Review "Top Threats Detected" table
4. Sort by risk score (highest first)
5. Identify threats requiring immediate action

### 2. Investigation

**Goal:** Understand the threat

**Steps:**
1. Click on threat/user/IP to open Unified Analysis
2. Review statistics (how many entries, files involved)
3. Check file breakdown (which files have this activity)
4. Review anomalies table (what was detected)
5. Examine log entries (raw data)
6. Look for patterns (time, frequency, destinations)

### 3. Validation

**Goal:** Confirm if threat is real

**Questions to Ask:**
- Is this expected behavior for this user?
- Is the destination legitimate?
- Is the timing suspicious (after hours, weekend)?
- Are there multiple anomalies for same user/IP?
- What is the confidence score?
- What detection method was used?

### 4. Response

**Goal:** Take appropriate action

**Actions:**
- **Block** - Block IP/domain in firewall/proxy
- **Isolate** - Quarantine affected device
- **Notify** - Alert user or security team
- **Monitor** - Watch for escalation
- **Document** - Record findings in ticketing system

### 5. Follow-Up

**Goal:** Ensure threat is resolved

**Steps:**
1. Upload new logs after remediation
2. Check if anomalies persist
3. Monitor user/IP for recurrence
4. Update detection rules if needed

## Tips and Tricks

### Filtering

**Use Unified Analysis filters to narrow down:**
- `username=john.doe` - All activity for specific user
- `ip=192.168.1.100` - All activity from specific IP
- `threat_name=Malware.Generic` - All instances of specific threat
- `min_risk=70` - Only high-risk entries (≥70)

### Sorting

**Click column headers to sort:**
- Risk Score (highest first)
- Timestamp (most recent first)
- Count (most frequent first)

### Time Ranges

**Focus on specific time periods:**
- Recent Activity (last 24 hours)
- Business Hours (9 AM - 5 PM)
- After Hours (5 PM - 9 AM)
- Weekends

### Pattern Recognition

**Look for:**
- **Beaconing** - Regular intervals (every 5 min, 10 min, etc.)
- **Bursts** - Sudden spike in activity
- **Persistence** - Same threat across multiple files/days
- **Lateral Movement** - Same user accessing many IPs
- **Data Staging** - Large downloads followed by large uploads

## Common Scenarios

### Scenario 1: Malware Alert

**Alert:** "Malware.Generic detected for user john.doe"

**Investigation:**
1. Click on "john.doe" in Top Risky Users
2. Check how many malware detections
3. Review URLs accessed
4. Check if malware was blocked or allowed
5. Determine if device is infected

**Action:**
- If blocked: Monitor user
- If allowed: Isolate device, run antivirus scan

### Scenario 2: Data Exfiltration

**Alert:** "Large upload detected: 500 MB to external IP"

**Investigation:**
1. Click on the IP in Top Risky IPs
2. Check what was uploaded (file types)
3. Review user who uploaded
4. Check if destination is known/approved
5. Determine if data is sensitive

**Action:**
- Block IP if malicious
- Investigate user if insider threat
- Review DLP policies

### Scenario 3: Phishing

**Alert:** "Phishing site accessed by multiple users"

**Investigation:**
1. Click on threat in Top Threats
2. See which users accessed the site
3. Check if credentials were entered
4. Determine if campaign is targeted

**Action:**
- Block phishing domain
- Notify affected users
- Force password resets if needed
- Security awareness training

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + K` | Search |
| `Esc` | Close modal |
| `←` | Back button |
| `Ctrl + R` | Refresh data |

## Support

For questions or issues, refer to:
- **README.md** - Project overview
- **documentation/architecture/** - System design
- **documentation/guides/** - Detailed guides


