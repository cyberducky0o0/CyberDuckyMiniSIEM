# Anomaly Detection Guide

## Overview

CyberDucky Mini SIEM uses a **multi-method approach** to anomaly detection, combining rule-based, statistical, and AI-powered techniques.

## Detection Pipeline

```
Log Entry
    ↓
Rule-Based Detection (Fast, High Confidence)
    ↓
Statistical Analysis (Medium Speed, Medium Confidence)
    ↓
LLM Analysis (Slow, Context-Aware)
    ↓
Anomaly Record Created
```

## 1. Rule-Based Detection

### Malware Detection

**Indicators:**
- Threat name contains: malware, virus, trojan, ransomware, worm, backdoor, rootkit
- URL category: Malware Sites, Botnet, Malicious Sites
- Risk score > 80

**Implementation:**
```python
def detect_malware(entry: LogEntry) -> Optional[Anomaly]:
    malware_indicators = ['malware', 'virus', 'trojan', 'ransomware', 'worm', 'backdoor']
    
    if entry.threat_name:
        threat_lower = entry.threat_name.lower()
        if any(indicator in threat_lower for indicator in malware_indicators):
            return Anomaly(
                type='malware_detected',
                severity='critical',
                confidence=0.95,
                description=f"Malware detected: {entry.threat_name}",
                detection_method='rule_based'
            )
    
    return None
```

### Phishing Detection

**Indicators:**
- URL category: Phishing, Suspicious, Newly Registered Domains
- Threat name contains: phishing, credential, fake login
- URL contains: login, signin, verify, account, update

**Implementation:**
```python
def detect_phishing(entry: LogEntry) -> Optional[Anomaly]:
    phishing_categories = ['Phishing', 'Suspicious', 'Newly Registered Domains']
    phishing_keywords = ['phishing', 'credential', 'fake login']
    
    if entry.url_category in phishing_categories:
        return Anomaly(
            type='phishing_attempt',
            severity='high',
            confidence=0.90,
            description=f"Phishing site accessed: {entry.url}",
            detection_method='rule_based'
        )
    
    return None
```

### C2 Beaconing Detection

**Indicators:**
- Regular time intervals (low standard deviation)
- Same destination IP/domain
- Small, consistent payload sizes
- High frequency (> 10 requests in short time)

**Implementation:**
```python
def detect_c2_beaconing(entries: List[LogEntry]) -> List[Anomaly]:
    # Group by destination IP
    by_dest = defaultdict(list)
    for entry in entries:
        by_dest[entry.destination_ip].append(entry)
    
    anomalies = []
    for dest_ip, dest_entries in by_dest.items():
        if len(dest_entries) < 10:
            continue
        
        # Calculate time intervals
        timestamps = sorted([e.timestamp for e in dest_entries])
        intervals = [(t2 - t1).total_seconds() for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
        
        avg_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        # Regular pattern = beaconing
        if std_interval < 5 and avg_interval < 300:  # < 5 min intervals
            anomalies.append(Anomaly(
                type='c2_beaconing',
                severity='critical',
                confidence=0.85,
                description=f"C2 beaconing detected to {dest_ip} (avg interval: {avg_interval:.1f}s)",
                detection_method='rule_based'
            ))
    
    return anomalies
```

### Data Exfiltration Detection

**Indicators:**
- Large upload size (> 100 MB)
- External destination
- Unusual file types (.zip, .rar, .7z, .db, .sql)
- After-hours activity

**Implementation:**
```python
def detect_data_exfiltration(entry: LogEntry) -> Optional[Anomaly]:
    # Large upload
    if entry.bytes_sent > 100_000_000:  # 100 MB
        # Check if external destination
        if not is_internal_ip(entry.destination_ip):
            return Anomaly(
                type='data_exfiltration',
                severity='critical',
                confidence=0.80,
                description=f"Large upload detected: {entry.bytes_sent / 1_000_000:.1f} MB to {entry.destination_ip}",
                detection_method='rule_based'
            )
    
    return None
```

## 2. Statistical Detection

CyberDucky Mini SIEM uses **4 core statistical methods** for anomaly detection:

### 1. Z-Score Analysis

**Purpose:** Detect outliers in numerical data using the 3-sigma rule

**Formula:**
```
z = (x - μ) / σ

where:
  x = observed value
  μ = mean
  σ = standard deviation
```

**Threshold:** |z| > 3.0 (99.7% confidence)

**Implementation:**
```python
def detect_zscore_anomalies(data: List[float], threshold: float = 3.0) -> List[int]:
    """
    Detect anomalies using Z-score method

    Args:
        data: List of numerical values
        threshold: Z-score threshold (default: 3.0)

    Returns:
        List of indices where anomalies detected
    """
    mean = np.mean(data)
    std = np.std(data)

    if std == 0:
        return []

    z_scores = [(x - mean) / std for x in data]

    anomaly_indices = [
        i for i, z in enumerate(z_scores)
        if abs(z) > threshold
    ]

    return anomaly_indices
```

**Use Cases:**
- Unusual request rates (user making 100 requests/min when average is 10)
- Abnormal risk scores
- Outlier detection in any metric

**Example:**
```python
# User requests per minute
user_rpm = [10, 12, 11, 9, 10, 11, 12, 10, 11, 150]
mean = 20.6
std_dev = 41.8
z_score_for_150 = (150 - 20.6) / 41.8 = 3.09  # ANOMALY!
```

---

### 2. Percentile-Based Detection

**Purpose:** Identify extreme values in the top or bottom percentiles

**Formula:**
```
threshold = percentile(data, 99)
if value > threshold: anomaly detected
```

**Threshold:** 99th percentile (top 1%)

**Implementation:**
```python
def detect_percentile_anomalies(data: List[float], percentile: int = 99) -> List[int]:
    """
    Detect anomalies using percentile-based method

    Args:
        data: List of numerical values
        percentile: Percentile threshold (default: 99)

    Returns:
        List of anomaly indices
    """
    threshold = np.percentile(data, percentile)

    anomalies = [
        i for i, value in enumerate(data)
        if value > threshold
    ]

    return anomalies
```

**Use Cases:**
- Data exfiltration (top 1% of upload sizes)
- Large downloads
- Extreme risk scores

**Example:**
```python
# Upload sizes in bytes
upload_sizes = [1000, 2000, 1500, 3000, 2500, 50000000]
threshold_99th = 49,505,000  # 99th percentile
# 50MB upload exceeds threshold → ANOMALY!
```

---

### 3. EWMA (Exponentially Weighted Moving Average)

**Purpose:** Detect deviations from expected trends by giving more weight to recent values

**Formula:**
```
EWMA_t = α × X_t + (1 - α) × EWMA_{t-1}

where:
  α = smoothing factor (0.3 typical)
  X_t = current value
  EWMA_{t-1} = previous EWMA
```

**Implementation:**
```python
def detect_ewma_anomalies(data: List[float], alpha: float = 0.3, threshold: float = 2.0) -> List[int]:
    """
    Detect anomalies using EWMA method

    Args:
        data: Time series data
        alpha: Smoothing factor (0-1)
        threshold: Number of standard deviations

    Returns:
        List of anomaly indices
    """
    if len(data) < 2:
        return []

    ewma = data[0]
    anomalies = []

    for i, value in enumerate(data[1:], 1):
        # Calculate deviation
        deviation = abs(value - ewma)
        std = np.std(data[:i])

        if std > 0 and deviation > threshold * std:
            anomalies.append(i)

        # Update EWMA
        ewma = alpha * value + (1 - alpha) * ewma

    return anomalies
```

**Use Cases:**
- Persistent high risk (user's risk score trending upward)
- Gradual behavior changes
- Slow attacks that build over time

**Example:**
```python
# User risk scores over time
risk_scores = [10, 12, 15, 18, 22, 70]  # Gradual increase then spike
alpha = 0.3

ewma = 10
for score in [12, 15, 18, 22, 70]:
    ewma = 0.3 * score + 0.7 * ewma

# At score=70: deviation = |70 - 32.26| = 37.74 → ANOMALY!
```

---

### 4. Burst Detection (Rolling Statistics)

**Purpose:** Detect sudden spikes in activity using sliding window analysis

**Formula:**
```
window_mean = mean(values[i-window:i])
window_std = std(values[i-window:i])
z_score = (current_value - window_mean) / window_std

if z_score > threshold_sigma: burst detected
```

**Parameters:**
- Window size: 10 (default)
- Threshold sigma: 2.0 (default)

**Implementation:**
```python
def detect_burst(data: List[float], window: int = 10, threshold_sigma: float = 2.0) -> List[int]:
    """
    Detect bursts using rolling window statistics

    Args:
        data: Time series data
        window: Window size for rolling statistics
        threshold_sigma: Z-score threshold

    Returns:
        List of burst indices
    """
    anomalies = []

    for i in range(window, len(data)):
        window_data = data[i-window:i]
        window_mean = np.mean(window_data)
        window_std = np.std(window_data)

        if window_std == 0:
            continue

        z_score = (data[i] - window_mean) / window_std

        if z_score > threshold_sigma:
            anomalies.append(i)

    return anomalies
```

**Use Cases:**
- DDoS attacks (sudden spike in requests)
- Brute force attempts (rapid failed logins)
- Port scanning (burst of connections)
- Blocked request spikes

**Example:**
```python
# Blocked requests per minute
blocked_per_minute = [2, 3, 2, 1, 3, 2, 45, 3, 2]
window_size = 5

# At index 6 (value=45):
window = [2, 3, 2, 1, 3]  # Previous 5 values
window_mean = 2.2
window_std = 0.75
z_score = (45 - 2.2) / 0.75 = 57.07  # BURST DETECTED!
```

---

## 3. LLM-Based Detection

**Purpose:** Context-aware analysis of high-severity anomalies using local LLM

**Model:** Ollama + phi3:mini (local inference)

**When Used:**
- High-severity anomalies (critical/high)
- Complex patterns requiring context
- Ambiguous cases needing human-like reasoning

**Implementation:**
```python
def analyze_with_llm(anomaly: Anomaly, log_entry: LogEntry) -> str:
    """
    Analyze anomaly using local LLM

    Args:
        anomaly: Detected anomaly
        log_entry: Associated log entry

    Returns:
        LLM analysis text
    """
    prompt = f"""
    Analyze this security anomaly:

    User: {log_entry.username}
    IP: {log_entry.source_ip}
    Anomaly Type: {anomaly.anomaly_type}
    Risk Score: {log_entry.risk_score}
    URL: {log_entry.url}
    Threat: {log_entry.threat_name}
    Action: {log_entry.action}
    Timestamp: {log_entry.timestamp}

    Provide:
    1. Threat assessment (1-2 sentences)
    2. Recommended actions (3-5 bullet points)
    3. Urgency level (LOW/MEDIUM/HIGH/CRITICAL)
    """

    response = ollama.generate(
        model='phi3:mini',
        prompt=prompt,
        temperature=0.3  # Low temperature for consistent output
    )

    return response['response']
```

**Example Output:**
```
Threat Assessment: User john.doe accessed a known phishing site and
attempted to download malware. This is a critical security incident
indicating potential credential compromise.

Recommended Actions:
1. Immediately isolate the user's device from the network
2. Force password reset for john.doe
3. Scan device for malware using EDR tools
4. Review user's recent activity for signs of compromise
5. Contact user to verify legitimacy of activity

Urgency: CRITICAL - Respond within 15 minutes
```

**Benefits:**
- **Context-aware:** Understands relationships between fields
- **Natural language:** Easy for SOC analysts to read
- **Actionable:** Provides specific recommendations
- **Private:** Data never leaves your infrastructure

---

## Detection Method Comparison

| Method | Speed | Accuracy | Use Case | Confidence |
|--------|-------|----------|----------|------------|
| **Rule-Based** | ⚡⚡⚡ Fast | ⭐⭐⭐⭐⭐ High | Known threats | 90-95% |
| **Z-Score** | ⚡⚡ Medium | ⭐⭐⭐⭐ Good | Outliers | 70-85% |
| **Percentile** | ⚡⚡ Medium | ⭐⭐⭐⭐ Good | Extreme values | 75-85% |
| **EWMA** | ⚡⚡ Medium | ⭐⭐⭐ Medium | Trends | 65-80% |
| **Burst** | ⚡⚡ Medium | ⭐⭐⭐⭐ Good | Spikes | 70-85% |
| **LLM** | ⚡ Slow | ⭐⭐⭐⭐ Good | Context | 60-75% |

---

## Anomaly Severity Levels

### Critical (Risk Score: 90-100)
- Malware detected
- C2 beaconing
- Active data exfiltration
- Ransomware activity

**Response Time:** < 15 minutes

### High (Risk Score: 70-89)
- Phishing attempts
- Large data uploads
- Suspicious domain access
- Multiple blocked requests

**Response Time:** < 1 hour

### Medium (Risk Score: 50-69)
- Unusual request patterns
- New domain access
- Moderate risk score spikes
- Policy violations

**Response Time:** < 4 hours

### Low (Risk Score: < 50)
- Minor deviations
- Informational alerts
- Baseline establishment
- Trend monitoring

**Response Time:** < 24 hours

---

## Best Practices

### For SOC Analysts

1. **Prioritize by Severity**
   - Start with Critical anomalies
   - Use filters to focus on high-risk items

2. **Investigate Context**
   - Click on users/IPs/threats for unified analysis
   - Review all related log entries
   - Check historical patterns

3. **Correlate Anomalies**
   - Look for multiple anomalies from same user/IP
   - Identify attack chains
   - Check temporal patterns

4. **Use LLM Analysis**
   - Read LLM recommendations for complex cases
   - Validate LLM suggestions with log data
   - Document findings

### For System Administrators

1. **Tune Thresholds**
   - Adjust Z-score threshold (default: 3.0)
   - Modify percentile cutoff (default: 99th)
   - Configure EWMA alpha (default: 0.3)
   - Set burst window size (default: 10)

2. **Monitor Performance**
   - Check detection rates
   - Review false positive rates
   - Optimize LLM usage

3. **Update Rules**
   - Add new threat indicators
   - Refine existing rules
   - Remove obsolete patterns

---

## Configuration

**Backend Configuration (`backend/app/config.py`):**

```python
# Statistical Detection Thresholds
ZSCORE_THRESHOLD = 3.0
PERCENTILE_THRESHOLD = 99
EWMA_ALPHA = 0.3
EWMA_THRESHOLD = 2.0
BURST_WINDOW = 10
BURST_THRESHOLD_SIGMA = 2.0

# LLM Configuration
LLM_ENABLED = True
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "phi3:mini"
LLM_TEMPERATURE = 0.3
LLM_MAX_TOKENS = 500

# Anomaly Detection
MIN_ENTRIES_FOR_STATISTICAL = 10  # Minimum entries needed for statistical analysis
ENABLE_LLM_FOR_SEVERITY = ['critical', 'high']  # Only use LLM for these severities
```

---

## Troubleshooting

### High False Positive Rate

**Problem:** Too many anomalies detected

**Solutions:**
1. Increase Z-score threshold (3.0 → 3.5)
2. Increase percentile threshold (99 → 99.5)
3. Increase EWMA threshold (2.0 → 2.5)
4. Increase burst threshold sigma (2.0 → 2.5)

### Missing Anomalies

**Problem:** Known threats not detected

**Solutions:**
1. Decrease Z-score threshold (3.0 → 2.5)
2. Add more rule-based detections
3. Review log data quality
4. Check parser field mappings

### LLM Not Working

**Problem:** No LLM analysis appearing

**Solutions:**
1. Check Ollama is running: `ollama serve`
2. Verify model is pulled: `ollama pull phi3:mini`
3. Check LLM_ENABLED = True in config
4. Review backend logs for errors

---

## Summary

CyberDucky Mini SIEM uses **4 core statistical methods** for robust anomaly detection:

1. **Z-Score Analysis** - Outlier detection (3-sigma rule)
2. **Percentile-Based** - Top 1% threshold for extreme values
3. **EWMA** - Trend deviation detection
4. **Burst Detection** - Sudden spike identification

Combined with **rule-based detection** for known threats and **LLM analysis** for context-aware insights, this provides comprehensive security monitoring for SOC analysts.

For more information, see:
- [SOC Analyst Guide](SOC_ANALYST_GUIDE.md)
- [System Architecture](../architecture/SYSTEM_ARCHITECTURE.md)
- [Parser Guide](PARSER_GUIDE.md)
