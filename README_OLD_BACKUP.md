# CyberDucky Mini SIEM 🦆🔒

**A SOC Analyst-Focused Security Information and Event Management System**

CyberDucky Mini SIEM is a full-stack web application designed specifically for Security Operations Center (SOC) analysts to analyze Zscaler NSS Web Logs with advanced threat detection, anomaly analysis, and AI-powered insights.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Architecture](#architecture)
4. [Technology Stack](#technology-stack)
5. [Quick Start](#quick-start)
6. [How It Works](#how-it-works)
7. [Design Decisions](#design-decisions)
8. [Parser Architecture](#parser-architecture)
9. [Anomaly Detection](#anomaly-detection)
10. [API Reference](#api-reference)
11. [Development](#development)
12. [Documentation](#documentation)

---

## 🎯 Overview

CyberDucky Mini SIEM provides SOC analysts with a powerful platform to:

- **Upload and parse** Zscaler NSS Web Logs (CSV format)
- **Detect threats** using multiple detection methods (rule-based, statistical, AI-powered)
- **Analyze anomalies** with 7 statistical detection algorithms
- **Visualize data** with 7+ interactive chart types
- **Investigate incidents** with unified analysis across all log files
- **Track metrics** with real-time dashboards and risk scoring

### Target Users

- **SOC Analysts** - Primary users who need to investigate security incidents
- **Security Engineers** - Configure detection rules and thresholds
- **Incident Responders** - Investigate and respond to threats

---

## ✨ Key Features

### 🔍 Multi-Method Threat Detection

1. **Rule-Based Detection**
   - Malware detection (malware, virus, trojan, ransomware)
   - Phishing detection (phishing, credential harvesting)
   - C2 beaconing detection (command-and-control patterns)
   - Data exfiltration detection (large uploads, suspicious file transfers)

2. **Statistical Anomaly Detection** (7 Methods)
   - Z-Score Analysis (rate anomalies)
   - EWMA (Exponentially Weighted Moving Average)
   - Percentile-Based Detection
   - IQR (Interquartile Range) Outlier Detection
   - Pearson Correlation Analysis
   - KDE (Kernel Density Estimation)
   - Rolling Statistics with Burst Detection

3. **AI-Powered Analysis**
   - Local LLM integration (Ollama with phi3:mini)
   - Context-aware threat assessment
   - Natural language threat descriptions
   - Confidence scoring

### 📊 Advanced Visualizations

- **Anomaly Time Series** - Track anomalies over time
- **Risk Score Trendline** - Monitor risk trends
- **Event Timeline** - Chronological event visualization
- **Requests Per Minute** - Traffic pattern analysis
- **Z-Score Heatmap** - Multi-dimensional anomaly view
- **Category Distribution** - URL category breakdown
- **Top Threats** - Most frequent threats

### 🎛️ SOC Analyst Dashboard

- **Overview Dashboard** - Aggregated metrics across all log files
  - Total log files, entries, anomalies, threats
  - Top risky users, IPs, and threats
  - Anomaly trends over time
  - Advanced analytics section
  
- **Unified Analysis** - Drill-down investigation
  - Filter by username, IP, threat name, category, risk score
  - View all matching entries across all files
  - File breakdown showing data sources
  - Anomaly and log entry tables

- **File Analysis** - Individual file deep-dive
  - File-specific metrics and statistics
  - All visualizations for single file
  - Export capabilities

### 🔐 Security Features

- **JWT Authentication** - Secure token-based auth
- **User Isolation** - Each user sees only their own data
- **Password Hashing** - Werkzeug secure password storage
- **CORS Protection** - Configured cross-origin policies
- **SQL Injection Prevention** - SQLAlchemy ORM with parameterized queries

---

## 🏗️ Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Frontend                             │
│  React + TypeScript + TailwindCSS + Recharts                │
│  - Overview Dashboard                                        │
│  - Unified Analysis                                          │
│  - File Analysis                                             │
│  - Upload Interface                                          │
└────────────────────┬────────────────────────────────────────┘
                     │ REST API (JSON)
                     │ JWT Authentication
┌────────────────────▼────────────────────────────────────────┐
│                      Backend (Flask)                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Controllers (API Endpoints)                         │  │
│  │  - Auth, Dashboard, Analysis, Upload, Visualization  │  │
│  └────────────┬─────────────────────────────────────────┘  │
│               │                                              │
│  ┌────────────▼─────────────────────────────────────────┐  │
│  │  Services (Business Logic)                           │  │
│  │  - Log Processing, Anomaly Detection, Enrichment     │  │
│  └────────────┬─────────────────────────────────────────┘  │
│               │                                              │
│  ┌────────────▼─────────────────────────────────────────┐  │
│  │  Parsers (Log Ingestion)                             │  │
│  │  - Zscaler Parser, Base Parser, Parser Factory       │  │
│  └────────────┬─────────────────────────────────────────┘  │
│               │                                              │
│  ┌────────────▼─────────────────────────────────────────┐  │
│  │  Repositories (Data Access)                          │  │
│  │  - User, LogFile, LogEntry, Anomaly Repos            │  │
│  └────────────┬─────────────────────────────────────────┘  │
└───────────────┼──────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────┐
│              PostgreSQL Database                              │
│  - users, log_files, log_entries, anomalies                  │
└───────────────────────────────────────────────────────────────┘
```

### Design Patterns

1. **MVC (Model-View-Controller)**
   - **Models**: SQLAlchemy ORM models (`User`, `LogFile`, `LogEntry`, `Anomaly`)
   - **Views**: React components (Dashboard, Analysis, Upload)
   - **Controllers**: Flask blueprints (auth, dashboard, analysis, upload)

2. **Repository Pattern**
   - Abstracts data access layer
   - Each model has a repository (`UserRepository`, `LogFileRepository`, etc.)
   - Provides clean interface for CRUD operations

3. **Service Layer Pattern**
   - Business logic separated from controllers
   - `LogProcessingService`, `AnomalyDetectionService`, `EnrichmentService`
   - Reusable across different controllers

4. **Strategy Pattern**
   - Extensible parser architecture
   - `BaseParser` abstract class
   - Concrete parsers: `ZscalerParser`, future parsers (CrowdStrike, Okta, etc.)
   - `ParserFactory` for parser selection

5. **Factory Pattern**
   - `ParserFactory.get_parser(log_type='zscaler')`
   - Auto-detection from file content
   - Easy to add new log sources

---

## 💻 Technology Stack

### Backend

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Programming language |
| Flask | 3.0+ | Web framework |
| PostgreSQL | 15+ | Relational database |
| SQLAlchemy | 2.0+ | ORM |
| Flask-JWT-Extended | 4.5+ | Authentication |
| NumPy | 1.24+ | Numerical computing |
| Pandas | 2.0+ | Data analysis |
| scikit-learn | 1.3+ | Machine learning |
| Ollama | Latest | Local LLM inference |

### Frontend

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18+ | UI framework |
| TypeScript | 5+ | Type safety |
| Vite | 5+ | Build tool |
| TailwindCSS | 3+ | Styling |
| Recharts | 2+ | Data visualization |
| Axios | 1+ | HTTP client |
| React Router | 6+ | Routing |
| Lucide React | Latest | Icons |

### Infrastructure

| Technology | Purpose |
|------------|---------|
| Docker | Containerization |
| Docker Compose | Multi-container orchestration |
| Nginx | Reverse proxy (production) |

---

## 🚀 Quick Start

### Prerequisites

- **Docker** and **Docker Compose** installed
- **Ollama** installed (for AI features)
- **8GB RAM** minimum
- **10GB disk space** for logs and database

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CyberDuckyMiniSIEM
   ```

2. **Start Ollama and pull the model**
   ```bash
   ollama serve
   ollama pull phi3:mini
   ```

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Access the application**
   - Frontend: http://localhost:5173
   - Backend API: http://localhost:5001

5. **Create an account**
   - Navigate to http://localhost:5173
   - Click "Register" and create an account
   - Login with your credentials

6. **Upload logs**
   - Click "Upload Logs" in the navigation
   - Select "Zscaler NSS Web Logs"
   - Upload a CSV file
   - Wait for processing to complete

7. **View analysis**
   - Navigate to "Overview Dashboard"
   - Explore metrics, visualizations, and anomalies
   - Click on users/IPs/threats for unified analysis

### Sample Data

Sample Zscaler logs are provided in `sample_logs/` directory:
- `zscaler_sample_comprehensive.csv` - Comprehensive sample with all detection methods triggered

---

## 🔧 How It Works

### 1. Log Upload and Parsing

**Flow:**
```
User uploads CSV → Backend receives file → Parser Factory selects parser →
Zscaler Parser processes → Normalized events created → Stored in database
```

**Zscaler Parser Process:**

1. **File Validation**
   - Checks file extension (.csv, .txt, .log)
   - Validates CSV structure
   - Detects Zscaler format by headers

2. **Line-by-Line Parsing**
   - Reads CSV with pandas
   - Maps 35 Zscaler fields to normalized schema
   - Handles missing/malformed data gracefully

3. **Field Mapping**
   ```python
   # Key Zscaler fields mapped:
   timestamp → datetime
   login → username
   csip → source_ip
   urlcategory → url_category
   threatname → threat_name
   risk → risk_score
   ```

4. **Data Normalization**
   - Converts timestamps to UTC
   - Normalizes IP addresses
   - Standardizes threat names
   - Calculates risk scores

### 2. Anomaly Detection Pipeline

**Multi-Stage Detection:**

```
Log Entry → Rule-Based Detection → Statistical Analysis →
LLM Analysis → Anomaly Record → Database Storage
```

**Stage 1: Rule-Based Detection**

Checks for known threat patterns:
- **Malware**: `threat_name` contains malware indicators
- **Phishing**: URL categories or threat names indicate phishing
- **C2 Beaconing**: Regular intervals, specific ports, known C2 domains
- **Data Exfiltration**: Large uploads, suspicious file types, external destinations

**Stage 2: Statistical Analysis**

Applies 7 statistical methods:

1. **Z-Score Analysis**
   ```python
   z_score = (value - mean) / std_dev
   if abs(z_score) > 3.0: anomaly detected
   ```

2. **EWMA (Exponentially Weighted Moving Average)**
   ```python
   ewma = alpha * current + (1 - alpha) * previous_ewma
   if abs(current - ewma) > threshold: anomaly detected
   ```

3. **Percentile-Based**
   ```python
   if value > 95th_percentile or value < 5th_percentile: anomaly detected
   ```

4. **IQR (Interquartile Range)**
   ```python
   IQR = Q3 - Q1
   if value < Q1 - 1.5*IQR or value > Q3 + 1.5*IQR: anomaly detected
   ```

5. **Pearson Correlation**
   - Detects unusual correlations between metrics
   - Identifies coordinated anomalies

6. **KDE (Kernel Density Estimation)**
   - Probability density estimation
   - Detects low-probability events

7. **Rolling Statistics with Burst Detection**
   - Sliding window analysis
   - Detects sudden spikes or drops

**Stage 3: LLM Analysis**

Uses Ollama (phi3:mini) for context-aware analysis:

```python
# Prompt sent to LLM
prompt = f"""
Analyze this security event:
- User: {username}
- Source IP: {source_ip}
- URL: {url}
- Threat: {threat_name}
- Risk Score: {risk_score}

Provide: threat assessment, confidence score, recommended actions
"""
```

LLM provides:
- Natural language threat description
- Confidence score (0-100)
- Recommended actions for SOC analysts
- Context-aware insights

### 3. Visualization Generation

**Process:**
```
Database Query → Data Aggregation → Statistical Calculation →
Chart Data Formatting → JSON Response → Frontend Rendering
```

**Visualization Types:**

1. **Anomaly Time Series**
   - Groups anomalies by hour
   - Counts by severity (critical, high, medium, low)
   - Line chart with multiple series

2. **Risk Score Trendline**
   - Calculates average risk per hour
   - Identifies risk trends
   - Area chart with gradient

3. **Event Timeline**
   - Chronological event ordering
   - Color-coded by risk level
   - Interactive timeline component

4. **Requests Per Minute**
   - Aggregates requests by minute
   - Identifies traffic patterns
   - Bar chart with threshold lines

5. **Z-Score Heatmap**
   - Multi-dimensional anomaly view
   - Metrics: requests_per_user, bytes_transferred, unique_destinations
   - Color intensity indicates anomaly severity

6. **Category Distribution**
   - URL category breakdown
   - Pie chart with percentages
   - Top 10 categories

7. **Top Threats**
   - Most frequent threats
   - Sorted by count and risk
   - Bar chart with risk color coding

### 4. Unified Analysis

**Purpose:** Aggregate data across all log files for comprehensive investigation

**Flow:**
```
User clicks on user/IP/threat → Navigate with filter →
Query all files → Aggregate results → Display unified view
```

**Example Queries:**

```sql
-- All entries for a specific user across all files
SELECT * FROM log_entries
WHERE log_file_id IN (user's files)
AND username = 'john.doe'
ORDER BY timestamp DESC
LIMIT 100;

-- All high-risk entries
SELECT * FROM log_entries
WHERE log_file_id IN (user's files)
AND risk_score >= 70
ORDER BY risk_score DESC, timestamp DESC;

-- All entries for a specific threat
SELECT * FROM log_entries
WHERE log_file_id IN (user's files)
AND threat_name = 'Malware.Generic'
ORDER BY timestamp DESC;
```

**Unified Analysis Features:**
- Filter by: username, IP, threat name, category, min risk score
- Statistics: total count, avg risk, high risk count, anomaly count
- File breakdown: shows which files contributed data
- Anomaly table: all anomalies matching filters
- Log entry table: up to 100 most recent entries

---

## 🎨 Design Decisions

### Why These Technologies?

**Flask vs Django:**
- ✅ Flask: Lightweight, flexible, perfect for APIs
- ❌ Django: Too opinionated, includes unnecessary features (admin panel, ORM constraints)

**PostgreSQL vs MongoDB:**
- ✅ PostgreSQL: ACID compliance, complex queries, relationships, JSON support
- ❌ MongoDB: No transactions, difficult joins, schema flexibility not needed

**React vs Vue/Angular:**
- ✅ React: Large ecosystem, TypeScript support, component reusability
- ❌ Vue: Smaller ecosystem
- ❌ Angular: Too heavy, steep learning curve

**Ollama vs OpenAI API:**
- ✅ Ollama: Local inference, no API costs, data privacy, offline capability
- ❌ OpenAI: Costs money, requires internet, data leaves premises

**TailwindCSS vs Bootstrap:**
- ✅ Tailwind: Utility-first, customizable, smaller bundle size
- ❌ Bootstrap: Opinionated, harder to customize, larger bundle

### Architecture Decisions

**1. Repository Pattern**
- **Why:** Separates data access from business logic
- **Benefit:** Easy to test, swap databases, mock data
- **Trade-off:** More code, but better maintainability

**2. Service Layer**
- **Why:** Encapsulates complex business logic
- **Benefit:** Reusable across controllers, easier to test
- **Trade-off:** Additional abstraction layer

**3. JWT Authentication**
- **Why:** Stateless, scalable, works with SPAs
- **Benefit:** No server-side session storage
- **Trade-off:** Token management complexity

**4. Unified Analysis vs Per-File**
- **Why:** SOC analysts need to see all occurrences of a threat/user/IP
- **Benefit:** Comprehensive investigation, pattern detection
- **Trade-off:** More complex queries, performance considerations

**5. Local LLM vs Cloud API**
- **Why:** Data privacy, cost control, offline capability
- **Benefit:** No data leaves premises, no API costs
- **Trade-off:** Requires local GPU/CPU resources

### Database Schema Design

**Key Decisions:**

1. **UUID Primary Keys**
   - Why: Distributed systems, no collision risk
   - Trade-off: Larger index size vs auto-increment

2. **Separate Anomaly Table**
   - Why: Not all log entries have anomalies
   - Benefit: Efficient queries, normalized data
   - Trade-off: Join required for full context

3. **User Isolation**
   - Why: Multi-tenant security
   - Implementation: `user_id` foreign key on `log_files`
   - Benefit: Data privacy, access control

4. **Timestamp Indexing**
   - Why: Time-based queries are common
   - Benefit: Fast time-range queries
   - Trade-off: Index maintenance overhead

---

## 🔍 Parser Architecture

### Overview

The parser architecture is designed for **extensibility** - easily add new log sources (CrowdStrike, Okta, AWS, etc.) without modifying existing code.

### Components

**1. BaseParser (Abstract Class)**

```python
class BaseParser(ABC):
    """Abstract base class for all log parsers"""

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse a single log line into a dictionary"""
        pass

    @abstractmethod
    def detect_format(self, file_path: str) -> bool:
        """Detect if this parser can handle the file"""
        pass

    def process_line(self, line: str, line_number: int) -> Optional[NormalizedEvent]:
        """Parse and normalize a log line"""
        parsed = self.parse_line(line, line_number)
        if parsed:
            return self.normalize_event(parsed)
        return None
```

**2. ZscalerParser (Concrete Implementation)**

```python
class ZscalerParser(BaseParser):
    """Parser for Zscaler NSS Web Logs"""

    # 35 Zscaler fields mapped
    ZSCALER_FIELDS = [
        'time', 'login', 'proto', 'sip', 'sport', 'dip', 'dport',
        'url', 'urlclass', 'urlsupercat', 'urlcat', 'malwarecat',
        'threatname', 'filetype', 'appname', 'appclass', 'reqmethod',
        'reqsize', 'respsize', 'stime', 'ctime', 'location', 'dept',
        'deviceowner', 'devicehostname', 'action', 'reason', 'risk',
        'recordid', 'epochtime', 'tz', 'contenttype', 'unscannabletype',
        'deviceappversion', 'devicemodel'
    ]

    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        # CSV parsing logic
        # Returns dictionary with normalized field names
        pass

    def detect_format(self, file_path: str) -> bool:
        # Check for Zscaler-specific headers
        # Returns True if Zscaler format detected
        pass
```

**3. ParserFactory**

```python
class ParserFactory:
    """Factory for creating appropriate parser instances"""

    _parsers = {
        'zscaler': ZscalerParser,
        # Future: 'crowdstrike': CrowdStrikeParser,
        # Future: 'okta': OktaParser,
    }

    @classmethod
    def get_parser(cls, log_type: str = None, file_path: str = None) -> BaseParser:
        """Get parser by type or auto-detect from file"""
        if log_type:
            return cls._parsers[log_type]()

        # Auto-detection
        for parser_class in cls._parsers.values():
            parser = parser_class()
            if parser.detect_format(file_path):
                return parser

        raise ValueError("No suitable parser found")
```

### Zscaler Field Mapping

| Zscaler Field | Normalized Field | Description |
|---------------|------------------|-------------|
| `time` | `timestamp` | Event timestamp |
| `login` | `username` | User login name |
| `sip` | `source_ip` | Source IP address |
| `dip` | `destination_ip` | Destination IP address |
| `url` | `url` | Requested URL |
| `urlcat` | `url_category` | URL category |
| `threatname` | `threat_name` | Detected threat |
| `risk` | `risk_score` | Risk score (0-100) |
| `action` | `action` | Action taken (allowed/blocked) |
| `reqsize` | `bytes_sent` | Request size in bytes |
| `respsize` | `bytes_received` | Response size in bytes |
| `devicehostname` | `device_name` | Device hostname |
| `location` | `location` | User location |
| `dept` | `department` | User department |

### Adding a New Parser

To add support for a new log source (e.g., CrowdStrike):

1. **Create parser file**: `backend/app/parsers/crowdstrike_parser.py`

2. **Implement BaseParser**:
   ```python
   class CrowdStrikeParser(BaseParser):
       def parse_line(self, line: str, line_number: int):
           # Parse CrowdStrike JSON/CSV format
           pass

       def detect_format(self, file_path: str):
           # Check for CrowdStrike indicators
           pass
   ```

3. **Register in ParserFactory**:
   ```python
   _parsers = {
       'zscaler': ZscalerParser,
       'crowdstrike': CrowdStrikeParser,  # Add here
   }
   ```

4. **Update frontend selector**:
   ```typescript
   <option value="crowdstrike">CrowdStrike EDR Logs</option>
   ```

**That's it!** The rest of the pipeline (anomaly detection, visualization, storage) works automatically.

---

## 🤖 Anomaly Detection

### Detection Methods

#### 1. Rule-Based Detection

**Malware Detection:**
```python
malware_indicators = ['malware', 'virus', 'trojan', 'ransomware', 'worm', 'backdoor']
if any(indicator in threat_name.lower() for indicator in malware_indicators):
    create_anomaly(
        type='malware_detected',
        severity='critical',
        confidence=0.95
    )
```

**Phishing Detection:**
```python
phishing_categories = ['Phishing', 'Suspicious', 'Newly Registered Domains']
phishing_indicators = ['phishing', 'credential', 'fake login']

if url_category in phishing_categories or any(ind in url for ind in phishing_indicators):
    create_anomaly(
        type='phishing_attempt',
        severity='high',
        confidence=0.90
    )
```

**C2 Beaconing Detection:**
```python
# Detect regular intervals (beaconing pattern)
time_diffs = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
avg_interval = mean(time_diffs)
std_interval = std(time_diffs)

if std_interval < 5 and len(timestamps) > 10:  # Regular pattern
    create_anomaly(
        type='c2_beaconing',
        severity='critical',
        confidence=0.85
    )
```

**Data Exfiltration Detection:**
```python
# Large upload to external destination
if bytes_sent > 100_000_000 and destination_type == 'external':
    create_anomaly(
        type='data_exfiltration',
        severity='critical',
        confidence=0.80
    )
```

#### 2. Statistical Detection

**Z-Score Analysis:**
```python
def detect_zscore_anomalies(data, threshold=3.0):
    mean = np.mean(data)
    std = np.std(data)
    z_scores = [(x - mean) / std for x in data]

    anomalies = []
    for i, z in enumerate(z_scores):
        if abs(z) > threshold:
            anomalies.append({
                'index': i,
                'value': data[i],
                'z_score': z,
                'severity': 'high' if abs(z) > 4 else 'medium'
            })

    return anomalies
```

**EWMA (Exponentially Weighted Moving Average):**
```python
def detect_ewma_anomalies(data, alpha=0.3, threshold=2.0):
    ewma = data[0]
    anomalies = []

    for i, value in enumerate(data[1:], 1):
        deviation = abs(value - ewma)
        std = np.std(data[:i])

        if deviation > threshold * std:
            anomalies.append({
                'index': i,
                'value': value,
                'expected': ewma,
                'deviation': deviation
            })

        ewma = alpha * value + (1 - alpha) * ewma

    return anomalies
```

**IQR Outlier Detection:**
```python
def detect_iqr_outliers(data):
    Q1 = np.percentile(data, 25)
    Q3 = np.percentile(data, 75)
    IQR = Q3 - Q1

    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR

    outliers = [
        {'index': i, 'value': x}
        for i, x in enumerate(data)
        if x < lower_bound or x > upper_bound
    ]

    return outliers
```

#### 3. LLM-Based Detection

**Integration with Ollama:**
```python
import requests

def analyze_with_llm(log_entry):
    prompt = f"""
    Analyze this security event and provide:
    1. Threat assessment (1-2 sentences)
    2. Confidence score (0-100)
    3. Recommended actions

    Event Details:
    - User: {log_entry.username}
    - Source IP: {log_entry.source_ip}
    - URL: {log_entry.url}
    - Threat: {log_entry.threat_name}
    - Risk Score: {log_entry.risk_score}
    - Action: {log_entry.action}
    """

    response = requests.post('http://localhost:11434/api/generate', json={
        'model': 'phi3:mini',
        'prompt': prompt,
        'stream': False
    })

    return parse_llm_response(response.json())
```

**LLM Response Parsing:**
```python
def parse_llm_response(response):
    text = response['response']

    # Extract confidence score
    confidence_match = re.search(r'confidence[:\s]+(\d+)', text, re.IGNORECASE)
    confidence = int(confidence_match.group(1)) if confidence_match else 50

    # Extract threat assessment
    assessment = text.split('\n')[0]  # First line

    # Extract recommended actions
    actions_match = re.search(r'recommended actions?[:\s]+(.*)', text, re.IGNORECASE | re.DOTALL)
    actions = actions_match.group(1).strip() if actions_match else "Review and investigate"

    return {
        'assessment': assessment,
        'confidence': confidence / 100,
        'recommended_actions': actions
    }
```

---

## 📡 API Reference

### Authentication

**Register User**
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "analyst1",
  "email": "analyst1@company.com",
  "password": "SecurePass123!"
}

Response: 201 Created
{
  "message": "User created successfully",
  "user": {
    "id": "uuid",
    "username": "analyst1",
    "email": "analyst1@company.com"
  }
}
```

**Login**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "analyst1",
  "password": "SecurePass123!"
}

Response: 200 OK
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "uuid",
    "username": "analyst1",
    "email": "analyst1@company.com"
  }
}
```

### Log Upload

**Upload Log File**
```http
POST /api/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary>
log_type: zscaler

Response: 200 OK
{
  "message": "File uploaded and processed successfully",
  "log_file": {
    "id": "uuid",
    "original_filename": "zscaler_logs.csv",
    "status": "completed",
    "total_entries": 1500,
    "anomaly_count": 45,
    "threat_count": 12
  }
}
```

### Dashboard

**Get Overview**
```http
GET /api/dashboard/overview
Authorization: Bearer <token>

Response: 200 OK
{
  "total_files": 5,
  "total_entries": 7500,
  "total_anomalies": 230,
  "critical_anomalies": 45,
  "avg_risk_score": 42.5,
  "high_risk_entries": 450,
  "unique_users": 125,
  "unique_ips": 89,
  "threat_count": 67,
  "recent_activity": [...]
}
```

**Get Top Threats**
```http
GET /api/dashboard/top-threats
Authorization: Bearer <token>

Response: 200 OK
{
  "threats": [
    {"name": "Malware.Generic", "count": 45, "avg_risk": 85.5},
    {"name": "Phishing.Credential", "count": 32, "avg_risk": 78.2}
  ],
  "categories": [
    {"category": "Malware Sites", "count": 120, "percentage": 15.5}
  ],
  "users": [
    {"username": "john.doe", "count": 1500, "avg_risk": 65.3, "max_risk": 95}
  ],
  "ips": [
    {"ip": "192.168.1.100", "count": 2300, "avg_risk": 55.8, "max_risk": 90}
  ]
}
```

**Get Unified Analysis**
```http
GET /api/dashboard/unified-analysis?username=john.doe&min_risk=70
Authorization: Bearer <token>

Response: 200 OK
{
  "log_entries": [...],  // Up to 100 entries
  "anomalies": [...],     // Up to 50 anomalies
  "statistics": {
    "total_count": 1500,
    "avg_risk_score": 75.5,
    "high_risk_count": 450,
    "anomaly_count": 45,
    "file_breakdown": {
      "file1.csv": 800,
      "file2.csv": 700
    }
  },
  "filters_applied": {
    "username": "john.doe",
    "min_risk": 70
  }
}
```

### Analysis

**Get File Analysis**
```http
GET /api/analysis/<file_id>
Authorization: Bearer <token>

Response: 200 OK
{
  "file_info": {...},
  "statistics": {...},
  "anomalies": [...],
  "log_entries": [...]
}
```

### Visualizations

**Get All Visualizations**
```http
GET /api/visualizations/<file_id>
Authorization: Bearer <token>

Response: 200 OK
{
  "anomaly_time_series": [...],
  "risk_score_trendline": [...],
  "event_timeline": [...],
  "requests_per_minute": [...],
  "z_score_heatmap": {...},
  "category_distribution": [...],
  "top_threats": [...]
}
```

---

## 🛠️ Development

### Project Structure

```
CyberDuckyMiniSIEM/
├── backend/
│   ├── app/
│   │   ├── __init__.py              # Flask app factory
│   │   ├── config.py                # Configuration
│   │   ├── models/                  # SQLAlchemy models
│   │   │   ├── user.py
│   │   │   ├── log_file.py
│   │   │   ├── log_entry.py
│   │   │   └── anomaly.py
│   │   ├── repositories/            # Data access layer
│   │   │   ├── user_repository.py
│   │   │   ├── log_file_repository.py
│   │   │   ├── log_entry_repository.py
│   │   │   └── anomaly_repository.py
│   │   ├── services/                # Business logic
│   │   │   ├── log_processing_service.py
│   │   │   ├── anomaly_detection_service.py
│   │   │   ├── enrichment_service.py
│   │   │   ├── statistical_service.py
│   │   │   └── llm_service.py
│   │   ├── parsers/                 # Log parsers
│   │   │   ├── base_parser.py
│   │   │   ├── zscaler_parser.py
│   │   │   └── parser_factory.py
│   │   ├── controllers/             # API endpoints
│   │   │   ├── auth_controller.py
│   │   │   ├── dashboard_controller.py
│   │   │   ├── analysis_controller.py
│   │   │   ├── upload_controller.py
│   │   │   └── visualization_controller.py
│   │   └── schemas/                 # Data schemas
│   │       └── normalized_event.py
│   ├── migrations/                  # Database migrations
│   ├── uploads/                     # Uploaded files
│   ├── requirements.txt             # Python dependencies
│   ├── Dockerfile
│   └── run.py                       # Application entry point
├── frontend/
│   ├── src/
│   │   ├── components/              # React components
│   │   │   ├── NavigationBar.tsx
│   │   │   └── ...
│   │   ├── pages/                   # Page components
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   ├── OverviewDashboard.tsx
│   │   │   ├── UnifiedAnalysis.tsx
│   │   │   ├── Analysis.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   └── UploadLogs.tsx
│   │   ├── services/                # API client
│   │   │   └── api.ts
│   │   ├── context/                 # React context
│   │   │   └── AuthContext.tsx
│   │   ├── App.tsx                  # Main app component
│   │   └── main.tsx                 # Entry point
│   ├── package.json                 # Node dependencies
│   ├── Dockerfile
│   └── vite.config.ts               # Vite configuration
├── sample_logs/                     # Sample log files
├── documentation/                   # Documentation (created by cleanup)
├── docker-compose.yml               # Docker orchestration
└── README.md                        # This file
```

### Running Locally (Without Docker)

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost:5432/cyberducky"
export JWT_SECRET_KEY="your-secret-key"

# Run migrations
flask db upgrade

# Start server
python run.py
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Database Migrations

```bash
cd backend

# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Rollback migration
flask db downgrade
```

---

## 📚 Documentation

Detailed documentation is available in the `documentation/` folder:

- **Architecture** - System design and patterns
- **Parser Guide** - How to add new log sources
- **API Reference** - Complete API documentation
- **Deployment** - Production deployment guide
- **Statistical Methods** - Anomaly detection algorithms
- **LLM Integration** - AI-powered analysis setup

---

## 🔒 Security Considerations

### Authentication & Authorization

- **JWT Tokens**: 24-hour expiration, secure secret key
- **Password Hashing**: Werkzeug PBKDF2 with salt
- **User Isolation**: All queries filtered by `user_id`
- **CORS**: Configured for specific origins only

### Input Validation

- **File Upload**: Size limits, type validation, virus scanning (recommended)
- **SQL Injection**: SQLAlchemy ORM with parameterized queries
- **XSS Prevention**: React auto-escapes output
- **CSRF**: Not needed for JWT-based API

### Data Privacy

- **Local LLM**: No data sent to external APIs
- **User Isolation**: Users can only see their own data
- **Secure Storage**: Passwords hashed, tokens encrypted

### Production Recommendations

1. **Use HTTPS**: SSL/TLS certificates
2. **Environment Variables**: Never commit secrets
3. **Rate Limiting**: Prevent brute force attacks
4. **Logging**: Audit logs for security events
5. **Backups**: Regular database backups
6. **Updates**: Keep dependencies updated

---

## 📝 License

This project is for educational purposes. Modify and use as needed.

---

## 🤝 Contributing

This is a learning project. Feel free to fork and customize for your needs.

---

## 📧 Support

For questions or issues, refer to the documentation in the `documentation/` folder.

---

**Built with ❤️ for SOC Analysts**


