# Parser Architecture Guide

## Overview

The parser architecture is designed for **extensibility** - easily add new log sources without modifying existing code.

## Components

### 1. BaseParser (Abstract Class)

Location: `backend/app/parsers/base_parser.py`

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseParser(ABC):
    """Abstract base class for all log parsers"""
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line into a dictionary
        
        Args:
            line: Raw log line
            line_number: Line number in file (for error reporting)
            
        Returns:
            Dictionary with parsed fields or None if parsing fails
        """
        pass
    
    @abstractmethod
    def detect_format(self, file_path: str) -> bool:
        """
        Detect if this parser can handle the file
        
        Args:
            file_path: Path to log file
            
        Returns:
            True if this parser can handle the file
        """
        pass
    
    def process_line(self, line: str, line_number: int) -> Optional[NormalizedEvent]:
        """
        Parse and normalize a log line
        
        This method calls parse_line() and then normalize_event()
        """
        parsed = self.parse_line(line, line_number)
        if parsed:
            return self.normalize_event(parsed)
        return None
    
    def normalize_event(self, parsed_data: Dict[str, Any]) -> NormalizedEvent:
        """Convert parsed data to NormalizedEvent schema"""
        return NormalizedEvent(**parsed_data)
```

### 2. ZscalerParser (Concrete Implementation)

Location: `backend/app/parsers/zscaler_parser.py`

**Zscaler NSS Web Log Format:**
- CSV format with 35 fields
- Header row with field names
- Comma-separated values

**Field Mapping:**

| Zscaler Field | Normalized Field | Type | Description |
|---------------|------------------|------|-------------|
| `time` | `timestamp` | datetime | Event timestamp |
| `login` | `username` | string | User login name |
| `sip` | `source_ip` | string | Source IP address |
| `dip` | `destination_ip` | string | Destination IP |
| `url` | `url` | string | Requested URL |
| `urlcat` | `url_category` | string | URL category |
| `threatname` | `threat_name` | string | Detected threat |
| `risk` | `risk_score` | integer | Risk score (0-100) |
| `action` | `action` | string | Action taken |
| `reqsize` | `bytes_sent` | integer | Request size |
| `respsize` | `bytes_received` | integer | Response size |

**Implementation:**

```python
class ZscalerParser(BaseParser):
    """Parser for Zscaler NSS Web Logs"""
    
    ZSCALER_FIELDS = [
        'time', 'login', 'proto', 'sip', 'sport', 'dip', 'dport',
        'url', 'urlclass', 'urlsupercat', 'urlcat', 'malwarecat',
        'threatname', 'filetype', 'appname', 'appclass', 'reqmethod',
        'reqsize', 'respsize', 'stime', 'ctime', 'location', 'dept',
        'deviceowner', 'devicehostname', 'action', 'reason', 'risk',
        'recordid', 'epochtime', 'tz', 'contenttype', 'unscannabletype',
        'deviceappversion', 'devicemodel'
    ]
    
    def detect_format(self, file_path: str) -> bool:
        """Check if file is Zscaler format by examining headers"""
        with open(file_path, 'r') as f:
            first_line = f.readline().strip()
            # Check for Zscaler-specific headers
            return 'time' in first_line and 'login' in first_line and 'threatname' in first_line
    
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse a single Zscaler CSV line"""
        try:
            # Use pandas for robust CSV parsing
            df = pd.read_csv(io.StringIO(line), names=self.ZSCALER_FIELDS)
            row = df.iloc[0]
            
            # Map to normalized schema
            return {
                'timestamp': self._parse_timestamp(row['time']),
                'username': row['login'],
                'source_ip': row['sip'],
                'destination_ip': row['dip'],
                'url': row['url'],
                'url_category': row['urlcat'],
                'threat_name': self._normalize_threat_name(row['threatname']),
                'risk_score': int(row['risk']) if pd.notna(row['risk']) else 0,
                'action': row['action'],
                'bytes_sent': int(row['reqsize']) if pd.notna(row['reqsize']) else 0,
                'bytes_received': int(row['respsize']) if pd.notna(row['respsize']) else 0,
                'device_name': row['devicehostname'],
                'location': row['location'],
                'department': row['dept']
            }
        except Exception as e:
            logger.error(f"Error parsing line {line_number}: {e}")
            return None
    
    def _parse_timestamp(self, time_str: str) -> datetime:
        """Parse Zscaler timestamp format"""
        # Zscaler format: "Mon Jan 15 14:30:45 2024"
        return datetime.strptime(time_str, "%a %b %d %H:%M:%S %Y")
    
    def _normalize_threat_name(self, threat_name: str) -> str:
        """Normalize threat names for consistency"""
        if pd.isna(threat_name) or threat_name == 'None':
            return None
        return threat_name.strip()
```

### 3. ParserFactory

Location: `backend/app/parsers/parser_factory.py`

```python
class ParserFactory:
    """Factory for creating appropriate parser instances"""
    
    _parsers = {
        'zscaler': ZscalerParser,
        # Future parsers:
        # 'crowdstrike': CrowdStrikeParser,
        # 'okta': OktaParser,
        # 'aws_cloudtrail': AWSCloudTrailParser,
    }
    
    @classmethod
    def get_parser(cls, log_type: str = None, file_path: str = None) -> BaseParser:
        """
        Get parser by type or auto-detect from file
        
        Args:
            log_type: Explicit parser type ('zscaler', 'crowdstrike', etc.)
            file_path: Path to file for auto-detection
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If no suitable parser found
        """
        if log_type:
            if log_type not in cls._parsers:
                raise ValueError(f"Unknown log type: {log_type}")
            return cls._parsers[log_type]()
        
        if file_path:
            # Auto-detection
            for parser_name, parser_class in cls._parsers.items():
                parser = parser_class()
                if parser.detect_format(file_path):
                    logger.info(f"Auto-detected {parser_name} format")
                    return parser
        
        raise ValueError("No suitable parser found for file")
    
    @classmethod
    def register_parser(cls, name: str, parser_class: type):
        """Register a new parser (for plugins/extensions)"""
        cls._parsers[name] = parser_class
```

## Adding a New Parser

### Example: CrowdStrike EDR Logs

**Step 1: Create Parser File**

Create `backend/app/parsers/crowdstrike_parser.py`:

```python
from .base_parser import BaseParser
import json

class CrowdStrikeParser(BaseParser):
    """Parser for CrowdStrike EDR JSON logs"""
    
    def detect_format(self, file_path: str) -> bool:
        """Detect CrowdStrike JSON format"""
        with open(file_path, 'r') as f:
            try:
                first_line = f.readline()
                data = json.loads(first_line)
                # Check for CrowdStrike-specific fields
                return 'event_simpleName' in data and 'aid' in data
            except:
                return False
    
    def parse_line(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse CrowdStrike JSON event"""
        try:
            event = json.loads(line)
            
            return {
                'timestamp': datetime.fromtimestamp(event['timestamp'] / 1000),
                'username': event.get('UserName'),
                'source_ip': event.get('LocalIP'),
                'destination_ip': event.get('RemoteIP'),
                'url': event.get('URL'),
                'threat_name': event.get('DetectName'),
                'risk_score': self._calculate_risk(event),
                'action': event.get('PatternDispositionDescription'),
                'device_name': event.get('ComputerName'),
                # Map other fields...
            }
        except Exception as e:
            logger.error(f"Error parsing CrowdStrike event: {e}")
            return None
```

**Step 2: Register in ParserFactory**

Edit `backend/app/parsers/parser_factory.py`:

```python
from .crowdstrike_parser import CrowdStrikeParser

class ParserFactory:
    _parsers = {
        'zscaler': ZscalerParser,
        'crowdstrike': CrowdStrikeParser,  # Add here
    }
```

**Step 3: Update Frontend**

Edit `frontend/src/pages/UploadLogs.tsx`:

```typescript
<select value={logType} onChange={(e) => setLogType(e.target.value)}>
  <option value="zscaler">Zscaler NSS Web Logs</option>
  <option value="crowdstrike">CrowdStrike EDR Logs</option>
</select>
```

**That's it!** The rest of the pipeline works automatically.


