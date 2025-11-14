"""
Zscaler NSS Web Log Parser
Parses Zscaler web proxy logs based on the NSS feed format
Reference: https://help.zscaler.com/zia/nss-feed-output-format-web-logs
"""
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

from app.parsers.base_parser import BaseParser

logger = logging.getLogger(__name__)

class ZscalerParser(BaseParser):
    """
    Parser for Zscaler NSS Web Logs

    Supports both key=value format and CSV format
    """

    def __init__(self):
        super().__init__()
        self.vendor = "zscaler"
        self.product = "zia"
        self.log_type = "zscaler"
        self.parser_name = "zscaler_legacy"
        self.header_detected = False  # Track if we've seen a header row
        self.csv_headers = None  # Store CSV headers for custom format parsing

    # Field mappings from Zscaler field names to our database field names
    FIELD_MAPPING = {
        'time': 'timestamp',
        'devTime': 'timestamp',
        'login': 'username',
        'user': 'username',
        'usrName': 'username',
        'src': 'source_ip',
        'srcip': 'source_ip',
        'srcPostNAT': 'source_post_nat_ip',
        'dst': 'destination_ip',
        'dstip': 'destination_ip',
        'srcBytes': 'source_bytes',
        'dstBytes': 'destination_bytes',
        'hostname': 'hostname',
        'url': 'url',
        'referer': 'referer',
        'reqmethod': 'request_method',
        'method': 'request_method',
        'respcode': 'response_code',
        'status': 'response_code',
        'useragent': 'user_agent',
        'ua': 'user_agent',
        'contenttype': 'content_type',
        'filetype': 'file_type',
        'fileclass': 'file_class',
        'urlcategory': 'url_category',
        'urlcat': 'url_category',
        'urlsupercategory': 'url_super_category',
        'urlclass': 'url_class',
        'appname': 'app_name',
        'app': 'app_name',
        'appclass': 'app_class',
        'appproto': 'app_protocol',
        'proto': 'app_protocol',
        'threatname': 'threat_name',
        'threat': 'threat_name',
        'malwaretype': 'malware_type',
        'malwareclass': 'malware_class',
        'riskscore': 'risk_score',
        'risk': 'risk_score',
        'policy': 'policy',
        'action': 'action',
        'bypassedtraffic': 'bypassed_traffic',
        'bypass': 'bypassed_traffic',
        'unscannabletype': 'unscannable_type',
        'dlpdict': 'dlp_dictionary',
        'dlpeng': 'dlp_engine',
        'devicehostname': 'device_hostname',
        'device': 'device_hostname',
        'deviceowner': 'device_owner',
        'owner': 'device_owner',
        'role': 'role',
        'realm': 'realm',
        'location': 'realm',
        'bwthrottle': 'bandwidth_throttle',
        'recordid': 'record_id',
        'id': 'record_id'
    }
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line

        Args:
            line: Raw log line
            line_number: Line number for error reporting

        Returns:
            Dictionary of parsed fields or None if parsing fails
        """
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return None

        # Detect and store CSV header row (first line with field names)
        if line_number == 1 and ',' in line:
            # Check if this looks like a header (contains common field names)
            lower_line = line.lower()
            header_indicators = ['datetime', 'timestamp', 'user', 'url', 'action', 'risk_score']
            if any(indicator in lower_line for indicator in header_indicators):
                logger.info(f"Detected CSV header row: {line[:100]}")
                self.header_detected = True
                # Store headers for custom CSV parsing
                import csv
                from io import StringIO
                reader = csv.reader(StringIO(line))
                self.csv_headers = next(reader)
                logger.info(f"Stored {len(self.csv_headers)} CSV headers for custom format parsing")
                return None

        try:
            # Try key=value format first (most common for Zscaler NSS)
            if '=' in line:
                return self._parse_key_value_format(line)
            # Try CSV format
            elif ',' in line or '\t' in line:
                return self._parse_csv_format(line)
            else:
                logger.warning(f"Line {line_number}: Unknown format: {line[:100]}")
                return None

        except Exception as e:
            logger.error(f"Line {line_number}: Parse error: {e}")
            return None
    
    def _parse_key_value_format(self, line: str) -> Dict[str, Any]:
        """
        Parse key=value format
        Example: time=2023-10-30T12:00:00Z user=john.doe@company.com src=192.168.1.100 ...
        """
        parsed = {}
        
        # Use regex to handle quoted values and spaces
        pattern = r'(\w+)=(?:"([^"]*)"|([^\s]*))'
        matches = re.findall(pattern, line)
        
        for key, quoted_value, unquoted_value in matches:
            value = quoted_value if quoted_value else unquoted_value
            
            # Map to our field names
            field_name = self.FIELD_MAPPING.get(key, key)
            
            # Type conversion and normalization
            parsed[field_name] = self._normalize_value(field_name, value)
        
        # Store raw log
        parsed['raw_log'] = line
        
        return parsed
    
    def _parse_csv_format(self, line: str) -> Dict[str, Any]:
        """
        Parse Zscaler NSS Web Log CSV format
        Reference: https://help.zscaler.com/zia/nss-feed-output-format-web-logs

        Supports two modes:
        1. Custom CSV with headers (if headers were detected)
        2. Standard Zscaler NSS format (33-35 fields in fixed order)
        """
        import csv
        from io import StringIO

        # Use CSV reader to properly handle quoted fields
        reader = csv.reader(StringIO(line))
        values = next(reader)

        # If we have custom headers, use them to map fields
        if self.csv_headers:
            return self._parse_custom_csv(values)

        # Otherwise, use standard Zscaler field order

        # Zscaler NSS Web Log field order (standard configuration)
        field_order = [
            'timestamp',           # 1. time
            'username',            # 2. login
            'app_protocol',        # 3. proto
            'url',                 # 4. url
            'action',              # 5. action
            'app_name',            # 6. appname
            'app_class',           # 7. appclass
            'source_bytes',        # 8. reqsize
            'destination_bytes',   # 9. respsize
            'req_header_size',     # 10. reqheadersize
            'resp_header_size',    # 11. respheadersize
            'url_class',           # 12. urlclass
            'url_super_category',  # 13. urlsupercat
            'url_category',        # 14. urlcat
            'malware_category',    # 15. malwarecat
            'malware_class',       # 16. malwareclass
            'threat_name',         # 17. threatname
            'risk_score',          # 18. riskscore
            'dlp_engine',          # 19. dlpeng
            'dlp_dictionary',      # 20. dlpdict
            'realm',               # 21. location
            'department',          # 22. dept
            'source_ip',           # 23. cip (client IP)
            'destination_ip',      # 24. sip (server IP)
            'request_method',      # 25. reqmethod
            'response_code',       # 26. respcode
            'user_agent',          # 27. ua
            'product',             # 28. product
            'rule_label',          # 29. rulelabel
            'rule_type',           # 30. ruletype
            'file_type',           # 31. filetype
            'file_subtype',        # 32. filesubtype
            'unscannable_type',    # 33. unscannabletype
            'device_owner',        # 34. deviceowner
            'device_hostname',     # 35. devicehostname
        ]

        parsed = {}
        for i, value in enumerate(values):
            if i < len(field_order):
                field_name = field_order[i]
                parsed[field_name] = self._normalize_value(field_name, value)

        # Extract hostname from URL if not present
        if parsed.get('url') and not parsed.get('hostname'):
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(parsed['url'])
                parsed['hostname'] = parsed_url.netloc or parsed_url.path.split('/')[0]
            except:
                pass

        parsed['raw_log'] = line

        return parsed

    def _parse_custom_csv(self, values: List[str]) -> Dict[str, Any]:
        """
        Parse CSV with custom headers
        Maps common field names to our internal schema
        """
        parsed = {}

        # Field name mappings (case-insensitive)
        header_mappings = {
            'datetime': 'timestamp',
            'timestamp': 'timestamp',
            'time': 'timestamp',
            'user': 'username',
            'username': 'username',
            'login': 'username',
            'client_ip': 'source_ip',
            'source_ip': 'source_ip',
            'cip': 'source_ip',
            'server_ip': 'destination_ip',
            'destination_ip': 'destination_ip',
            'sip': 'destination_ip',
            'url': 'url',
            'url_category': 'url_category',
            'urlcat': 'url_category',
            'threat_category': 'malware_category',
            'malware_category': 'malware_category',
            'threat_name': 'threat_name',
            'threatname': 'threat_name',
            'action': 'action',
            'risk_score': 'risk_score',
            'riskscore': 'risk_score',
            'dlp_engine': 'dlp_engine',
            'dlpeng': 'dlp_engine',
            'dlp_dictionaries': 'dlp_dictionary',
            'dlpdict': 'dlp_dictionary',
            'file_type': 'file_type',
            'filetype': 'file_type',
            'app_name': 'app_name',
            'appname': 'app_name',
            'app_class': 'app_class',
            'appclass': 'app_class',
            'http_method': 'request_method',
            'request_method': 'request_method',
            'reqmethod': 'request_method',
            'http_status': 'response_code',
            'response_code': 'response_code',
            'respcode': 'response_code',
            'user_agent': 'user_agent',
            'ua': 'user_agent',
            'request_size': 'source_bytes',
            'reqsize': 'source_bytes',
            'response_size': 'destination_bytes',
            'respsize': 'destination_bytes',
            'department': 'department',
            'dept': 'department',
            'location': 'realm',
            'device_owner': 'device_owner',
            'deviceowner': 'device_owner',
            'device_hostname': 'device_hostname',
            'devicehostname': 'device_hostname',
            'malware_class': 'malware_class',
            'policy': 'policy',
        }

        # Map values to fields
        for i, value in enumerate(values):
            if i < len(self.csv_headers):
                header = self.csv_headers[i].lower().strip()
                field_name = header_mappings.get(header, header)
                parsed[field_name] = self._normalize_value(field_name, value)

        # Store raw log
        parsed['raw_log'] = ','.join(values)

        return parsed

    def _normalize_value(self, field_name: str, value: str) -> Any:
        """
        Normalize and convert field values to appropriate types
        """
        if not value or value == '-' or value == 'null' or value == 'None' or value == 'N/A' or value == 'NA':
            # Special handling for threat_name - default to UNKNOWN instead of None
            if field_name == 'threat_name':
                return 'UNKNOWN'
            return None

        # Timestamp fields
        if field_name == 'timestamp':
            return self._parse_timestamp(value)

        # Integer fields
        if field_name in ['source_bytes', 'destination_bytes', 'response_code', 'risk_score',
                          'req_header_size', 'resp_header_size']:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None

        # Boolean fields
        if field_name in ['bypassed_traffic']:
            return value.lower() in ['true', '1', 'yes', 'y']

        # String fields - just return as is
        return value
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse various timestamp formats used by Zscaler
        """
        if not timestamp_str:
            return None

        # Common Zscaler timestamp formats
        formats = [
            '%a %b %d %H:%M:%S %Y',    # Zscaler NSS default: "Mon Jun 20 15:29:11 2022"
            '%Y-%m-%dT%H:%M:%S.%fZ',   # ISO 8601 with microseconds
            '%Y-%m-%dT%H:%M:%SZ',      # ISO 8601
            '%Y-%m-%d %H:%M:%S',       # Standard datetime
            '%d/%b/%Y:%H:%M:%S %z',    # Apache-style
            '%s',                       # Unix timestamp
        ]

        for fmt in formats:
            try:
                if fmt == '%s':
                    # Unix timestamp
                    return datetime.fromtimestamp(int(timestamp_str))
                else:
                    return datetime.strptime(timestamp_str, fmt)
            except (ValueError, TypeError):
                continue

        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
    
    def validate_entry(self, entry: Dict[str, Any]) -> bool:
        """
        Validate that a parsed entry has minimum required fields
        """
        required_fields = ['timestamp']
        
        for field in required_fields:
            if field not in entry or entry[field] is None:
                return False
        
        return True
    
    def enrich_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich parsed entry with derived fields and normalizations
        """
        # Ensure we have a record_id
        if not entry.get('record_id'):
            # Generate one from timestamp and source IP
            ts = entry.get('timestamp', datetime.utcnow())
            src = entry.get('source_ip', 'unknown')
            entry['record_id'] = f"{ts.strftime('%Y%m%d%H%M%S')}_{src}"
        
        # Normalize action field
        if entry.get('action'):
            action = entry['action'].lower()
            if action in ['allowed', 'allow', 'permit']:
                entry['action'] = 'allowed'
            elif action in ['blocked', 'block', 'deny', 'denied']:
                entry['action'] = 'blocked'
        
        # Set default risk score if not present
        if entry.get('risk_score') is None:
            # Derive basic risk score from other fields
            risk = 0
            if entry.get('threat_name'):
                risk = 90
            elif entry.get('malware_type'):
                risk = 85
            elif entry.get('bypassed_traffic'):
                risk = 70
            elif entry.get('url_category') in ['Malware', 'Phishing', 'Command and Control']:
                risk = 80
            entry['risk_score'] = risk

        return entry

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines are Zscaler format

        Args:
            sample_lines: List of sample log lines

        Returns:
            True if this parser can handle the format
        """
        if not sample_lines:
            return False

        # Check for Zscaler-specific patterns
        for line in sample_lines[:5]:  # Check first 5 lines
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check for key=value format with Zscaler fields
            if '=' in line and any(field in line.lower() for field in ['login=', 'user=', 'url=', 'action=', 'threatname=']):
                return True

            # Check for CSV format with typical Zscaler field count (30-35 fields)
            if ',' in line or '\t' in line:
                # Try to parse as CSV
                import csv
                from io import StringIO
                try:
                    reader = csv.reader(StringIO(line))
                    fields = next(reader)
                    # Zscaler logs typically have 30-35 fields
                    if 25 <= len(fields) <= 40:
                        return True
                except:
                    pass

        return False

    def normalize(self, parsed_data: Dict[str, Any]):
        """
        Convert Zscaler-specific fields to normalized event schema
        """
        from app.schemas.normalized_event import (
            NormalizedEvent, EventMetadata, Source, Destination,
            User, URL, HTTP, UserAgent, Device, Network, Rule
        )
        from dateutil import parser as date_parser

        # Parse timestamp
        timestamp = parsed_data.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = date_parser.parse(timestamp)
            except:
                timestamp = datetime.utcnow()
        elif not isinstance(timestamp, datetime):
            timestamp = datetime.utcnow()

        # Determine event action and outcome
        action = parsed_data.get('action', 'unknown').lower()
        if action in ['allowed', 'allow']:
            outcome = 'success'
            event_action = 'allowed'
        elif action in ['blocked', 'block', 'denied', 'deny']:
            outcome = 'failure'
            event_action = 'blocked'
        else:
            outcome = 'unknown'
            event_action = action

        # Determine severity based on threat and risk score
        risk_score = parsed_data.get('risk_score', 0) or 0
        threat_name = parsed_data.get('threat_name', 'UNKNOWN')
        if threat_name and threat_name != 'UNKNOWN' and threat_name.lower() != 'none':
            severity = max(75, risk_score)  # Threats are at least 75
        elif risk_score >= 80:
            severity = 70
        elif risk_score >= 50:
            severity = 50
        else:
            severity = max(20, risk_score)

        # Create event metadata
        event_meta = EventMetadata(
            category="web",
            action=event_action,
            outcome=outcome,
            severity=severity,
            kind="event",
            type=["connection", "access"],
            dataset="zscaler.web",
            module="zscaler_legacy"
        )

        # Create source (client)
        source = Source(
            ip=parsed_data.get('source_ip'),
            bytes=parsed_data.get('source_bytes')
        )

        # Create destination (server)
        destination = Destination(
            ip=parsed_data.get('destination_ip'),
            bytes=parsed_data.get('destination_bytes'),
            domain=parsed_data.get('hostname')
        )

        # Create user
        user = User(
            name=parsed_data.get('username'),
            department=parsed_data.get('department')
        )

        # Create URL
        url_str = parsed_data.get('url')
        url_obj = None
        if url_str:
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(url_str)
                url_obj = URL(
                    original=url_str,
                    domain=parsed_url.netloc or parsed_data.get('hostname'),
                    path=parsed_url.path,
                    query=parsed_url.query
                )
            except:
                url_obj = URL(original=url_str)

        # Create HTTP
        http = None
        if parsed_data.get('request_method') or parsed_data.get('response_code'):
            http = HTTP(
                request_method=parsed_data.get('request_method'),
                response_status_code=parsed_data.get('response_code'),
                request_referrer=parsed_data.get('referer')
            )

        # Create User Agent
        user_agent = None
        ua_str = parsed_data.get('user_agent')
        if ua_str:
            user_agent = UserAgent(original=ua_str)

        # Create Device
        device = None
        if parsed_data.get('device_hostname') or parsed_data.get('device_owner'):
            device = Device(
                hostname=parsed_data.get('device_hostname'),
                id=parsed_data.get('device_owner')
            )

        # Create Network
        network = None
        if parsed_data.get('app_protocol') or parsed_data.get('app_name'):
            network = Network(
                protocol=parsed_data.get('app_protocol'),
                application=parsed_data.get('app_name')
            )

        # Create Rule
        rule = None
        if parsed_data.get('policy'):
            rule = Rule(
                name=parsed_data.get('policy'),
                category=parsed_data.get('url_category')
            )

        # Create normalized event
        normalized_event = NormalizedEvent(
            timestamp=timestamp,
            event=event_meta,
            observer_vendor="zscaler",
            observer_product="zia",
            observer_type="proxy",
            source=source,
            destination=destination,
            user=user,
            url=url_obj,
            http=http,
            user_agent=user_agent,
            device=device,
            network=network,
            rule=rule,
            risk_score=risk_score,
            original_log=parsed_data.get('raw_log'),
            original_fields=parsed_data
        )

        return normalized_event

