"""
Zscaler NSS Web Log Parser (v2 - Normalized)
Implements BaseParser interface with normalization to common schema
Reference: https://help.zscaler.com/zia/nss-feed-output-format-web-logs
"""
import re
import csv
from io import StringIO
from datetime import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import logging

from app.parsers.base_parser import BaseParser
from app.schemas.normalized_event import (
    NormalizedEvent, EventMetadata, Source, Destination, User,
    URL, HTTP, UserAgent, Device, Network, Rule
)

logger = logging.getLogger(__name__)


class ZscalerParserV2(BaseParser):
    """
    Parser for Zscaler NSS Web Logs with normalization
    Supports both key=value format and CSV format
    """
    
    def __init__(self):
        super().__init__()
        self.vendor = "zscaler"
        self.product = "zia"
        self.log_type = "zscaler"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[Dict[str, Any]]:
        """Parse a single Zscaler log line"""
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return None
        
        try:
            # Try key=value format first
            if '=' in line and not line.startswith('"'):
                return self._parse_key_value_format(line)
            # Try CSV format
            elif ',' in line or '\t' in line:
                return self._parse_csv_format(line)
            else:
                logger.warning(f"Line {line_number}: Unknown format")
                return None
                
        except Exception as e:
            logger.error(f"Line {line_number}: Parse error: {e}")
            return None
    
    def _parse_csv_format(self, line: str) -> Dict[str, Any]:
        """Parse Zscaler NSS Web Log CSV format"""
        reader = csv.reader(StringIO(line))
        values = next(reader)
        
        # Standard Zscaler NSS Web Log field order
        field_order = [
            'timestamp', 'username', 'app_protocol', 'url', 'action',
            'app_name', 'app_class', 'source_bytes', 'destination_bytes',
            'req_header_size', 'resp_header_size', 'url_class',
            'url_super_category', 'url_category', 'malware_category',
            'malware_class', 'threat_name', 'risk_score', 'dlp_engine',
            'dlp_dictionary', 'realm', 'department', 'source_ip',
            'destination_ip', 'request_method', 'response_code',
            'user_agent', 'product', 'rule_label', 'rule_type',
            'file_type', 'file_subtype', 'unscannable_type',
            'device_owner', 'device_hostname'
        ]
        
        parsed = {'raw_log': line}
        for i, value in enumerate(values):
            if i < len(field_order):
                field_name = field_order[i]
                parsed[field_name] = self.normalize_value(value)
        
        # Special handling for threat_name
        if not parsed.get('threat_name'):
            parsed['threat_name'] = 'UNKNOWN'
        
        return parsed
    
    def _parse_key_value_format(self, line: str) -> Dict[str, Any]:
        """Parse key=value format"""
        parsed = {'raw_log': line}
        pattern = r'(\w+)=(?:"([^"]*)"|([^\s]*))'
        matches = re.findall(pattern, line)
        
        for key, quoted_value, unquoted_value in matches:
            value = quoted_value if quoted_value else unquoted_value
            parsed[key] = self.normalize_value(value)
        
        return parsed
    
    def normalize(self, parsed_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Convert Zscaler-specific fields to normalized event schema
        """
        # Parse timestamp
        timestamp = self.parse_timestamp(
            parsed_data.get('timestamp', ''),
            formats=[
                "%a %b %d %H:%M:%S %Y",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ"
            ]
        )
        if not timestamp:
            timestamp = datetime.utcnow()
        
        # Determine event category and action
        action = parsed_data.get('action', 'unknown').lower()
        threat_name = parsed_data.get('threat_name', 'UNKNOWN')
        
        if threat_name and threat_name != 'UNKNOWN':
            category = "threat"
            event_type = ["connection", "denied", "threat"]
        elif action in ['blocked', 'denied']:
            category = "web"
            event_type = ["connection", "denied"]
        else:
            category = "web"
            event_type = ["connection", "allowed"]
        
        # Create event metadata
        event_meta = EventMetadata(
            category=category,
            action=action,
            outcome="success" if action == "allowed" else "failure",
            severity=self.safe_int(parsed_data.get('risk_score', 0)),
            type=event_type,
            dataset="zscaler.web",
            module="zscaler_nss"
        )
        
        # Create source (client)
        source = Source(
            ip=parsed_data.get('source_ip'),
            bytes=self.safe_int(parsed_data.get('source_bytes', 0))
        )
        
        # Create destination (server)
        destination = Destination(
            ip=parsed_data.get('destination_ip'),
            bytes=self.safe_int(parsed_data.get('destination_bytes', 0)),
            domain=self.extract_domain(parsed_data.get('url', ''))
        )
        
        # Create user
        user = User(
            name=parsed_data.get('username'),
            email=parsed_data.get('username') if '@' in str(parsed_data.get('username', '')) else None,
            department=parsed_data.get('department')
        )
        
        # Create URL
        url_str = parsed_data.get('url', '')
        url_obj = None
        if url_str:
            try:
                parsed_url = urlparse(url_str if '://' in url_str else f'http://{url_str}')
                url_obj = URL(
                    original=url_str,
                    full=url_str,
                    scheme=parsed_url.scheme,
                    domain=parsed_url.netloc,
                    path=parsed_url.path,
                    query=parsed_url.query,
                    port=parsed_url.port
                )
            except:
                url_obj = URL(original=url_str)
        
        # Create HTTP
        http = HTTP(
            request_method=parsed_data.get('request_method'),
            request_body_bytes=self.safe_int(parsed_data.get('source_bytes', 0)),
            response_status_code=self.safe_int(parsed_data.get('response_code', 0)),
            response_body_bytes=self.safe_int(parsed_data.get('destination_bytes', 0))
        )
        
        # Create user agent
        user_agent_str = parsed_data.get('user_agent')
        user_agent = UserAgent(original=user_agent_str) if user_agent_str else None
        
        # Create device
        device = Device(
            hostname=parsed_data.get('device_hostname'),
            id=parsed_data.get('device_owner')
        )
        
        # Create network
        network = Network(
            protocol=parsed_data.get('app_protocol', '').lower(),
            application=parsed_data.get('app_name')
        )
        
        # Create rule (if applicable)
        rule = None
        if parsed_data.get('rule_label') or parsed_data.get('rule_type'):
            rule = Rule(
                name=parsed_data.get('rule_label'),
                category=parsed_data.get('rule_type')
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
            risk_score=self.safe_int(parsed_data.get('risk_score', 0)),
            original_log=parsed_data.get('raw_log'),
            original_fields=parsed_data
        )
        
        return normalized_event
    
    def detect_format(self, sample_lines: List[str]) -> bool:
        """Auto-detect if this is a Zscaler log"""
        for line in sample_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check for Zscaler-specific fields
            zscaler_indicators = [
                'urlcat=', 'urlclass=', 'appname=', 'threatname=',
                'riskscore=', 'dlpeng=', 'deviceowner='
            ]
            
            # Key-value format detection
            if any(indicator in line for indicator in zscaler_indicators):
                return True
            
            # CSV format detection - check if it has the right number of fields
            if ',' in line:
                try:
                    reader = csv.reader(StringIO(line))
                    values = next(reader)
                    # Zscaler NSS typically has 33-35 fields
                    if 30 <= len(values) <= 40:
                        # Check if first field looks like a timestamp
                        if any(month in values[0] for month in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']):
                            return True
                except:
                    pass
        
        return False

