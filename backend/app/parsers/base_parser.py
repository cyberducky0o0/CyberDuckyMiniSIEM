"""
Base Parser Interface
All log parsers must implement this interface for consistency and extensibility
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from app.schemas.normalized_event import (
    NormalizedEvent, EventMetadata, Source, Destination, User,
    URL, HTTP, UserAgent, File, Threat, Rule, Device, Network
)

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for all log parsers
    
    Pipeline: Raw Log → Parse → Normalize → Enrich → Validate
    """
    
    def __init__(self):
        self.parser_name = self.__class__.__name__
        self.vendor = "unknown"
        self.product = "unknown"
        self.log_type = "unknown"
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int = 0) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line into a dictionary of raw fields
        
        Args:
            line: Raw log line
            line_number: Line number in file (for error reporting)
            
        Returns:
            Dictionary of parsed fields, or None if line should be skipped
        """
        pass
    
    @abstractmethod
    def normalize(self, parsed_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Convert vendor-specific parsed data into normalized event schema
        
        Args:
            parsed_data: Dictionary from parse_line()
            
        Returns:
            NormalizedEvent object with standardized fields
        """
        pass
    
    def enrich(self, normalized_event: NormalizedEvent) -> NormalizedEvent:
        """
        Enrich normalized event with additional context
        Override this method to add vendor-specific enrichment
        
        Args:
            normalized_event: Normalized event to enrich
            
        Returns:
            Enriched NormalizedEvent
        """
        # Base enrichment - can be overridden
        return normalized_event
    
    def validate(self, normalized_event: NormalizedEvent) -> bool:
        """
        Validate that normalized event has required fields
        
        Args:
            normalized_event: Event to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Required fields
            if not normalized_event.timestamp:
                logger.warning(f"{self.parser_name}: Missing timestamp")
                return False
            
            if not normalized_event.event:
                logger.warning(f"{self.parser_name}: Missing event metadata")
                return False
            
            if not normalized_event.observer_vendor:
                logger.warning(f"{self.parser_name}: Missing observer vendor")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"{self.parser_name}: Validation error: {e}")
            return False
    
    def process_line(self, line: str, line_number: int = 0) -> Optional[NormalizedEvent]:
        """
        Full pipeline: Parse → Normalize → Enrich → Validate

        Args:
            line: Raw log line
            line_number: Line number in file

        Returns:
            Validated NormalizedEvent or None if processing failed
        """
        try:
            # Step 1: Parse
            parsed_data = self.parse_line(line, line_number)
            if not parsed_data:
                return None

            # Step 2: Normalize
            normalized_event = self.normalize(parsed_data)

            # If normalize returns None, this is a legacy parser
            # that doesn't support the normalization pipeline
            if normalized_event is None:
                return None

            # Step 3: Enrich
            normalized_event = self.enrich(normalized_event)

            # Step 4: Validate
            if not self.validate(normalized_event):
                logger.warning(f"{self.parser_name}: Event validation failed at line {line_number}")
                return None

            return normalized_event

        except Exception as e:
            logger.error(f"{self.parser_name}: Error processing line {line_number}: {e}")
            return None
    
    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Auto-detect if this parser can handle the given log format
        Override this for auto-detection capability
        
        Args:
            sample_lines: First few lines of the log file
            
        Returns:
            True if this parser can handle the format
        """
        return False
    
    def get_parser_info(self) -> Dict[str, str]:
        """Get parser metadata"""
        return {
            'name': self.parser_name,
            'vendor': self.vendor,
            'product': self.product,
            'log_type': self.log_type,
            'version': '1.0'
        }
    
    # Helper methods for common parsing tasks
    
    @staticmethod
    def parse_timestamp(timestamp_str: str, formats: List[str] = None) -> Optional[datetime]:
        """
        Parse timestamp from various formats
        
        Args:
            timestamp_str: Timestamp string
            formats: List of datetime format strings to try
            
        Returns:
            datetime object or None
        """
        if not timestamp_str:
            return None
        
        # Default formats to try
        if not formats:
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%d/%b/%Y:%H:%M:%S",
                "%b %d %H:%M:%S",
                "%a %b %d %H:%M:%S %Y",
            ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return None
    
    @staticmethod
    def safe_int(value: Any, default: int = 0) -> int:
        """Safely convert value to int"""
        try:
            if value is None or value == '' or value == '-':
                return default
            return int(value)
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def safe_float(value: Any, default: float = 0.0) -> float:
        """Safely convert value to float"""
        try:
            if value is None or value == '' or value == '-':
                return default
            return float(value)
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def normalize_value(value: Any) -> Any:
        """Normalize common null/empty values"""
        if value in [None, '', '-', 'null', 'None', 'N/A', 'NA', 'UNKNOWN']:
            return None
        return value
    
    @staticmethod
    def extract_domain(url_or_hostname: str) -> Optional[str]:
        """Extract domain from URL or hostname"""
        if not url_or_hostname:
            return None
        
        # Remove protocol
        if '://' in url_or_hostname:
            url_or_hostname = url_or_hostname.split('://', 1)[1]
        
        # Remove path
        if '/' in url_or_hostname:
            url_or_hostname = url_or_hostname.split('/', 1)[0]
        
        # Remove port
        if ':' in url_or_hostname:
            url_or_hostname = url_or_hostname.split(':', 1)[0]
        
        return url_or_hostname if url_or_hostname else None
    
    @staticmethod
    def calculate_risk_score(factors: Dict[str, int]) -> int:
        """
        Calculate risk score from multiple factors
        
        Args:
            factors: Dict of factor_name: score (0-100)
            
        Returns:
            Weighted risk score (0-100)
        """
        if not factors:
            return 0
        
        # Simple average for now - can be made more sophisticated
        total = sum(factors.values())
        count = len(factors)
        return min(100, max(0, total // count))

