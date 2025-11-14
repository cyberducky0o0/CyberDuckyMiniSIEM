"""
Parser Factory
Auto-detects log format and returns appropriate parser
Enables multi-source log ingestion
"""
import logging
from typing import Optional, List, Type, Dict
from app.parsers.base_parser import BaseParser
from app.parsers.zscaler_parser import ZscalerParser

logger = logging.getLogger(__name__)


class ParserFactory:
    """
    Factory for creating appropriate parser based on log format
    Supports auto-detection and manual selection
    """
    
    # Registry of available parsers
    _parsers: List[Type[BaseParser]] = [
        ZscalerParser,
        # Add more parsers here as they're implemented:
        # CrowdStrikeParser,
        # OktaParser,
        # AWSCloudTrailParser,
        # PaloAltoParser,
        # etc.
    ]
    
    @classmethod
    def register_parser(cls, parser_class: Type[BaseParser]):
        """
        Register a new parser
        
        Args:
            parser_class: Parser class to register
        """
        if parser_class not in cls._parsers:
            cls._parsers.append(parser_class)
            logger.info(f"Registered parser: {parser_class.__name__}")
    
    @classmethod
    def get_parser_by_name(cls, parser_name: str) -> Optional[BaseParser]:
        """
        Get parser by name
        
        Args:
            parser_name: Name of parser (e.g., 'zscaler', 'crowdstrike')
            
        Returns:
            Parser instance or None
        """
        parser_name_lower = parser_name.lower()
        
        for parser_class in cls._parsers:
            parser = parser_class()
            if parser.log_type.lower() == parser_name_lower:
                logger.info(f"Selected parser: {parser_class.__name__}")
                return parser
        
        logger.warning(f"No parser found for: {parser_name}")
        return None
    
    @classmethod
    def auto_detect_parser(cls, file_path: str, sample_size: int = 10) -> Optional[BaseParser]:
        """
        Auto-detect appropriate parser by analyzing sample lines
        
        Args:
            file_path: Path to log file
            sample_size: Number of lines to sample for detection
            
        Returns:
            Parser instance or None
        """
        try:
            # Read sample lines
            sample_lines = []
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= sample_size:
                        break
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty and comment lines
                        sample_lines.append(line)
            
            if not sample_lines:
                logger.warning(f"No valid sample lines found in {file_path}")
                return None
            
            # Try each parser's detect_format method
            for parser_class in cls._parsers:
                parser = parser_class()
                if parser.detect_format(sample_lines):
                    logger.info(f"Auto-detected parser: {parser_class.__name__}")
                    return parser
            
            logger.warning(f"Could not auto-detect parser for {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"Error during auto-detection: {e}")
            return None
    
    @classmethod
    def get_available_parsers(cls) -> List[Dict[str, str]]:
        """
        Get list of available parsers
        
        Returns:
            List of parser info dictionaries
        """
        parsers_info = []
        for parser_class in cls._parsers:
            parser = parser_class()
            parsers_info.append(parser.get_parser_info())
        return parsers_info
    
    @classmethod
    def get_parser(cls, log_type: Optional[str] = None, file_path: Optional[str] = None) -> Optional[BaseParser]:
        """
        Get parser - try by name first, then auto-detect
        
        Args:
            log_type: Optional log type name
            file_path: Optional file path for auto-detection
            
        Returns:
            Parser instance or None
        """
        # Try by name first
        if log_type:
            parser = cls.get_parser_by_name(log_type)
            if parser:
                return parser
        
        # Try auto-detection
        if file_path:
            parser = cls.auto_detect_parser(file_path)
            if parser:
                return parser
        
        logger.error(f"Could not get parser for log_type={log_type}, file_path={file_path}")
        return None


# Example usage:
# parser = ParserFactory.get_parser(log_type='zscaler')
# parser = ParserFactory.get_parser(file_path='/path/to/unknown.log')
# parsers = ParserFactory.get_available_parsers()

