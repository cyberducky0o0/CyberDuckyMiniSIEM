"""
Log Parser Service
Orchestrates log file parsing and database insertion
Supports multiple log sources via parser factory
Dual storage: Legacy LogEntry + New NormalizedEvent for cross-source correlation
"""
import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime
from app.models.log_file import LogFile
from app.models.log_entry import LogEntry
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.log_file_repository import LogFileRepository
from app.parsers.parser_factory import ParserFactory
from app.parsers.zscaler_parser import ZscalerParser  # Legacy support
from app.parsers.base_parser import BaseParser
from app.services.enrichment_service import EnrichmentService
from app.schemas.normalized_event import NormalizedEvent
from app.extensions import db

logger = logging.getLogger(__name__)

class LogParserService:
    """Service for parsing log files with multi-source support"""

    def __init__(self):
        self.log_file_repo = LogFileRepository()
        self.enrichment_service = EnrichmentService()
        # Legacy parser for backward compatibility
        self.zscaler_parser = ZscalerParser()
    
    def parse_log_file(self, log_file_id: str) -> Dict[str, Any]:
        """
        Parse a log file and store entries in database
        
        Returns:
            Dictionary with parsing results
        """
        log_file = self.log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            raise ValueError(f"Log file {log_file_id} not found")
        
        # Update status to processing
        self.log_file_repo.update(log_file, status='processing')
        
        try:
            # Get appropriate parser based on log type (with auto-detection support)
            parser = self._get_parser(log_file.log_type, file_path=log_file.file_path)

            # Parse the file
            result = self._parse_file(log_file, parser)
            
            # Update log file with results
            self.log_file_repo.update(
                log_file,
                status='completed',
                total_entries=result['total_lines'],
                parsed_entries=result['parsed_count'],
                failed_entries=result['failed_count'],
                processed_at=datetime.utcnow()
            )
            
            logger.info(f"Successfully parsed log file {log_file_id}: "
                       f"{result['parsed_count']} entries")
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing log file {log_file_id}: {e}")
            self.log_file_repo.update(
                log_file,
                status='failed',
                error_message=str(e)
            )
            raise
    
    def _get_parser(self, log_type: str, file_path: Optional[str] = None):
        """
        Get appropriate parser for log type
        Supports both legacy and new parser architecture
        """
        # Try new parser factory first
        parser = ParserFactory.get_parser(log_type=log_type, file_path=file_path)
        if parser:
            logger.info(f"Using new parser architecture: {parser.__class__.__name__}")
            return parser

        # Fallback to legacy parser
        if log_type == 'zscaler':
            logger.info("Using legacy Zscaler parser")
            return self.zscaler_parser

        raise ValueError(f"Unsupported log type: {log_type}")

    def _filter_valid_fields(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter parsed data to only include fields that exist in LogEntry model
        """
        # Valid LogEntry fields (excluding id, log_file_id, created_at which are auto-generated)
        valid_fields = {
            'timestamp', 'record_id', 'username', 'role',
            'source_ip', 'source_post_nat_ip', 'source_bytes',
            'destination_ip', 'destination_bytes', 'hostname',
            'url', 'referer', 'request_method', 'response_code', 'user_agent',
            'content_type', 'file_type', 'file_class',
            'url_category', 'url_super_category', 'url_class',
            'app_name', 'app_class', 'app_protocol',
            'threat_name', 'malware_type', 'malware_class', 'risk_score',
            'policy', 'action', 'bypassed_traffic', 'unscannable_type',
            'dlp_dictionary', 'dlp_engine',
            'device_hostname', 'device_owner',
            'realm', 'bandwidth_throttle',
            'raw_log'
        }

        # Filter to only valid fields
        filtered = {k: v for k, v in parsed_data.items() if k in valid_fields}

        return filtered

    def _serialize_original_fields(self, original_fields: Dict[str, Any]) -> str:
        """Serialize original_fields dict to JSON, handling datetime objects"""
        if not original_fields:
            return None

        # Convert datetime objects to ISO format strings
        serializable = {}
        for key, value in original_fields.items():
            if isinstance(value, datetime):
                serializable[key] = value.isoformat()
            elif value is None:
                serializable[key] = None
            else:
                serializable[key] = value

        return json.dumps(serializable)

    def _convert_to_db_model(self, normalized_event: NormalizedEvent, log_file_id: str) -> NormalizedEventModel:
        """Convert NormalizedEvent dataclass to database model"""
        from dateutil import parser as date_parser

        # Parse timestamp
        timestamp = date_parser.parse(normalized_event.timestamp) if isinstance(normalized_event.timestamp, str) else normalized_event.timestamp

        return NormalizedEventModel(
            log_file_id=log_file_id,

            # Timestamp
            timestamp=timestamp,

            # Event metadata
            event_category=normalized_event.event.category if normalized_event.event else None,
            event_action=normalized_event.event.action if normalized_event.event else None,
            event_outcome=normalized_event.event.outcome if normalized_event.event else None,
            event_severity=normalized_event.event.severity if normalized_event.event else 0,
            event_kind=normalized_event.event.kind if normalized_event.event else 'event',
            event_type=json.dumps(normalized_event.event.type) if normalized_event.event and normalized_event.event.type else None,
            event_dataset=normalized_event.event.dataset if normalized_event.event else None,
            event_module=normalized_event.event.module if normalized_event.event else None,

            # Observer
            observer_vendor=normalized_event.observer_vendor,
            observer_product=normalized_event.observer_product,
            observer_type=normalized_event.observer_type,

            # Source
            source_ip=normalized_event.source.ip if normalized_event.source else None,
            source_port=normalized_event.source.port if normalized_event.source else None,
            source_bytes=normalized_event.source.bytes if normalized_event.source else None,
            source_geo_country=normalized_event.source.geo_country if normalized_event.source else None,
            source_geo_city=normalized_event.source.geo_city if normalized_event.source else None,

            # Destination
            destination_ip=normalized_event.destination.ip if normalized_event.destination else None,
            destination_port=normalized_event.destination.port if normalized_event.destination else None,
            destination_domain=normalized_event.destination.domain if normalized_event.destination else None,
            destination_bytes=normalized_event.destination.bytes if normalized_event.destination else None,

            # User
            user_name=normalized_event.user.name if normalized_event.user else None,
            user_email=normalized_event.user.email if normalized_event.user else None,
            user_domain=normalized_event.user.domain if normalized_event.user else None,
            user_roles=json.dumps(normalized_event.user.roles) if normalized_event.user and normalized_event.user.roles else None,

            # URL
            url_original=normalized_event.url.original if normalized_event.url else None,
            url_full=normalized_event.url.full if normalized_event.url else None,
            url_domain=normalized_event.url.domain if normalized_event.url else None,
            url_path=normalized_event.url.path if normalized_event.url else None,

            # HTTP
            http_request_method=normalized_event.http.request_method if normalized_event.http else None,
            http_request_referrer=normalized_event.http.request_referrer if normalized_event.http else None,
            http_response_status_code=normalized_event.http.response_status_code if normalized_event.http else None,
            http_response_mime_type=normalized_event.http.response_mime_type if normalized_event.http else None,

            # User Agent
            user_agent_original=normalized_event.user_agent.original if normalized_event.user_agent else None,

            # File
            file_name=normalized_event.file.name if normalized_event.file else None,
            file_size=normalized_event.file.size if normalized_event.file else None,
            file_hash_md5=normalized_event.file.hash_md5 if normalized_event.file else None,
            file_mime_type=normalized_event.file.mime_type if normalized_event.file else None,

            # Threat
            threat_framework=normalized_event.threat.framework if normalized_event.threat else None,
            threat_tactic_name=normalized_event.threat.tactic_name if normalized_event.threat else None,
            threat_technique_name=normalized_event.threat.technique_name if normalized_event.threat else None,

            # Rule
            rule_id=normalized_event.rule.id if normalized_event.rule else None,
            rule_name=normalized_event.rule.name if normalized_event.rule else None,
            rule_category=normalized_event.rule.category if normalized_event.rule else None,

            # Device
            device_hostname=normalized_event.device.hostname if normalized_event.device else None,
            device_id=normalized_event.device.id if normalized_event.device else None,
            device_os_name=normalized_event.device.os_name if normalized_event.device else None,

            # Network
            network_protocol=normalized_event.network.protocol if normalized_event.network else None,
            network_transport=normalized_event.network.transport if normalized_event.network else None,
            network_application=normalized_event.network.application if normalized_event.network else None,
            network_bytes=normalized_event.network.bytes if normalized_event.network else None,

            # Risk
            risk_score=normalized_event.risk_score,
            risk_score_norm=normalized_event.risk_score_norm,

            # Original data
            original_log=normalized_event.original_log,
            original_fields=self._serialize_original_fields(normalized_event.original_fields),

            # Metadata
            ingestion_timestamp=datetime.utcnow(),
            pipeline_version=normalized_event.pipeline_version
        )

    def _convert_to_legacy_entry(self, normalized_event: NormalizedEvent, log_file_id: str) -> Optional[LogEntry]:
        """Convert NormalizedEvent to legacy LogEntry (for Zscaler backward compatibility)"""
        from dateutil import parser as date_parser

        # Only convert Zscaler events to legacy format
        if normalized_event.observer_vendor != 'zscaler':
            return None

        # Parse timestamp
        timestamp = date_parser.parse(normalized_event.timestamp) if isinstance(normalized_event.timestamp, str) else normalized_event.timestamp

        # Extract Zscaler-specific fields from original_fields
        original_fields = normalized_event.original_fields or {}

        return LogEntry(
            log_file_id=log_file_id,
            timestamp=timestamp,
            username=normalized_event.user.name if normalized_event.user else None,
            source_ip=normalized_event.source.ip if normalized_event.source else None,
            source_bytes=normalized_event.source.bytes if normalized_event.source else None,
            destination_ip=normalized_event.destination.ip if normalized_event.destination else None,
            destination_bytes=normalized_event.destination.bytes if normalized_event.destination else None,
            hostname=normalized_event.destination.domain if normalized_event.destination else None,
            url=normalized_event.url.original if normalized_event.url else None,
            referer=normalized_event.http.request_referrer if normalized_event.http else None,
            request_method=normalized_event.http.request_method if normalized_event.http else None,
            response_code=normalized_event.http.response_status_code if normalized_event.http else None,
            user_agent=normalized_event.user_agent.original if normalized_event.user_agent else None,
            threat_name=original_fields.get('threat_name', 'UNKNOWN'),
            risk_score=normalized_event.risk_score,
            action=normalized_event.event.action if normalized_event.event else None,
            device_hostname=normalized_event.device.hostname if normalized_event.device else None,
            raw_log=normalized_event.original_log,
            # Map other Zscaler-specific fields from original_fields
            role=original_fields.get('role'),
            url_category=original_fields.get('url_category'),
            url_super_category=original_fields.get('url_super_category'),
            app_name=original_fields.get('app_name'),
            policy=original_fields.get('policy'),
            bypassed_traffic=original_fields.get('bypassed_traffic', False)
        )

    def _parse_file(self, log_file: LogFile, parser) -> Dict[str, Any]:
        """
        Parse file and insert entries into database
        Supports dual storage: Legacy LogEntry + New NormalizedEvent
        """
        total_lines = 0
        parsed_count = 0
        failed_count = 0
        normalized_count = 0

        legacy_entries = []
        normalized_entries = []
        batch_size = 1000  # Insert in batches for performance

        # Check if parser supports normalization (new architecture)
        supports_normalization = isinstance(parser, BaseParser) and hasattr(parser, 'process_line')

        try:
            with open(log_file.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    total_lines += 1

                    # NEW ARCHITECTURE: Use process_line for full pipeline
                    if supports_normalization:
                        try:
                            # Full pipeline: Parse → Normalize → Enrich → Validate
                            normalized_event = parser.process_line(line, line_number)

                            if normalized_event:
                                # Convert NormalizedEvent dataclass to database model
                                normalized_db_entry = self._convert_to_db_model(
                                    normalized_event,
                                    log_file.id
                                )
                                normalized_entries.append(normalized_db_entry)
                                normalized_count += 1

                                # Also create legacy LogEntry for backward compatibility
                                # (only for Zscaler logs for now)
                                if normalized_event.observer_vendor == 'zscaler':
                                    legacy_entry = self._convert_to_legacy_entry(
                                        normalized_event,
                                        log_file.id
                                    )
                                    if legacy_entry:
                                        legacy_entries.append(legacy_entry)
                                        parsed_count += 1
                            else:
                                failed_count += 1

                        except Exception as e:
                            logger.warning(f"Error processing line {line_number}: {e}")
                            failed_count += 1

                    # LEGACY ARCHITECTURE: Use old parse_line method
                    else:
                        parsed_data = parser.parse_line(line, line_number)

                        if parsed_data:
                            # Validate and enrich
                            parsed_data = parser.enrich_entry(parsed_data)

                            if parser.validate_entry(parsed_data):
                                # Filter out fields that don't exist in LogEntry model
                                valid_fields = self._filter_valid_fields(parsed_data)

                                # Create LogEntry object
                                entry = LogEntry(
                                    log_file_id=log_file.id,
                                    **valid_fields
                                )
                                legacy_entries.append(entry)
                                parsed_count += 1
                            else:
                                failed_count += 1

                    # Batch insert for both legacy and normalized
                    if len(legacy_entries) >= batch_size or len(normalized_entries) >= batch_size:
                        if legacy_entries:
                            db.session.bulk_save_objects(legacy_entries)
                            logger.info(f"Inserted batch of {len(legacy_entries)} legacy entries")
                            legacy_entries = []
                        if normalized_entries:
                            db.session.bulk_save_objects(normalized_entries)
                            logger.info(f"Inserted batch of {len(normalized_entries)} normalized entries")
                            normalized_entries = []
                        db.session.commit()

            # Insert remaining entries
            if legacy_entries or normalized_entries:
                if legacy_entries:
                    db.session.bulk_save_objects(legacy_entries)
                    logger.info(f"Inserted final batch of {len(legacy_entries)} legacy entries")
                if normalized_entries:
                    db.session.bulk_save_objects(normalized_entries)
                    logger.info(f"Inserted final batch of {len(normalized_entries)} normalized entries")
                db.session.commit()

        except Exception as e:
            logger.error(f"Error reading file {log_file.file_path}: {e}")
            db.session.rollback()
            raise

        return {
            'total_lines': total_lines,
            'parsed_count': parsed_count,
            'failed_count': failed_count,
            'normalized_count': normalized_count
        }

