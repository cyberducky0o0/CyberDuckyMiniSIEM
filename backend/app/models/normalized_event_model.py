"""
NormalizedEvent Database Model
Stores normalized events from all log sources in a common schema
Enables cross-source correlation and unified detection rules
Based on Elastic Common Schema (ECS) principles
"""
from app.extensions import db
from datetime import datetime
import uuid
import json

class NormalizedEventModel(db.Model):
    """
    Universal event storage for multi-source log analysis
    Supports correlation across Zscaler, CrowdStrike, Okta, AWS, etc.
    """
    __tablename__ = 'normalized_events'
    
    # Primary identification
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    log_file_id = db.Column(db.String(36), db.ForeignKey('log_files.id'), nullable=False, index=True)
    
    # Event metadata
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    event_category = db.Column(db.String(50), index=True)  # web, network, authentication, etc.
    event_action = db.Column(db.String(100), index=True)  # access, blocked, login, etc.
    event_outcome = db.Column(db.String(20), index=True)  # success, failure, unknown
    event_severity = db.Column(db.Integer, index=True)  # 0-100
    event_kind = db.Column(db.String(20))  # event, alert, metric, state
    event_type = db.Column(db.Text)  # JSON array: ["connection", "denied", "threat"]
    event_dataset = db.Column(db.String(100), index=True)  # zscaler.web, crowdstrike.edr, etc.
    event_module = db.Column(db.String(100))  # zscaler_nss, crowdstrike_falcon, etc.
    
    # Observer (the system that generated the log)
    observer_vendor = db.Column(db.String(100), index=True)  # zscaler, crowdstrike, okta, aws
    observer_product = db.Column(db.String(100))  # zia, falcon, okta, cloudtrail
    observer_type = db.Column(db.String(50))  # proxy, edr, idp, cloud
    
    # Source (client/attacker)
    source_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    source_mac = db.Column(db.String(17))
    source_domain = db.Column(db.String(255))
    source_bytes = db.Column(db.BigInteger)
    source_packets = db.Column(db.BigInteger)
    source_geo_country = db.Column(db.String(2))  # ISO country code
    source_geo_city = db.Column(db.String(100))
    source_geo_location = db.Column(db.String(100))  # lat,lon
    source_as_number = db.Column(db.Integer)  # Autonomous System Number
    source_as_organization = db.Column(db.String(255))
    
    # Destination (server/target)
    destination_ip = db.Column(db.String(45), index=True)
    destination_port = db.Column(db.Integer)
    destination_mac = db.Column(db.String(17))
    destination_domain = db.Column(db.String(255), index=True)
    destination_bytes = db.Column(db.BigInteger)
    destination_packets = db.Column(db.BigInteger)
    destination_geo_country = db.Column(db.String(2))
    destination_geo_city = db.Column(db.String(100))
    destination_geo_location = db.Column(db.String(100))
    
    # User
    user_name = db.Column(db.String(255), index=True)
    user_email = db.Column(db.String(255), index=True)
    user_domain = db.Column(db.String(255))
    user_id = db.Column(db.String(255))
    user_full_name = db.Column(db.String(255))
    user_roles = db.Column(db.Text)  # JSON array
    user_group = db.Column(db.String(255))
    user_department = db.Column(db.String(255))
    
    # URL (for web traffic)
    url_original = db.Column(db.Text)
    url_full = db.Column(db.Text)
    url_scheme = db.Column(db.String(10))  # http, https, ftp
    url_domain = db.Column(db.String(255), index=True)
    url_path = db.Column(db.Text)
    url_query = db.Column(db.Text)
    url_fragment = db.Column(db.String(255))
    url_port = db.Column(db.Integer)
    
    # HTTP (for web traffic)
    http_request_method = db.Column(db.String(20))  # GET, POST, etc.
    http_request_body_bytes = db.Column(db.BigInteger)
    http_request_referrer = db.Column(db.Text)
    http_response_status_code = db.Column(db.Integer, index=True)
    http_response_body_bytes = db.Column(db.BigInteger)
    http_response_mime_type = db.Column(db.String(100))
    http_version = db.Column(db.String(10))
    
    # User Agent
    user_agent_original = db.Column(db.Text)
    user_agent_name = db.Column(db.String(100))
    user_agent_version = db.Column(db.String(50))
    user_agent_device_name = db.Column(db.String(100))
    user_agent_os_name = db.Column(db.String(100))
    user_agent_os_version = db.Column(db.String(50))
    
    # File (for file-related events)
    file_name = db.Column(db.String(255))
    file_path = db.Column(db.Text)
    file_size = db.Column(db.BigInteger)
    file_hash_md5 = db.Column(db.String(32))
    file_hash_sha1 = db.Column(db.String(40))
    file_hash_sha256 = db.Column(db.String(64))
    file_mime_type = db.Column(db.String(100))
    file_extension = db.Column(db.String(20))
    
    # Threat Intelligence
    threat_framework = db.Column(db.String(50))  # MITRE ATT&CK, etc.
    threat_tactic_id = db.Column(db.String(20))  # T1566
    threat_tactic_name = db.Column(db.String(255))  # Phishing
    threat_technique_id = db.Column(db.String(20))  # T1566.001
    threat_technique_name = db.Column(db.String(255))  # Spearphishing Attachment
    threat_indicator_type = db.Column(db.String(50))  # domain, ip, hash, url
    threat_indicator_value = db.Column(db.Text)
    threat_enrichment = db.Column(db.Text)  # JSON: threat intel data
    
    # Rule/Policy
    rule_id = db.Column(db.String(255))
    rule_name = db.Column(db.String(255), index=True)
    rule_description = db.Column(db.Text)
    rule_category = db.Column(db.String(100))
    rule_ruleset = db.Column(db.String(255))
    rule_version = db.Column(db.String(50))
    
    # Device/Host
    device_hostname = db.Column(db.String(255), index=True)
    device_id = db.Column(db.String(255), index=True)
    device_mac = db.Column(db.String(17))
    device_ip = db.Column(db.String(45))
    device_os_name = db.Column(db.String(100))
    device_os_version = db.Column(db.String(50))
    device_type = db.Column(db.String(50))  # laptop, server, mobile, etc.
    
    # Network
    network_protocol = db.Column(db.String(20), index=True)  # http, https, dns, smtp
    network_transport = db.Column(db.String(10))  # tcp, udp
    network_application = db.Column(db.String(100))  # Web Browsing, Email, etc.
    network_direction = db.Column(db.String(20))  # inbound, outbound, internal
    network_bytes = db.Column(db.BigInteger)
    network_packets = db.Column(db.BigInteger)
    network_community_id = db.Column(db.String(100))  # Network flow hash
    
    # Risk and Scoring
    risk_score = db.Column(db.Integer, index=True)  # 0-100
    risk_score_norm = db.Column(db.Float)  # 0.0-1.0 normalized
    
    # Original data preservation
    original_log = db.Column(db.Text)  # Original raw log line
    original_fields = db.Column(db.Text)  # JSON: vendor-specific fields
    
    # Metadata
    ingestion_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    pipeline_version = db.Column(db.String(20))  # Track schema version
    
    # Relationships
    anomalies = db.relationship('Anomaly', backref='normalized_event', lazy='dynamic', 
                               foreign_keys='Anomaly.normalized_event_id')
    
    # Indexes for common correlation queries
    __table_args__ = (
        db.Index('idx_user_time', 'user_name', 'timestamp'),
        db.Index('idx_source_ip_time', 'source_ip', 'timestamp'),
        db.Index('idx_device_time', 'device_id', 'timestamp'),
        db.Index('idx_domain_time', 'destination_domain', 'timestamp'),
        db.Index('idx_event_category_severity', 'event_category', 'event_severity'),
        db.Index('idx_observer_dataset', 'observer_vendor', 'event_dataset'),
    )
    
    def to_dict(self, include_original=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'log_file_id': self.log_file_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            
            # Event
            'event': {
                'category': self.event_category,
                'action': self.event_action,
                'outcome': self.event_outcome,
                'severity': self.event_severity,
                'kind': self.event_kind,
                'type': json.loads(self.event_type) if self.event_type else [],
                'dataset': self.event_dataset,
                'module': self.event_module
            },
            
            # Observer
            'observer': {
                'vendor': self.observer_vendor,
                'product': self.observer_product,
                'type': self.observer_type
            },
            
            # Source
            'source': {
                'ip': self.source_ip,
                'port': self.source_port,
                'bytes': self.source_bytes,
                'geo': {
                    'country': self.source_geo_country,
                    'city': self.source_geo_city
                } if self.source_geo_country else None
            },
            
            # Destination
            'destination': {
                'ip': self.destination_ip,
                'port': self.destination_port,
                'domain': self.destination_domain,
                'bytes': self.destination_bytes
            },
            
            # User
            'user': {
                'name': self.user_name,
                'email': self.user_email,
                'department': self.user_department
            },
            
            # URL
            'url': {
                'original': self.url_original,
                'domain': self.url_domain,
                'path': self.url_path
            } if self.url_original else None,
            
            # HTTP
            'http': {
                'request': {
                    'method': self.http_request_method
                },
                'response': {
                    'status_code': self.http_response_status_code
                }
            } if self.http_request_method else None,
            
            # Device
            'device': {
                'hostname': self.device_hostname,
                'id': self.device_id,
                'os': {
                    'name': self.device_os_name,
                    'version': self.device_os_version
                } if self.device_os_name else None
            },
            
            # Risk
            'risk_score': self.risk_score,
            'risk_score_norm': self.risk_score_norm,
            
            # Metadata
            'ingestion_timestamp': self.ingestion_timestamp.isoformat() if self.ingestion_timestamp else None
        }
        
        if include_original:
            data['original_log'] = self.original_log
            data['original_fields'] = json.loads(self.original_fields) if self.original_fields else {}
        
        return data
    
    def __repr__(self):
        return f'<NormalizedEvent {self.event_dataset} - {self.user_name}@{self.source_ip}>'

