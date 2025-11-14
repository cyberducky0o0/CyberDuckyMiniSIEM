"""
LogEntry model - represents individual parsed log entries from Zscaler NSS Web Logs
Comprehensive field mapping based on Zscaler documentation
"""
from app.extensions import db
from datetime import datetime
import uuid

class LogEntry(db.Model):
    __tablename__ = 'log_entries'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    log_file_id = db.Column(db.String(36), db.ForeignKey('log_files.id'), nullable=False, index=True)
    
    # Core timestamp and identification
    timestamp = db.Column(db.DateTime, nullable=False, index=True)  # devTime
    record_id = db.Column(db.String(100), index=True)  # recordid - unique log record ID
    
    # User and authentication
    username = db.Column(db.String(255), index=True)  # usrName
    role = db.Column(db.String(100))  # role - user role/department
    
    # Network - Source
    source_ip = db.Column(db.String(45), index=True)  # src - client IP (pre-NAT)
    source_post_nat_ip = db.Column(db.String(45))  # srcPostNAT - client IP after NAT
    source_bytes = db.Column(db.BigInteger)  # srcBytes - request size
    
    # Network - Destination
    destination_ip = db.Column(db.String(45))  # dst - destination IP
    destination_bytes = db.Column(db.BigInteger)  # dstBytes - response size
    hostname = db.Column(db.String(500), index=True)  # hostname - destination hostname
    
    # URL and Request Details
    url = db.Column(db.Text)  # url - full URL requested
    referer = db.Column(db.Text)  # referer - HTTP referrer
    request_method = db.Column(db.String(20))  # reqmethod - GET, POST, etc.
    response_code = db.Column(db.Integer, index=True)  # respcode - HTTP response code
    user_agent = db.Column(db.Text)  # useragent - client browser/agent
    
    # Content Classification
    content_type = db.Column(db.String(100))  # contenttype - MIME type
    file_type = db.Column(db.String(50))  # filetype - file type when applicable
    file_class = db.Column(db.String(50))  # fileclass - file classification
    
    # URL Categorization (Critical for SOC)
    url_category = db.Column(db.String(100), index=True)  # urlcategory
    url_super_category = db.Column(db.String(100), index=True)  # urlsupercategory
    url_class = db.Column(db.String(100), index=True)  # urlclass
    
    # Application Classification
    app_name = db.Column(db.String(100), index=True)  # appname
    app_class = db.Column(db.String(100))  # appclass
    app_protocol = db.Column(db.String(50))  # appproto - HTTP/HTTPS etc
    
    # Threat Detection (Critical for SOC)
    threat_name = db.Column(db.String(255), index=True)  # threatname - threat identifier
    malware_type = db.Column(db.String(100), index=True)  # malwaretype
    malware_class = db.Column(db.String(100), index=True)  # malwareclass
    risk_score = db.Column(db.Integer, index=True)  # riskscore - numeric risk score
    
    # Policy and Security
    policy = db.Column(db.String(255))  # policy - policy triggered
    action = db.Column(db.String(50), index=True)  # action taken (allowed, blocked, etc.)
    bypassed_traffic = db.Column(db.Boolean, default=False, index=True)  # bypassedtraffic
    unscannable_type = db.Column(db.String(100))  # unscannabletype - if content unscannable
    
    # DLP (Data Loss Prevention)
    dlp_dictionary = db.Column(db.String(255))  # dlpdict
    dlp_engine = db.Column(db.String(255))  # dlpeng
    
    # Device and Endpoint
    device_hostname = db.Column(db.String(255), index=True)  # devicehostname
    device_owner = db.Column(db.String(255), index=True)  # deviceowner
    
    # Location and Network Context
    realm = db.Column(db.String(100))  # realm - location/policy realm
    bandwidth_throttle = db.Column(db.String(50))  # bwthrottle
    
    # Metadata
    raw_log = db.Column(db.Text)  # Store original log line for reference
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    anomalies = db.relationship('Anomaly', backref='log_entry', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self, include_raw=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'log_file_id': self.log_file_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'record_id': self.record_id,
            
            # User
            'username': self.username,
            'role': self.role,
            
            # Network
            'source_ip': self.source_ip,
            'source_post_nat_ip': self.source_post_nat_ip,
            'source_bytes': self.source_bytes,
            'destination_ip': self.destination_ip,
            'destination_bytes': self.destination_bytes,
            'hostname': self.hostname,
            
            # Request
            'url': self.url,
            'referer': self.referer,
            'request_method': self.request_method,
            'response_code': self.response_code,
            'user_agent': self.user_agent,
            
            # Content
            'content_type': self.content_type,
            'file_type': self.file_type,
            'file_class': self.file_class,
            
            # Categorization
            'url_category': self.url_category,
            'url_super_category': self.url_super_category,
            'url_class': self.url_class,
            'app_name': self.app_name,
            'app_class': self.app_class,
            'app_protocol': self.app_protocol,
            
            # Threats
            'threat_name': self.threat_name,
            'malware_type': self.malware_type,
            'malware_class': self.malware_class,
            'risk_score': self.risk_score,
            
            # Policy
            'policy': self.policy,
            'action': self.action,
            'bypassed_traffic': self.bypassed_traffic,
            'unscannable_type': self.unscannable_type,
            
            # DLP
            'dlp_dictionary': self.dlp_dictionary,
            'dlp_engine': self.dlp_engine,
            
            # Device
            'device_hostname': self.device_hostname,
            'device_owner': self.device_owner,
            
            # Context
            'realm': self.realm,
            'bandwidth_throttle': self.bandwidth_throttle,
            
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_raw:
            data['raw_log'] = self.raw_log
        
        return data
    
    def __repr__(self):
        return f'<LogEntry {self.record_id} - {self.username}@{self.source_ip}>'

