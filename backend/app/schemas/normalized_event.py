"""
Normalized Event Schema (ECS-inspired)
Common schema for all log sources to enable cross-source correlation and analysis
Based on Elastic Common Schema (ECS) and OCSF principles
"""
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum


class EventCategory(Enum):
    """Event categories following ECS"""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    WEB = "web"
    FILE = "file"
    PROCESS = "process"
    MALWARE = "malware"
    INTRUSION_DETECTION = "intrusion_detection"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    IAM = "iam"


class EventOutcome(Enum):
    """Event outcomes"""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventAction(Enum):
    """Common event actions"""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    DENIED = "denied"
    DETECTED = "detected"
    QUARANTINED = "quarantined"
    DELETED = "deleted"
    CREATED = "created"
    MODIFIED = "modified"
    ACCESSED = "accessed"


@dataclass
class EventMetadata:
    """Core event metadata"""
    category: str  # EventCategory
    action: str  # What happened
    outcome: str = "unknown"  # EventOutcome
    severity: int = 0  # 0-100 severity score
    kind: str = "event"  # event, alert, metric, state
    type: List[str] = field(default_factory=list)  # connection, access, info, etc.
    dataset: str = ""  # Source dataset (e.g., "zscaler.web", "crowdstrike.edr")
    module: str = ""  # Integration module name


@dataclass
class Source:
    """Source information (client/attacker)"""
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_location: Optional[Dict[str, float]] = None  # lat, lon
    as_number: Optional[int] = None
    as_organization: Optional[str] = None


@dataclass
class Destination:
    """Destination information (server/target)"""
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    domain: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_location: Optional[Dict[str, float]] = None


@dataclass
class User:
    """User/identity information"""
    name: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    id: Optional[str] = None
    full_name: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    group: Optional[str] = None
    department: Optional[str] = None


@dataclass
class URL:
    """URL information"""
    original: Optional[str] = None
    full: Optional[str] = None
    scheme: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    port: Optional[int] = None


@dataclass
class HTTP:
    """HTTP request/response details"""
    request_method: Optional[str] = None
    request_body_bytes: Optional[int] = None
    request_referrer: Optional[str] = None
    response_status_code: Optional[int] = None
    response_body_bytes: Optional[int] = None
    response_mime_type: Optional[str] = None
    version: Optional[str] = None


@dataclass
class UserAgent:
    """User agent details"""
    original: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    device_name: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None


@dataclass
class File:
    """File information"""
    name: Optional[str] = None
    path: Optional[str] = None
    extension: Optional[str] = None
    size: Optional[int] = None
    mime_type: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None


@dataclass
class Threat:
    """Threat intelligence information"""
    framework: Optional[str] = None  # MITRE ATT&CK, etc.
    tactic: List[str] = field(default_factory=list)  # Initial Access, Execution, etc.
    technique: List[str] = field(default_factory=list)  # T1566, T1059, etc.
    software: Optional[str] = None
    indicator_type: Optional[str] = None  # domain, ip, hash, url
    indicator_value: Optional[str] = None
    enrichment: Dict[str, Any] = field(default_factory=dict)  # Threat intel enrichment


@dataclass
class Rule:
    """Detection rule information"""
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    ruleset: Optional[str] = None
    version: Optional[str] = None


@dataclass
class Device:
    """Device/host information"""
    hostname: Optional[str] = None
    id: Optional[str] = None
    mac: Optional[str] = None
    ip: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    type: Optional[str] = None  # server, workstation, mobile, etc.


@dataclass
class Network:
    """Network layer information"""
    protocol: Optional[str] = None  # tcp, udp, icmp
    transport: Optional[str] = None  # tcp, udp
    application: Optional[str] = None  # http, dns, ssh
    direction: Optional[str] = None  # inbound, outbound, internal
    bytes: Optional[int] = None
    packets: Optional[int] = None
    community_id: Optional[str] = None  # Network flow hash


@dataclass
class NormalizedEvent:
    """
    Normalized event structure - the universal format for all log sources
    This enables cross-source correlation, unified detection rules, and consistent analysis
    """
    # Core fields (required)
    timestamp: datetime
    event: EventMetadata
    
    # Source system
    observer_vendor: str  # zscaler, crowdstrike, okta, aws, etc.
    observer_product: str  # zia, falcon, sso, cloudtrail, etc.
    observer_type: str  # proxy, edr, idp, cloud, etc.
    
    # Optional enriched fields
    source: Optional[Source] = None
    destination: Optional[Destination] = None
    user: Optional[User] = None
    url: Optional[URL] = None
    http: Optional[HTTP] = None
    user_agent: Optional[UserAgent] = None
    file: Optional[File] = None
    threat: Optional[Threat] = None
    rule: Optional[Rule] = None
    device: Optional[Device] = None
    network: Optional[Network] = None
    
    # Risk scoring
    risk_score: int = 0  # 0-100
    risk_score_norm: float = 0.0  # 0.0-1.0 normalized
    
    # Original data
    original_log: Optional[str] = None
    original_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    ingestion_timestamp: datetime = field(default_factory=datetime.utcnow)
    pipeline_version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {}
        for key, value in asdict(self).items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                elif isinstance(value, Enum):
                    result[key] = value.value
                else:
                    result[key] = value
        return result
    
    def get_correlation_keys(self) -> Dict[str, Any]:
        """
        Extract key fields for correlation across events
        Used for UEBA, lateral movement detection, etc.
        """
        return {
            'user_name': self.user.name if self.user else None,
            'source_ip': self.source.ip if self.source else None,
            'destination_ip': self.destination.ip if self.destination else None,
            'device_hostname': self.device.hostname if self.device else None,
            'url_domain': self.url.domain if self.url else None,
        }

