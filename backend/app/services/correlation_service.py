"""
Correlation Service
Enables cross-source log correlation for SOC analysts
Correlates events across Zscaler, CrowdStrike, Okta, AWS, etc.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from app.repositories.normalized_event_repository import NormalizedEventRepository
from app.models.normalized_event_model import NormalizedEventModel

logger = logging.getLogger(__name__)

class CorrelationService:
    """
    Cross-source correlation service for SOC analysts
    Enables investigation across multiple log sources using normalized schema
    """
    
    def __init__(self):
        self.event_repo = NormalizedEventRepository()
    
    # ========== User-Centric Correlation ==========
    
    def investigate_user(self, username: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Complete user investigation across all log sources
        Returns timeline, statistics, and anomalies
        """
        events = self.event_repo.get_by_user(username, time_window_hours)
        
        if not events:
            return {
                'user': username,
                'event_count': 0,
                'events': [],
                'sources': [],
                'anomalies': []
            }
        
        # Group events by source
        sources = {}
        for event in events:
            vendor = event.observer_vendor
            if vendor not in sources:
                sources[vendor] = {
                    'vendor': vendor,
                    'product': event.observer_product,
                    'event_count': 0,
                    'categories': set()
                }
            sources[vendor]['event_count'] += 1
            if event.event_category:
                sources[vendor]['categories'].add(event.event_category)
        
        # Convert sets to lists for JSON serialization
        for vendor in sources:
            sources[vendor]['categories'] = list(sources[vendor]['categories'])
        
        # Detect anomalies
        anomalies = self._detect_user_anomalies(events, username)
        
        return {
            'user': username,
            'event_count': len(events),
            'time_window_hours': time_window_hours,
            'events': [e.to_dict() for e in events[:100]],  # Limit to 100 for performance
            'sources': list(sources.values()),
            'anomalies': anomalies,
            'timeline': self._build_timeline(events)
        }
    
    def _detect_user_anomalies(self, events: List[NormalizedEventModel], username: str) -> List[Dict[str, Any]]:
        """Detect anomalies in user behavior"""
        anomalies = []
        
        # Check for impossible travel (multiple countries in short time)
        countries = {}
        for event in events:
            if event.source_geo_country:
                if event.source_geo_country not in countries:
                    countries[event.source_geo_country] = []
                countries[event.source_geo_country].append(event.timestamp)
        
        if len(countries) > 1:
            anomalies.append({
                'type': 'impossible_travel',
                'severity': 'high',
                'description': f'User {username} appeared in {len(countries)} different countries',
                'countries': list(countries.keys()),
                'recommendation': 'Investigate for compromised credentials or VPN usage'
            })
        
        # Check for high volume of failed events
        failed_events = [e for e in events if e.event_outcome == 'failure']
        if len(failed_events) > 10:
            anomalies.append({
                'type': 'high_failure_rate',
                'severity': 'medium',
                'description': f'User {username} has {len(failed_events)} failed events',
                'failed_count': len(failed_events),
                'recommendation': 'Check for authentication issues or potential account compromise'
            })
        
        # Check for high-severity events
        high_severity = [e for e in events if e.event_severity >= 70]
        if high_severity:
            anomalies.append({
                'type': 'high_severity_events',
                'severity': 'critical',
                'description': f'User {username} has {len(high_severity)} high-severity events',
                'high_severity_count': len(high_severity),
                'recommendation': 'Immediate investigation required'
            })
        
        return anomalies
    
    # ========== IP-Centric Correlation ==========
    
    def investigate_ip(self, ip_address: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Complete IP investigation across all log sources
        Critical for threat hunting and lateral movement detection
        """
        events = self.event_repo.get_by_source_ip(ip_address, time_window_hours)
        
        if not events:
            return {
                'ip': ip_address,
                'event_count': 0,
                'events': [],
                'users': [],
                'devices': [],
                'anomalies': []
            }
        
        # Extract unique users and devices
        users = set()
        devices = set()
        for event in events:
            if event.user_name:
                users.add(event.user_name)
            if event.device_hostname:
                devices.add(event.device_hostname)
        
        # Detect anomalies
        anomalies = self._detect_ip_anomalies(events, ip_address, users, devices)
        
        return {
            'ip': ip_address,
            'event_count': len(events),
            'time_window_hours': time_window_hours,
            'events': [e.to_dict() for e in events[:100]],
            'users': list(users),
            'devices': list(devices),
            'geo_location': {
                'country': events[0].source_geo_country if events else None,
                'city': events[0].source_geo_city if events else None
            },
            'anomalies': anomalies,
            'timeline': self._build_timeline(events)
        }
    
    def _detect_ip_anomalies(self, events: List[NormalizedEventModel], ip: str, users: set, devices: set) -> List[Dict[str, Any]]:
        """Detect anomalies in IP behavior"""
        anomalies = []
        
        # Multiple users from same IP (potential lateral movement)
        if len(users) > 5:
            anomalies.append({
                'type': 'multiple_users_same_ip',
                'severity': 'medium',
                'description': f'IP {ip} used by {len(users)} different users',
                'user_count': len(users),
                'recommendation': 'Check for shared workstation or potential lateral movement'
            })
        
        # Multiple devices from same IP (potential NAT or proxy)
        if len(devices) > 10:
            anomalies.append({
                'type': 'multiple_devices_same_ip',
                'severity': 'low',
                'description': f'IP {ip} associated with {len(devices)} different devices',
                'device_count': len(devices),
                'recommendation': 'Likely NAT or proxy - verify network architecture'
            })
        
        # High-severity events from this IP
        high_severity = [e for e in events if e.event_severity >= 70]
        if high_severity:
            anomalies.append({
                'type': 'high_severity_from_ip',
                'severity': 'critical',
                'description': f'IP {ip} has {len(high_severity)} high-severity events',
                'high_severity_count': len(high_severity),
                'recommendation': 'Investigate for malicious activity'
            })
        
        return anomalies
    
    # ========== Device-Centric Correlation ==========
    
    def investigate_device(self, device_id: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Complete device investigation across all log sources
        Critical for endpoint investigation
        """
        events = self.event_repo.get_by_device(device_id, time_window_hours)
        
        if not events:
            return {
                'device': device_id,
                'event_count': 0,
                'events': [],
                'users': [],
                'anomalies': []
            }
        
        # Extract unique users
        users = set()
        for event in events:
            if event.user_name:
                users.add(event.user_name)
        
        return {
            'device': device_id,
            'event_count': len(events),
            'time_window_hours': time_window_hours,
            'events': [e.to_dict() for e in events[:100]],
            'users': list(users),
            'anomalies': [],
            'timeline': self._build_timeline(events)
        }
    
    # ========== Domain-Centric Correlation ==========
    
    def investigate_domain(self, domain: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Complete domain investigation across all log sources
        Critical for C2 detection and threat hunting
        """
        events = self.event_repo.get_by_domain(domain, time_window_hours)
        
        if not events:
            return {
                'domain': domain,
                'event_count': 0,
                'events': [],
                'users': [],
                'ips': [],
                'anomalies': []
            }
        
        # Extract unique users and IPs
        users = set()
        ips = set()
        for event in events:
            if event.user_name:
                users.add(event.user_name)
            if event.source_ip:
                ips.add(event.source_ip)
        
        # Detect anomalies
        anomalies = self._detect_domain_anomalies(events, domain, users)
        
        return {
            'domain': domain,
            'event_count': len(events),
            'time_window_hours': time_window_hours,
            'events': [e.to_dict() for e in events[:100]],
            'users': list(users),
            'ips': list(ips),
            'anomalies': anomalies,
            'timeline': self._build_timeline(events)
        }
    
    def _detect_domain_anomalies(self, events: List[NormalizedEventModel], domain: str, users: set) -> List[Dict[str, Any]]:
        """Detect anomalies in domain access patterns"""
        anomalies = []
        
        # High volume of requests to domain (potential C2 beaconing)
        if len(events) > 100:
            anomalies.append({
                'type': 'high_volume_domain_access',
                'severity': 'high',
                'description': f'Domain {domain} accessed {len(events)} times',
                'access_count': len(events),
                'recommendation': 'Check for C2 beaconing or data exfiltration'
            })
        
        # Multiple users accessing suspicious domain
        if len(users) > 10:
            anomalies.append({
                'type': 'multiple_users_same_domain',
                'severity': 'medium',
                'description': f'Domain {domain} accessed by {len(users)} different users',
                'user_count': len(users),
                'recommendation': 'Verify domain legitimacy and check for phishing campaign'
            })
        
        return anomalies
    
    # ========== Helper Methods ==========
    
    def _build_timeline(self, events: List[NormalizedEventModel]) -> List[Dict[str, Any]]:
        """Build a timeline of events for visualization"""
        timeline = []
        for event in sorted(events, key=lambda e: e.timestamp):
            timeline.append({
                'timestamp': event.timestamp.isoformat(),
                'source': event.observer_vendor,
                'category': event.event_category,
                'action': event.event_action,
                'outcome': event.event_outcome,
                'severity': event.event_severity
            })
        return timeline

