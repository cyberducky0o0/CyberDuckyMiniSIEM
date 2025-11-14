"""
Cross-Source Anomaly Detection Service
Detects anomalies across multiple log sources using normalized events
Enables correlation-based detection that works across Zscaler, CrowdStrike, Okta, AWS, etc.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from app.models.anomaly import Anomaly
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.normalized_event_repository import NormalizedEventRepository
from app.repositories.anomaly_repository import AnomalyRepository
from app.extensions import db

logger = logging.getLogger(__name__)

class CrossSourceAnomalyDetectionService:
    """
    Multi-source anomaly detection for SOC analysts
    Works with normalized events to detect threats across all log sources
    
    Detection Categories:
    1. Cross-source correlation anomalies (same user in multiple systems)
    2. Impossible travel (geo-location anomalies)
    3. Failed authentication patterns (brute force)
    4. High-severity event clustering
    5. Behavioral anomalies (UEBA)
    6. Data exfiltration patterns
    """
    
    def __init__(self):
        self.event_repo = NormalizedEventRepository()
        self.anomaly_repo = AnomalyRepository()
        
        # Thresholds
        self.IMPOSSIBLE_TRAVEL_MINUTES = 30  # Same user in different countries within 30 min
        self.FAILED_AUTH_THRESHOLD = 5  # Failed auth attempts in 10 minutes
        self.HIGH_SEVERITY_THRESHOLD = 70
        self.HIGH_VOLUME_THRESHOLD = 1000  # Events per hour
        self.DATA_EXFIL_BYTES = 100 * 1024 * 1024  # 100 MB
    
    def detect_all_anomalies(self, log_file_id: str, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Run all cross-source anomaly detection methods
        
        Args:
            log_file_id: The log file to analyze
            time_window_hours: Time window for correlation (default 24 hours)
        
        Returns:
            Summary of detected anomalies
        """
        logger.info(f"Starting cross-source anomaly detection for log file {log_file_id}")
        
        anomalies_detected = []
        
        # Get all normalized events for this log file
        events = self.event_repo.get_by_file(log_file_id, limit=100000)
        
        if not events:
            logger.warning(f"No normalized events found for log file {log_file_id}")
            return {
                'total_anomalies': 0,
                'by_severity': {},
                'by_type': {}
            }
        
        logger.info(f"Analyzing {len(events)} normalized events")
        
        # 1. Impossible Travel Detection
        travel_anomalies = self._detect_impossible_travel(events, log_file_id)
        anomalies_detected.extend(travel_anomalies)
        logger.info(f"Detected {len(travel_anomalies)} impossible travel anomalies")
        
        # 2. Failed Authentication Patterns
        auth_anomalies = self._detect_failed_auth_patterns(events, log_file_id)
        anomalies_detected.extend(auth_anomalies)
        logger.info(f"Detected {len(auth_anomalies)} failed authentication anomalies")
        
        # 3. High Severity Event Clustering
        severity_anomalies = self._detect_high_severity_clustering(events, log_file_id)
        anomalies_detected.extend(severity_anomalies)
        logger.info(f"Detected {len(severity_anomalies)} high-severity clusters")
        
        # 4. High Volume Anomalies
        volume_anomalies = self._detect_high_volume_users(events, log_file_id)
        anomalies_detected.extend(volume_anomalies)
        logger.info(f"Detected {len(volume_anomalies)} high-volume anomalies")
        
        # 5. Data Exfiltration Patterns
        exfil_anomalies = self._detect_data_exfiltration(events, log_file_id)
        anomalies_detected.extend(exfil_anomalies)
        logger.info(f"Detected {len(exfil_anomalies)} potential data exfiltration events")
        
        # 6. Threat Indicator Detection
        threat_anomalies = self._detect_threat_indicators(events, log_file_id)
        anomalies_detected.extend(threat_anomalies)
        logger.info(f"Detected {len(threat_anomalies)} threat indicator matches")
        
        # Save all anomalies to database
        saved_count = 0
        for anomaly_data in anomalies_detected:
            try:
                anomaly = Anomaly(**anomaly_data)
                db.session.add(anomaly)
                saved_count += 1
            except Exception as e:
                logger.error(f"Error saving anomaly: {e}")
        
        db.session.commit()
        logger.info(f"Saved {saved_count} anomalies to database")
        
        # Generate summary
        summary = self._generate_summary(anomalies_detected)
        summary['events_analyzed'] = len(events)
        
        return summary
    
    def _detect_impossible_travel(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect users appearing in multiple countries within short time window"""
        anomalies = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_name and event.source_geo_country:
                user_events[event.user_name].append(event)
        
        # Check each user for impossible travel
        for username, user_event_list in user_events.items():
            # Sort by timestamp
            sorted_events = sorted(user_event_list, key=lambda e: e.timestamp)
            
            # Check consecutive events for geo anomalies
            for i in range(len(sorted_events) - 1):
                event1 = sorted_events[i]
                event2 = sorted_events[i + 1]
                
                # Different countries?
                if event1.source_geo_country != event2.source_geo_country:
                    time_diff = (event2.timestamp - event1.timestamp).total_seconds() / 60
                    
                    # Within impossible travel window?
                    if time_diff <= self.IMPOSSIBLE_TRAVEL_MINUTES:
                        anomalies.append({
                            'log_file_id': log_file_id,
                            'normalized_event_id': event2.id,
                            'anomaly_type': 'impossible_travel',
                            'severity': 'critical',
                            'confidence_score': 0.9,
                            'title': f'Impossible Travel: {username}',
                            'description': f'User {username} appeared in {event1.source_geo_country} and {event2.source_geo_country} within {time_diff:.1f} minutes',
                            'recommendation': 'Investigate for compromised credentials. Check if user is using VPN or if account is shared.',
                            'detection_method': 'rule_based',
                            'ai_model_used': 'geo_correlation',
                            'affected_user': username,
                            'affected_ip': event2.source_ip,
                            'threat_indicators': {
                                'country1': event1.source_geo_country,
                                'country2': event2.source_geo_country,
                                'time_diff_minutes': time_diff,
                                'ip1': event1.source_ip,
                                'ip2': event2.source_ip
                            }
                        })
        
        return anomalies
    
    def _detect_failed_auth_patterns(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect potential brute force attacks"""
        anomalies = []
        
        # Filter authentication events
        auth_events = [e for e in events if e.event_category == 'authentication']
        
        # Group by user and IP
        failed_attempts = defaultdict(lambda: defaultdict(list))
        for event in auth_events:
            if event.event_outcome == 'failure' and event.user_name and event.source_ip:
                key = (event.user_name, event.source_ip)
                failed_attempts[key[0]][key[1]].append(event)
        
        # Check for brute force patterns
        for username, ip_dict in failed_attempts.items():
            for ip, failed_events in ip_dict.items():
                if len(failed_events) >= self.FAILED_AUTH_THRESHOLD:
                    # Check if within 10 minute window
                    sorted_events = sorted(failed_events, key=lambda e: e.timestamp)
                    time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 60
                    
                    if time_span <= 10:
                        anomalies.append({
                            'log_file_id': log_file_id,
                            'normalized_event_id': sorted_events[-1].id,
                            'anomaly_type': 'brute_force_attempt',
                            'severity': 'high',
                            'confidence_score': 0.85,
                            'title': f'Potential Brute Force: {username}',
                            'description': f'{len(failed_events)} failed authentication attempts for {username} from {ip} in {time_span:.1f} minutes',
                            'recommendation': 'Block IP address. Reset user password. Enable MFA if not already enabled.',
                            'detection_method': 'statistical',
                            'ai_model_used': 'threshold_based',
                            'affected_user': username,
                            'affected_ip': ip,
                            'threat_indicators': {
                                'failed_count': len(failed_events),
                                'time_span_minutes': time_span,
                                'source': sorted_events[0].observer_vendor
                            }
                        })
        
        return anomalies
    
    def _detect_high_severity_clustering(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect clustering of high-severity events"""
        anomalies = []
        
        # Filter high-severity events
        high_severity = [e for e in events if e.event_severity >= self.HIGH_SEVERITY_THRESHOLD]
        
        # Group by user
        user_high_severity = defaultdict(list)
        for event in high_severity:
            if event.user_name:
                user_high_severity[event.user_name].append(event)
        
        # Detect users with multiple high-severity events
        for username, user_events in user_high_severity.items():
            if len(user_events) >= 3:
                anomalies.append({
                    'log_file_id': log_file_id,
                    'normalized_event_id': user_events[0].id,
                    'anomaly_type': 'high_severity_clustering',
                    'severity': 'critical',
                    'confidence_score': 0.95,
                    'title': f'High-Severity Event Cluster: {username}',
                    'description': f'User {username} has {len(user_events)} high-severity events across multiple sources',
                    'recommendation': 'Immediate investigation required. User may be compromised or engaging in malicious activity.',
                    'detection_method': 'statistical',
                    'ai_model_used': 'clustering',
                    'affected_user': username,
                    'threat_indicators': {
                        'high_severity_count': len(user_events),
                        'sources': list(set([e.observer_vendor for e in user_events])),
                        'categories': list(set([e.event_category for e in user_events if e.event_category]))
                    }
                })
        
        return anomalies
    
    def _detect_high_volume_users(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect users with unusually high event volumes"""
        anomalies = []
        
        # Count events per user
        user_counts = defaultdict(int)
        user_bytes = defaultdict(int)
        for event in events:
            if event.user_name:
                user_counts[event.user_name] += 1
                # Sum bytes transferred
                src_bytes = event.source_bytes or 0
                dst_bytes = event.destination_bytes or 0
                user_bytes[event.user_name] += (src_bytes + dst_bytes)
        
        # Calculate mean and std dev
        if len(user_counts) > 1:
            counts = list(user_counts.values())
            mean_count = np.mean(counts)
            std_count = np.std(counts)
            
            # Detect outliers (Z-score > 3)
            for username, count in user_counts.items():
                if std_count > 0:
                    z_score = (count - mean_count) / std_count
                    
                    if z_score > 3.0:
                        total_bytes = user_bytes[username]
                        anomalies.append({
                            'log_file_id': log_file_id,
                            'normalized_event_id': None,  # Not tied to specific event
                            'anomaly_type': 'high_volume_user',
                            'severity': 'medium',
                            'confidence_score': min(0.5 + (z_score / 10), 0.95),
                            'title': f'High Volume Activity: {username}',
                            'description': f'User {username} has {count} events (Z-score: {z_score:.2f}), {total_bytes / (1024*1024):.2f} MB transferred',
                            'recommendation': 'Review user activity for potential data exfiltration or compromised account.',
                            'detection_method': 'statistical',
                            'ai_model_used': 'z_score',
                            'affected_user': username,
                            'threat_indicators': {
                                'event_count': count,
                                'z_score': z_score,
                                'total_bytes': total_bytes,
                                'mean_count': mean_count
                            }
                        })
        
        return anomalies
    
    def _detect_data_exfiltration(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration based on large data transfers"""
        anomalies = []
        
        # Group by user and sum bytes
        user_uploads = defaultdict(int)
        user_events = defaultdict(list)
        
        for event in events:
            if event.user_name and event.source_bytes:
                user_uploads[event.user_name] += event.source_bytes
                user_events[event.user_name].append(event)
        
        # Check for large uploads
        for username, total_bytes in user_uploads.items():
            if total_bytes >= self.DATA_EXFIL_BYTES:
                anomalies.append({
                    'log_file_id': log_file_id,
                    'normalized_event_id': user_events[username][0].id,
                    'anomaly_type': 'data_exfiltration',
                    'severity': 'critical',
                    'confidence_score': 0.8,
                    'title': f'Potential Data Exfiltration: {username}',
                    'description': f'User {username} uploaded {total_bytes / (1024*1024):.2f} MB of data',
                    'recommendation': 'Investigate data transfer. Check destination domains and file types. Review DLP policies.',
                    'detection_method': 'statistical',
                    'ai_model_used': 'threshold_based',
                    'affected_user': username,
                    'threat_indicators': {
                        'total_bytes': total_bytes,
                        'total_mb': total_bytes / (1024*1024),
                        'event_count': len(user_events[username])
                    }
                })
        
        return anomalies
    
    def _detect_threat_indicators(self, events: List[NormalizedEventModel], log_file_id: str) -> List[Dict[str, Any]]:
        """Detect events with threat intelligence indicators"""
        anomalies = []
        
        for event in events:
            if event.threat_indicator_value:
                anomalies.append({
                    'log_file_id': log_file_id,
                    'normalized_event_id': event.id,
                    'anomaly_type': 'threat_indicator_match',
                    'severity': 'critical',
                    'confidence_score': 0.95,
                    'title': f'Threat Indicator Match: {event.threat_indicator_type}',
                    'description': f'Threat indicator detected: {event.threat_indicator_type} = {event.threat_indicator_value}',
                    'recommendation': 'Immediate investigation required. Block indicator if confirmed malicious.',
                    'detection_method': 'rule_based',
                    'ai_model_used': 'threat_intel',
                    'affected_user': event.user_name,
                    'affected_ip': event.source_ip,
                    'threat_indicators': {
                        'type': event.threat_indicator_type,
                        'value': event.threat_indicator_value,
                        'framework': event.threat_framework,
                        'tactic': event.threat_tactic_name
                    }
                })
        
        return anomalies
    
    def _generate_summary(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics"""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        
        for anomaly in anomalies:
            by_severity[anomaly['severity']] += 1
            by_type[anomaly['anomaly_type']] += 1
        
        return {
            'total_anomalies': len(anomalies),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type)
        }

