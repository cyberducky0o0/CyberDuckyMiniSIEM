"""
SOC-Focused Anomaly Detection Service
Implements detection patterns specifically for SOC analysts analyzing Zscaler logs

AI/ML Methods Used:
1. Statistical Analysis (Z-score, EWMA, Percentiles) - for rate-based anomalies
2. Rule-based Detection - for known threat patterns
3. Behavioral Analytics - for user/device anomalies
4. Time Series Analysis - for temporal patterns
5. Correlation Analysis - for multi-metric anomalies
6. LLM Analysis (Ollama) - for intelligent risk scoring and pattern detection
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from app.models.anomaly import Anomaly
from app.models.log_entry import LogEntry
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.anomaly_repository import AnomalyRepository
from app.services.statistical_analysis_service import StatisticalAnalysisService
from app.services.time_series_analysis_service import TimeSeriesAnalysisService
from app.services.llm_analysis_service import LLMAnalysisService
from app.extensions import db

logger = logging.getLogger(__name__)

class AnomalyDetectionService:
    """
    Comprehensive anomaly detection for SOC analysts
    
    Detection Categories:
    1. Threat Detection (direct threats from Zscaler)
    2. Rate-based Anomalies (unusual request volumes)
    3. Behavioral Anomalies (unusual user/device behavior)
    4. Data Exfiltration (large uploads)
    5. Policy Violations (bypassed traffic, high-risk categories)
    """
    
    def __init__(self, enable_llm: bool = True):
        self.log_entry_repo = LogEntryRepository()
        self.anomaly_repo = AnomalyRepository()
        self.stats_service = StatisticalAnalysisService()
        self.time_series_service = TimeSeriesAnalysisService()

        # Initialize LLM service (optional)
        self.llm_service = None
        self.llm_enabled = enable_llm
        if enable_llm:
            try:
                self.llm_service = LLMAnalysisService()
                if self.llm_service.is_available():
                    logger.info("LLM service initialized and available")
                else:
                    logger.warning("LLM service initialized but Ollama not available")
                    self.llm_enabled = False
            except Exception as e:
                logger.warning(f"Failed to initialize LLM service: {e}")
                self.llm_enabled = False

        # Thresholds (configurable)
        self.RATE_THRESHOLD_STDDEV = 3.0  # Z-score threshold
        self.HIGH_RISK_THRESHOLD = 70
        self.LARGE_UPLOAD_MB = 100
        self.REQUESTS_PER_MINUTE_THRESHOLD = 100
        self.PERCENTILE_THRESHOLD = 99  # 99th percentile for data upload anomalies
        self.EWMA_ALPHA = 0.3  # EWMA smoothing factor
        self.PERSISTENT_HIGH_RISK_HOURS = 1  # Hours for persistent high risk

        # High-risk URL categories
        self.HIGH_RISK_CATEGORIES = {
            'Malware', 'Phishing', 'Command and Control', 'C2',
            'Hacking', 'Proxy Avoidance', 'Anonymizers',
            'Newly Registered Domains', 'Suspicious'
        }
    
    def detect_all_anomalies(self, log_file_id: str) -> Dict[str, Any]:
        """
        Run all anomaly detection methods
        
        Returns summary of detected anomalies
        """
        logger.info(f"Starting anomaly detection for log file {log_file_id}")
        
        anomalies_detected = []
        
        # 1. Direct Threat Detection (highest priority)
        threat_anomalies = self._detect_threats(log_file_id)
        anomalies_detected.extend(threat_anomalies)
        logger.info(f"Detected {len(threat_anomalies)} direct threats")
        
        # 2. High Risk Category Access
        category_anomalies = self._detect_high_risk_categories(log_file_id)
        anomalies_detected.extend(category_anomalies)
        logger.info(f"Detected {len(category_anomalies)} high-risk category accesses")
        
        # 3. Rate-based Anomalies
        rate_anomalies = self._detect_rate_anomalies(log_file_id)
        anomalies_detected.extend(rate_anomalies)
        logger.info(f"Detected {len(rate_anomalies)} rate anomalies")
        
        # 4. Data Exfiltration
        exfil_anomalies = self._detect_data_exfiltration(log_file_id)
        anomalies_detected.extend(exfil_anomalies)
        logger.info(f"Detected {len(exfil_anomalies)} potential data exfiltration events")
        
        # 5. Bypassed Traffic
        bypass_anomalies = self._detect_bypassed_traffic(log_file_id)
        anomalies_detected.extend(bypass_anomalies)
        logger.info(f"Detected {len(bypass_anomalies)} bypassed traffic events")
        
        # 6. Behavioral Anomalies
        behavioral_anomalies = self._detect_behavioral_anomalies(log_file_id)
        anomalies_detected.extend(behavioral_anomalies)
        logger.info(f"Detected {len(behavioral_anomalies)} behavioral anomalies")

        # 7. Risk Score Spike Detection (Statistical)
        risk_spike_anomalies = self._detect_risk_score_spikes(log_file_id)
        anomalies_detected.extend(risk_spike_anomalies)
        logger.info(f"Detected {len(risk_spike_anomalies)} risk score spikes")

        # 8. Data Upload Anomalies (99th Percentile)
        upload_anomalies = self._detect_data_upload_anomalies(log_file_id)
        anomalies_detected.extend(upload_anomalies)
        logger.info(f"Detected {len(upload_anomalies)} data upload anomalies")

        # 9. New Domains Anomaly
        domain_anomalies = self._detect_new_domains_anomaly(log_file_id)
        anomalies_detected.extend(domain_anomalies)
        logger.info(f"Detected {len(domain_anomalies)} new domain anomalies")

        # 10. Persistent High Risk (EWMA)
        persistent_risk_anomalies = self._detect_persistent_high_risk(log_file_id)
        anomalies_detected.extend(persistent_risk_anomalies)
        logger.info(f"Detected {len(persistent_risk_anomalies)} persistent high risk users")

        # 11. Burst Detection (Sudden Spike in Blocked Requests)
        burst_anomalies = self._detect_burst_blocked_requests(log_file_id)
        anomalies_detected.extend(burst_anomalies)
        logger.info(f"Detected {len(burst_anomalies)} burst anomalies")

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

        # Enrich high-severity anomalies with LLM analysis (async/background task in production)
        if self.llm_enabled and saved_count > 0:
            self._enrich_anomalies_with_llm(log_file_id, limit=5)

        return {
            'total_anomalies': len(anomalies_detected),
            'saved_anomalies': saved_count,
            'by_type': self._count_by_type(anomalies_detected),
            'by_severity': self._count_by_severity(anomalies_detected),
            'llm_enabled': self.llm_enabled
        }
    
    def _detect_threats(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect direct threats flagged by Zscaler
        
        AI Method: Rule-based detection
        Priority: CRITICAL
        """
        anomalies = []
        threat_entries = self.log_entry_repo.get_threat_entries(log_file_id)
        
        for entry in threat_entries:
            severity = 'critical' if entry.risk_score and entry.risk_score >= 90 else 'high'
            
            anomaly = {
                'log_entry_id': entry.id,
                'log_file_id': log_file_id,
                'anomaly_type': 'threat_detected',
                'severity': severity,
                'confidence_score': 0.95,  # High confidence - direct from Zscaler
                'title': f"Threat Detected: {entry.threat_name}",
                'description': f"Zscaler detected threat '{entry.threat_name}' from {entry.username or 'unknown user'} "
                              f"at {entry.source_ip} accessing {entry.hostname or entry.url}",
                'recommendation': f"IMMEDIATE ACTION REQUIRED: Investigate user {entry.username}, "
                                 f"isolate device {entry.device_hostname}, check for lateral movement",
                'detection_method': 'rule_based',
                'ai_model_used': 'zscaler_threat_detection',
                'affected_user': entry.username,
                'affected_device': entry.device_hostname,
                'affected_ip': entry.source_ip,
                'threat_indicators': {
                    'threat_name': entry.threat_name,
                    'malware_type': entry.malware_type,
                    'malware_class': entry.malware_class,
                    'risk_score': entry.risk_score,
                    'url': entry.url,
                    'hostname': entry.hostname
                }
            }
            anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_high_risk_categories(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect access to high-risk URL categories
        
        AI Method: Rule-based detection with category classification
        Priority: HIGH
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)
        
        for entry in entries:
            if entry.url_category in self.HIGH_RISK_CATEGORIES or \
               entry.url_super_category in self.HIGH_RISK_CATEGORIES:
                
                # Determine severity based on category and action
                if entry.action == 'blocked':
                    severity = 'medium'  # Blocked is less severe
                    confidence = 0.75
                else:
                    severity = 'high'  # Allowed is more concerning
                    confidence = 0.85
                
                anomaly = {
                    'log_entry_id': entry.id,
                    'log_file_id': log_file_id,
                    'anomaly_type': 'high_risk_category',
                    'severity': severity,
                    'confidence_score': confidence,
                    'title': f"High-Risk Category Access: {entry.url_category}",
                    'description': f"User {entry.username or 'unknown'} accessed {entry.url_category} category "
                                  f"({entry.hostname}). Action: {entry.action}",
                    'recommendation': f"Review user {entry.username} activity, check if access was legitimate, "
                                     f"consider blocking category if not business-related",
                    'detection_method': 'rule_based',
                    'ai_model_used': 'category_classification',
                    'affected_user': entry.username,
                    'affected_device': entry.device_hostname,
                    'affected_ip': entry.source_ip,
                    'threat_indicators': {
                        'url_category': entry.url_category,
                        'url_super_category': entry.url_super_category,
                        'action': entry.action,
                        'hostname': entry.hostname
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_rate_anomalies(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect unusual request rates using statistical analysis
        
        AI Method: Z-score statistical analysis
        Priority: MEDIUM-HIGH
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)
        
        # Group by source IP and count requests per minute
        ip_minute_counts = defaultdict(lambda: defaultdict(int))
        
        for entry in entries:
            if entry.timestamp and entry.source_ip:
                minute_key = entry.timestamp.replace(second=0, microsecond=0)
                ip_minute_counts[entry.source_ip][minute_key] += 1
        
        # Calculate statistics for each IP
        for ip, minute_counts in ip_minute_counts.items():
            counts = list(minute_counts.values())
            
            if len(counts) < 2:
                continue
            
            mean_count = np.mean(counts)
            std_count = np.std(counts)
            
            if std_count == 0:
                continue
            
            # Find outliers
            for minute, count in minute_counts.items():
                z_score = (count - mean_count) / std_count
                
                if z_score > self.RATE_THRESHOLD_STDDEV:
                    # Get a sample entry for this IP/minute
                    sample_entry = next(
                        (e for e in entries if e.source_ip == ip and 
                         e.timestamp and e.timestamp.replace(second=0, microsecond=0) == minute),
                        None
                    )
                    
                    if not sample_entry:
                        continue
                    
                    severity = self._calculate_severity_from_zscore(z_score)
                    
                    anomaly = {
                        'log_entry_id': sample_entry.id,
                        'log_file_id': log_file_id,
                        'anomaly_type': 'rate_limit_exceeded',
                        'severity': severity,
                        'confidence_score': min(z_score / 10, 1.0),
                        'title': f"Unusual Request Rate from {ip}",
                        'description': f"IP {ip} made {count} requests in 1 minute "
                                      f"(mean: {mean_count:.1f}, std: {std_count:.1f}, z-score: {z_score:.2f})",
                        'recommendation': f"Investigate IP {ip} for potential bot activity, DDoS, or compromised system",
                        'detection_method': 'statistical',
                        'ai_model_used': 'z_score_analysis',
                        'affected_user': sample_entry.username,
                        'affected_device': sample_entry.device_hostname,
                        'affected_ip': ip,
                        'threat_indicators': {
                            'request_count': count,
                            'mean_count': float(mean_count),
                            'std_dev': float(std_count),
                            'z_score': float(z_score)
                        }
                    }
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_data_exfiltration(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect potential data exfiltration based on large uploads
        
        AI Method: Statistical threshold analysis
        Priority: HIGH
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)
        
        large_upload_threshold = self.LARGE_UPLOAD_MB * 1024 * 1024  # Convert to bytes
        
        for entry in entries:
            if entry.destination_bytes and entry.destination_bytes > large_upload_threshold:
                size_mb = entry.destination_bytes / (1024 * 1024)
                
                anomaly = {
                    'log_entry_id': entry.id,
                    'log_file_id': log_file_id,
                    'anomaly_type': 'data_exfiltration',
                    'severity': 'high',
                    'confidence_score': 0.80,
                    'title': f"Large Data Upload Detected ({size_mb:.1f} MB)",
                    'description': f"User {entry.username or 'unknown'} uploaded {size_mb:.1f} MB "
                                  f"to {entry.hostname}",
                    'recommendation': f"Investigate data upload by {entry.username}, verify if legitimate business activity, "
                                     f"check file contents if possible",
                    'detection_method': 'statistical',
                    'ai_model_used': 'threshold_analysis',
                    'affected_user': entry.username,
                    'affected_device': entry.device_hostname,
                    'affected_ip': entry.source_ip,
                    'threat_indicators': {
                        'bytes_uploaded': entry.destination_bytes,
                        'size_mb': size_mb,
                        'hostname': entry.hostname,
                        'url': entry.url
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_bypassed_traffic(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect bypassed or unscannable traffic
        
        AI Method: Rule-based detection
        Priority: MEDIUM-HIGH
        """
        anomalies = []
        bypassed_entries = self.log_entry_repo.get_bypassed_traffic(log_file_id)
        
        for entry in bypassed_entries:
            anomaly = {
                'log_entry_id': entry.id,
                'log_file_id': log_file_id,
                'anomaly_type': 'bypassed_traffic',
                'severity': 'medium',
                'confidence_score': 0.85,
                'title': f"Traffic Bypassed Inspection",
                'description': f"Traffic from {entry.username or 'unknown'} to {entry.hostname} "
                              f"bypassed security inspection",
                'recommendation': f"Investigate why traffic was bypassed, review policy configuration, "
                                 f"check for policy evasion attempts",
                'detection_method': 'rule_based',
                'ai_model_used': 'policy_analysis',
                'affected_user': entry.username,
                'affected_device': entry.device_hostname,
                'affected_ip': entry.source_ip,
                'threat_indicators': {
                    'bypassed': True,
                    'unscannable_type': entry.unscannable_type,
                    'hostname': entry.hostname
                }
            }
            anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect behavioral anomalies (new users accessing unusual categories, etc.)
        
        AI Method: Behavioral analysis
        Priority: MEDIUM
        """
        # This is a simplified version - in production, you'd compare against historical baselines
        # For now, we'll detect users with multiple high-risk events
        
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)
        
        # Group by user and count high-risk events
        user_risk_counts = defaultdict(int)
        user_entries = defaultdict(list)
        
        for entry in entries:
            if entry.username and entry.risk_score and entry.risk_score >= self.HIGH_RISK_THRESHOLD:
                user_risk_counts[entry.username] += 1
                user_entries[entry.username].append(entry)
        
        # Flag users with multiple high-risk events
        for username, risk_count in user_risk_counts.items():
            if risk_count >= 5:  # Threshold for behavioral anomaly
                sample_entry = user_entries[username][0]
                
                anomaly = {
                    'log_entry_id': sample_entry.id,
                    'log_file_id': log_file_id,
                    'anomaly_type': 'behavioral_anomaly',
                    'severity': 'medium',
                    'confidence_score': 0.70,
                    'title': f"Multiple High-Risk Events from User {username}",
                    'description': f"User {username} triggered {risk_count} high-risk events",
                    'recommendation': f"Review all activity from {username}, check for account compromise, "
                                     f"verify user identity",
                    'detection_method': 'behavioral',
                    'ai_model_used': 'behavioral_analysis',
                    'affected_user': username,
                    'affected_device': sample_entry.device_hostname,
                    'affected_ip': sample_entry.source_ip,
                    'threat_indicators': {
                        'high_risk_event_count': risk_count
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _calculate_severity_from_zscore(self, z_score: float) -> str:
        """Calculate severity level from Z-score"""
        if z_score > 5:
            return 'critical'
        elif z_score > 4:
            return 'high'
        elif z_score > 3:
            return 'medium'
        else:
            return 'low'
    
    def _count_by_type(self, anomalies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count anomalies by type"""
        counts = defaultdict(int)
        for anomaly in anomalies:
            counts[anomaly['anomaly_type']] += 1
        return dict(counts)
    
    def _count_by_severity(self, anomalies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count anomalies by severity"""
        counts = defaultdict(int)
        for anomaly in anomalies:
            counts[anomaly['severity']] += 1
        return dict(counts)

    def _detect_risk_score_spikes(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect risk score spikes using rolling mean + 2σ

        Detection: User's risk score spike
        Statistical Logic: rolling mean + 2σ
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)

        # Group by user
        user_entries = defaultdict(list)
        for entry in entries:
            if entry.username and entry.risk_score:
                user_entries[entry.username].append(entry)

        for username, user_entry_list in user_entries.items():
            if len(user_entry_list) < 10:
                continue

            # Sort by timestamp
            user_entry_list = sorted(user_entry_list, key=lambda e: e.timestamp)

            # Extract risk scores
            risk_scores = [e.risk_score for e in user_entry_list]

            # Calculate rolling statistics
            rolling_stats = self.stats_service.calculate_rolling_statistics(risk_scores, window=10)

            # Detect spikes (value > rolling_mean + 2*rolling_std)
            for i in range(len(risk_scores)):
                if i < 10:
                    continue

                threshold = rolling_stats['rolling_mean'][i] + 2 * rolling_stats['rolling_std'][i]

                if risk_scores[i] > threshold and rolling_stats['rolling_std'][i] > 0:
                    z_score = (risk_scores[i] - rolling_stats['rolling_mean'][i]) / rolling_stats['rolling_std'][i]

                    anomaly = {
                        'log_entry_id': user_entry_list[i].id,
                        'log_file_id': log_file_id,
                        'anomaly_type': 'risk_score_spike',
                        'severity': 'high' if z_score > 3 else 'medium',
                        'confidence_score': min(z_score / 5, 1.0),
                        'title': f"Risk Score Spike: {username}",
                        'description': f"User {username} risk score spiked to {risk_scores[i]} "
                                      f"(rolling mean: {rolling_stats['rolling_mean'][i]:.1f}, "
                                      f"threshold: {threshold:.1f}, z-score: {z_score:.2f})",
                        'recommendation': f"Investigate recent activity from {username}, check for compromised account",
                        'detection_method': 'statistical',
                        'ai_model_used': 'rolling_mean_analysis',
                        'affected_user': username,
                        'affected_device': user_entry_list[i].device_hostname,
                        'affected_ip': user_entry_list[i].source_ip,
                        'threat_indicators': {
                            'current_risk_score': risk_scores[i],
                            'rolling_mean': rolling_stats['rolling_mean'][i],
                            'rolling_std': rolling_stats['rolling_std'][i],
                            'z_score': z_score,
                            'threshold': threshold
                        }
                    }
                    anomalies.append(anomaly)

        return anomalies

    def _detect_data_upload_anomalies(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect data upload anomalies using 99th percentile

        Detection: Data upload anomaly
        Statistical Logic: 99th percentile of dstBytes exceeded
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)

        # Extract all upload sizes
        upload_sizes = [e.destination_bytes for e in entries if e.destination_bytes and e.destination_bytes > 0]

        if not upload_sizes:
            return anomalies

        # Calculate 99th percentile
        percentile_99 = self.stats_service.calculate_percentile(upload_sizes, 99)

        # Find entries exceeding 99th percentile
        for entry in entries:
            if entry.destination_bytes and entry.destination_bytes > percentile_99:
                size_mb = entry.destination_bytes / (1024 * 1024)
                percentile_mb = percentile_99 / (1024 * 1024)

                anomaly = {
                    'log_entry_id': entry.id,
                    'log_file_id': log_file_id,
                    'anomaly_type': 'data_upload_anomaly',
                    'severity': 'high',
                    'confidence_score': 0.85,
                    'title': f"Data Upload Exceeds 99th Percentile ({size_mb:.1f} MB)",
                    'description': f"User {entry.username or 'unknown'} uploaded {size_mb:.1f} MB "
                                  f"to {entry.hostname} (99th percentile: {percentile_mb:.1f} MB)",
                    'recommendation': f"Investigate large upload by {entry.username}, verify legitimacy",
                    'detection_method': 'statistical',
                    'ai_model_used': 'percentile_analysis',
                    'affected_user': entry.username,
                    'affected_device': entry.device_hostname,
                    'affected_ip': entry.source_ip,
                    'threat_indicators': {
                        'bytes_uploaded': entry.destination_bytes,
                        'size_mb': size_mb,
                        'percentile_99': percentile_99,
                        'percentile_99_mb': percentile_mb,
                        'hostname': entry.hostname
                    }
                }
                anomalies.append(anomaly)

        return anomalies

    def _detect_new_domains_anomaly(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies in new domains accessed

        Detection: New domains accessed anomaly
        Statistical Logic: > mean + 3σ new domains per day
        """
        anomalies = []

        # Use time series service for detection
        domain_analysis = self.time_series_service.detect_new_domains_anomaly(log_file_id)

        for anomaly_data in domain_analysis.get('anomalies', []):
            # Get a sample entry from that day
            entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)

            # Find entry from the anomaly date
            from datetime import datetime
            anomaly_date = datetime.fromisoformat(anomaly_data['date']).date()
            sample_entry = next(
                (e for e in entries if e.timestamp.date() == anomaly_date),
                entries[0] if entries else None
            )

            if not sample_entry:
                continue

            anomaly = {
                'log_entry_id': sample_entry.id,
                'log_file_id': log_file_id,
                'anomaly_type': 'new_domains_anomaly',
                'severity': 'medium',
                'confidence_score': min(abs(anomaly_data['z_score']) / 5, 1.0),
                'title': f"Unusual Number of New Domains Accessed",
                'description': f"{anomaly_data['new_domains']} new domains accessed on {anomaly_data['date']} "
                              f"(mean: {anomaly_data['mean']:.1f}, threshold: {anomaly_data['threshold']:.1f}, "
                              f"z-score: {anomaly_data['z_score']:.2f})",
                'recommendation': f"Review new domains accessed, check for reconnaissance or C2 activity",
                'detection_method': 'statistical',
                'ai_model_used': 'z_score_analysis',
                'affected_user': None,
                'affected_device': None,
                'affected_ip': None,
                'threat_indicators': {
                    'new_domains_count': anomaly_data['new_domains'],
                    'mean': anomaly_data['mean'],
                    'std_dev': anomaly_data['std_dev'],
                    'z_score': anomaly_data['z_score'],
                    'threshold': anomaly_data['threshold']
                }
            }
            anomalies.append(anomaly)

        return anomalies

    def _detect_persistent_high_risk(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect persistent high risk using EWMA

        Detection: Persistent high risk
        Statistical Logic: EWMA stays above threshold for > 1 hour
        """
        anomalies = []

        # Use time series service for detection
        persistent_risk = self.time_series_service.detect_persistent_high_risk(
            log_file_id,
            threshold=self.HIGH_RISK_THRESHOLD,
            duration_hours=self.PERSISTENT_HIGH_RISK_HOURS
        )

        for detection in persistent_risk.get('detections', []):
            username = detection['user']

            # Get a sample entry for this user
            entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)
            sample_entry = next(
                (e for e in entries if e.username == username),
                None
            )

            if not sample_entry:
                continue

            for period in detection['periods']:
                severity = 'critical' if period.get('ongoing') else 'high'

                anomaly = {
                    'log_entry_id': sample_entry.id,
                    'log_file_id': log_file_id,
                    'anomaly_type': 'persistent_high_risk',
                    'severity': severity,
                    'confidence_score': 0.90,
                    'title': f"Persistent High Risk: {username}",
                    'description': f"User {username} maintained high risk (EWMA > {self.HIGH_RISK_THRESHOLD}) "
                                  f"for {period['duration_hours']:.1f} hours "
                                  f"(from {period['start_time']} to {period['end_time']})",
                    'recommendation': f"URGENT: Investigate {username} for sustained malicious activity or compromise",
                    'detection_method': 'statistical',
                    'ai_model_used': 'ewma_control_chart',
                    'affected_user': username,
                    'affected_device': sample_entry.device_hostname,
                    'affected_ip': sample_entry.source_ip,
                    'threat_indicators': {
                        'duration_hours': period['duration_hours'],
                        'avg_ewma': period['avg_ewma'],
                        'threshold': self.HIGH_RISK_THRESHOLD,
                        'start_time': period['start_time'],
                        'end_time': period['end_time'],
                        'ongoing': period.get('ongoing', False)
                    }
                }
                anomalies.append(anomaly)

        return anomalies

    def _detect_burst_blocked_requests(self, log_file_id: str) -> List[Dict[str, Any]]:
        """
        Detect sudden bursts of blocked requests

        Detection: Sudden burst of blocked requests
        Statistical Logic: moving average deviation
        """
        anomalies = []
        entries = self.log_entry_repo.get_by_file(log_file_id, limit=10000)

        # Filter blocked requests
        blocked_entries = [e for e in entries if e.action == 'blocked']

        if not blocked_entries:
            return anomalies

        # Group by minute
        minute_counts = defaultdict(int)
        minute_entries = defaultdict(list)

        for entry in blocked_entries:
            minute_bucket = entry.timestamp.replace(second=0, microsecond=0)
            minute_counts[minute_bucket] += 1
            minute_entries[minute_bucket].append(entry)

        # Convert to time series
        sorted_minutes = sorted(minute_counts.keys())
        counts = [minute_counts[m] for m in sorted_minutes]

        if len(counts) < 10:
            return anomalies

        # Detect bursts
        burst_indices = self.stats_service.detect_burst(counts, window=10, threshold_sigma=2.0)

        for idx in burst_indices:
            minute = sorted_minutes[idx]
            count = counts[idx]

            # Calculate statistics
            window_values = counts[max(0, idx-10):idx]
            mean = np.mean(window_values) if window_values else 0
            std_dev = np.std(window_values) if window_values else 0

            # Get sample entry
            sample_entry = minute_entries[minute][0]

            anomaly = {
                'log_entry_id': sample_entry.id,
                'log_file_id': log_file_id,
                'anomaly_type': 'burst_blocked_requests',
                'severity': 'high',
                'confidence_score': 0.85,
                'title': f"Burst of Blocked Requests Detected",
                'description': f"Sudden burst of {count} blocked requests at {minute.isoformat()} "
                              f"(mean: {mean:.1f}, std: {std_dev:.1f})",
                'recommendation': f"Investigate cause of blocked request burst, check for attack or policy changes",
                'detection_method': 'statistical',
                'ai_model_used': 'burst_detection',
                'affected_user': None,
                'affected_device': None,
                'affected_ip': None,
                'threat_indicators': {
                    'blocked_count': count,
                    'mean': mean,
                    'std_dev': std_dev,
                    'timestamp': minute.isoformat()
                }
            }
            anomalies.append(anomaly)

        return anomalies

    def _enrich_anomalies_with_llm(self, log_file_id: str, limit: int = 5):
        """
        Enrich high-severity anomalies with LLM analysis

        Args:
            log_file_id: Log file ID
            limit: Maximum number of anomalies to enrich
        """
        if not self.llm_enabled or not self.llm_service:
            return

        try:
            # Get high-severity anomalies without LLM analysis
            anomalies = self.anomaly_repo.get_by_file(log_file_id, limit=limit)
            anomalies = [a for a in anomalies if a.severity in ['critical', 'high'] and not a.ai_explanation]

            for anomaly in anomalies[:limit]:
                try:
                    # Get associated log entry
                    log_entry = None
                    if anomaly.log_entry_id:
                        log_entry = self.log_entry_repo.get_by_id(anomaly.log_entry_id)

                    # Get LLM analysis
                    analysis = self.llm_service.analyze_anomaly(anomaly, log_entry)

                    if not analysis.get('error'):
                        # Update anomaly with LLM insights
                        anomaly.ai_explanation = analysis.get('explanation', '')
                        anomaly.recommendation = analysis.get('recommendations', [])[:3]  # Top 3
                        if not anomaly.detection_method:
                            anomaly.detection_method = 'llm'
                        anomaly.ai_model_used = analysis.get('model', 'unknown')

                        db.session.add(anomaly)
                        logger.info(f"Enriched anomaly {anomaly.id} with LLM analysis")

                except Exception as e:
                    logger.error(f"Error enriching anomaly {anomaly.id} with LLM: {e}")
                    continue

            db.session.commit()
            logger.info(f"Enriched {len(anomalies)} anomalies with LLM analysis")

        except Exception as e:
            logger.error(f"Error in LLM enrichment: {e}")

