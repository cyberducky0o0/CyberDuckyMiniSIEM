"""
Time Series Analysis Service
Provides time series event tracking and temporal pattern analysis
Supports: Event timelines, temporal aggregations, trend detection, seasonality analysis
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
from app.models.log_entry import LogEntry
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.normalized_event_repository import NormalizedEventRepository
from app.services.statistical_analysis_service import StatisticalAnalysisService

logger = logging.getLogger(__name__)

class TimeSeriesAnalysisService:
    """
    Time series analysis service for SOC analysts
    Provides temporal pattern detection and event timeline analysis
    """
    
    def __init__(self):
        self.log_entry_repo = LogEntryRepository()
        self.event_repo = NormalizedEventRepository()
        self.stats_service = StatisticalAnalysisService()
    
    def generate_event_timeline(self, log_file_id: str, bucket_size: str = 'hour') -> Dict[str, Any]:
        """
        Generate event timeline with temporal aggregations

        Args:
            log_file_id: Log file ID
            bucket_size: Time bucket size ('minute', 'hour', 'day')

        Returns:
            Dictionary with timeline data
        """
        if not log_file_id:
            return self._empty_timeline()

        entries = self.log_entry_repo.get_by_file(log_file_id)

        if not entries:
            return self._empty_timeline()

        # Sort by timestamp, filter out entries without timestamps
        entries = [e for e in entries if e and e.timestamp]
        if not entries:
            return self._empty_timeline()

        entries = sorted(entries, key=lambda e: e.timestamp)

        # Group by time bucket
        time_buckets = defaultdict(lambda: {
            'count': 0,
            'risk_scores': [],
            'bytes_uploaded': [],
            'bytes_downloaded': [],
            'users': set(),
            'ips': set(),
            'domains': set(),
            'categories': Counter(),
            'actions': Counter()
        })

        for entry in entries:
            if not entry or not entry.timestamp:
                continue

            bucket = self._get_time_bucket(entry.timestamp, bucket_size)

            time_buckets[bucket]['count'] += 1
            time_buckets[bucket]['risk_scores'].append(entry.risk_score if entry.risk_score is not None else 0)
            time_buckets[bucket]['bytes_uploaded'].append(entry.source_bytes if entry.source_bytes is not None else 0)
            time_buckets[bucket]['bytes_downloaded'].append(entry.destination_bytes if entry.destination_bytes is not None else 0)
            time_buckets[bucket]['users'].add(entry.username if entry.username else 'unknown')
            time_buckets[bucket]['ips'].add(entry.source_ip if entry.source_ip else 'unknown')
            time_buckets[bucket]['domains'].add(entry.hostname if entry.hostname else 'unknown')
            time_buckets[bucket]['categories'][entry.url_category if entry.url_category else 'unknown'] += 1
            time_buckets[bucket]['actions'][entry.action if entry.action else 'unknown'] += 1
        
        # Convert to timeline format
        timeline = []
        for bucket in sorted(time_buckets.keys()):
            data = time_buckets[bucket]

            timeline.append({
                'timestamp': bucket.isoformat(),
                'event_count': int(data['count']),
                'avg_risk_score': float(np.mean(data['risk_scores'])) if data['risk_scores'] else 0.0,
                'max_risk_score': float(np.max(data['risk_scores'])) if data['risk_scores'] else 0.0,
                'total_bytes_uploaded': int(sum(data['bytes_uploaded'])),
                'total_bytes_downloaded': int(sum(data['bytes_downloaded'])),
                'unique_users': int(len(data['users'])),
                'unique_ips': int(len(data['ips'])),
                'unique_domains': int(len(data['domains'])),
                'top_category': data['categories'].most_common(1)[0][0] if data['categories'] else 'unknown',
                'top_action': data['actions'].most_common(1)[0][0] if data['actions'] else 'unknown'
            })

        # Extract arrays for frontend widget compatibility
        time_buckets = [item['timestamp'] for item in timeline]
        event_counts = [item['event_count'] for item in timeline]

        return {
            'timeline': timeline,
            'time_buckets': time_buckets,
            'event_counts': event_counts,
            'bucket_size': bucket_size,
            'total_buckets': int(len(timeline)),
            'start_time': timeline[0]['timestamp'] if timeline else None,
            'end_time': timeline[-1]['timestamp'] if timeline else None
        }
    
    def detect_temporal_anomalies(self, log_file_id: str, metric: str = 'event_count',
                                  bucket_size: str = 'hour') -> Dict[str, Any]:
        """
        Detect temporal anomalies in event patterns
        
        Args:
            log_file_id: Log file ID
            metric: Metric to analyze
            bucket_size: Time bucket size
        
        Returns:
            Dictionary with anomaly detection results
        """
        timeline_data = self.generate_event_timeline(log_file_id, bucket_size)
        timeline = timeline_data['timeline']
        
        if not timeline:
            return {'anomalies': [], 'timeline': []}
        
        # Extract metric values
        values = [bucket[metric] for bucket in timeline]
        timestamps = [bucket['timestamp'] for bucket in timeline]
        
        # Calculate Z-scores
        z_scores = self.stats_service.calculate_z_scores_series(values)
        
        # Detect bursts
        burst_indices = self.stats_service.detect_burst(values, window=10, threshold_sigma=2.0)
        
        # Detect outliers
        outlier_indices = self.stats_service.detect_outliers_iqr(values)
        
        # Combine anomalies
        anomalies = []
        for i in range(len(timeline)):
            is_burst = i in burst_indices
            is_outlier = i in outlier_indices
            is_high_z = abs(z_scores[i]) > 3.0
            
            if is_burst or is_outlier or is_high_z:
                anomalies.append({
                    'timestamp': timestamps[i],
                    'value': values[i],
                    'z_score': z_scores[i],
                    'is_burst': is_burst,
                    'is_outlier': is_outlier,
                    'is_high_z_score': is_high_z,
                    'bucket_data': timeline[i]
                })
        
        return {
            'anomalies': anomalies,
            'timeline': timeline,
            'metric': metric,
            'total_anomalies': len(anomalies)
        }
    
    def analyze_user_activity_pattern(self, log_file_id: str, username: str) -> Dict[str, Any]:
        """
        Analyze temporal activity pattern for a specific user
        
        Args:
            log_file_id: Log file ID
            username: Username to analyze
        
        Returns:
            Dictionary with user activity pattern analysis
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        user_entries = [e for e in entries if e.username == username]
        
        if not user_entries:
            return {'user': username, 'activity': []}
        
        # Sort by timestamp
        user_entries = sorted(user_entries, key=lambda e: e.timestamp)
        
        # Analyze by hour of day
        hourly_activity = defaultdict(lambda: {
            'count': 0,
            'risk_scores': [],
            'bytes_uploaded': []
        })
        
        for entry in user_entries:
            hour = entry.timestamp.hour
            hourly_activity[hour]['count'] += 1
            hourly_activity[hour]['risk_scores'].append(entry.risk_score or 0)
            hourly_activity[hour]['bytes_uploaded'].append(entry.source_bytes or 0)
        
        # Convert to list
        activity_by_hour = []
        for hour in range(24):
            data = hourly_activity[hour]
            activity_by_hour.append({
                'hour': hour,
                'event_count': data['count'],
                'avg_risk_score': np.mean(data['risk_scores']) if data['risk_scores'] else 0,
                'total_bytes_uploaded': sum(data['bytes_uploaded'])
            })
        
        # Analyze by day of week
        daily_activity = defaultdict(lambda: {
            'count': 0,
            'risk_scores': []
        })
        
        for entry in user_entries:
            day = entry.timestamp.strftime('%A')
            daily_activity[day]['count'] += 1
            daily_activity[day]['risk_scores'].append(entry.risk_score or 0)
        
        activity_by_day = [
            {
                'day': day,
                'event_count': daily_activity[day]['count'],
                'avg_risk_score': np.mean(daily_activity[day]['risk_scores']) if daily_activity[day]['risk_scores'] else 0
            }
            for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        ]
        
        return {
            'user': username,
            'total_events': len(user_entries),
            'first_seen': user_entries[0].timestamp.isoformat(),
            'last_seen': user_entries[-1].timestamp.isoformat(),
            'activity_by_hour': activity_by_hour,
            'activity_by_day': activity_by_day
        }
    
    def calculate_requests_per_minute(self, log_file_id: str, group_by: str = 'ip') -> Dict[str, Any]:
        """
        Calculate requests per minute grouped by IP or user
        
        Args:
            log_file_id: Log file ID
            group_by: Group by 'ip' or 'user'
        
        Returns:
            Dictionary with requests per minute statistics
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'data': [], 'anomalies': []}
        
        # Group by entity and minute
        entity_minute_counts = defaultdict(lambda: defaultdict(int))
        
        for entry in entries:
            if group_by == 'ip':
                entity = entry.source_ip or 'unknown'
            else:
                entity = entry.username or 'unknown'
            
            minute_bucket = entry.timestamp.replace(second=0, microsecond=0)
            entity_minute_counts[entity][minute_bucket] += 1
        
        # Calculate statistics for each entity
        results = []
        anomalies = []
        
        for entity, minute_counts in entity_minute_counts.items():
            counts = list(minute_counts.values())
            
            # Calculate statistics
            mean_rpm = np.mean(counts)
            max_rpm = np.max(counts)
            std_rpm = np.std(counts)
            
            # Detect anomalies (Z-score > 3)
            for minute, count in minute_counts.items():
                z_score = self.stats_service.calculate_z_score(counts, count)

                if abs(z_score) > 3.0:
                    anomalies.append({
                        'entity': entity,
                        'timestamp': minute.isoformat(),
                        'requests_per_minute': int(count),
                        'z_score': float(z_score),
                        'mean': float(mean_rpm),
                        'std_dev': float(std_rpm)
                    })

            results.append({
                'entity': entity,
                'mean_rpm': float(mean_rpm),
                'max_rpm': float(max_rpm),
                'std_rpm': float(std_rpm),
                'total_minutes': int(len(counts))
            })

        # Sort by max_rpm descending
        results = sorted(results, key=lambda x: x['max_rpm'], reverse=True)

        return {
            'data': results,
            'anomalies': anomalies,
            'group_by': group_by,
            'total_entities': int(len(results))
        }
    
    def detect_new_domains_anomaly(self, log_file_id: str) -> Dict[str, Any]:
        """
        Detect anomalies in new domains accessed per day
        
        Args:
            log_file_id: Log file ID
        
        Returns:
            Dictionary with new domain anomaly detection
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'anomalies': [], 'daily_stats': []}
        
        # Sort by timestamp
        entries = sorted(entries, key=lambda e: e.timestamp)
        
        # Track domains seen per day
        daily_domains = defaultdict(set)
        all_seen_domains = set()

        for entry in entries:
            day = entry.timestamp.date()
            domain = entry.hostname or 'unknown'
            daily_domains[day].add(domain)
        
        # Calculate new domains per day
        daily_stats = []
        for day in sorted(daily_domains.keys()):
            domains_today = daily_domains[day]
            new_domains = domains_today - all_seen_domains
            
            daily_stats.append({
                'date': day.isoformat(),
                'total_domains': len(domains_today),
                'new_domains': len(new_domains),
                'new_domain_list': list(new_domains)[:10]  # Top 10
            })
            
            all_seen_domains.update(domains_today)
        
        # Detect anomalies
        new_domain_counts = [stat['new_domains'] for stat in daily_stats]
        
        if len(new_domain_counts) > 1:
            mean = np.mean(new_domain_counts)
            std_dev = np.std(new_domain_counts)
            
            anomalies = []
            for i, stat in enumerate(daily_stats):
                z_score = self.stats_service.calculate_z_score(new_domain_counts, stat['new_domains'])
                
                if abs(z_score) > 3.0:
                    anomalies.append({
                        'date': stat['date'],
                        'new_domains': stat['new_domains'],
                        'z_score': z_score,
                        'mean': mean,
                        'std_dev': std_dev,
                        'threshold': mean + 3 * std_dev
                    })
        else:
            anomalies = []
        
        return {
            'daily_stats': daily_stats,
            'anomalies': anomalies,
            'total_days': len(daily_stats)
        }
    
    def detect_persistent_high_risk(self, log_file_id: str, threshold: int = 70,
                                   duration_hours: int = 1) -> Dict[str, Any]:
        """
        Detect users with persistent high risk (EWMA stays above threshold for > duration)
        
        Args:
            log_file_id: Log file ID
            threshold: Risk score threshold
            duration_hours: Minimum duration in hours
        
        Returns:
            Dictionary with persistent high risk detections
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'detections': []}
        
        # Group by user
        user_entries = defaultdict(list)
        for entry in entries:
            user = entry.username or 'unknown'
            user_entries[user].append(entry)
        
        detections = []
        
        for user, user_entry_list in user_entries.items():
            # Sort by timestamp
            user_entry_list = sorted(user_entry_list, key=lambda e: e.timestamp)
            
            # Extract risk scores
            risk_scores = [e.risk_score or 0 for e in user_entry_list]
            
            # Calculate EWMA
            ewma_scores = self.stats_service.calculate_ewma(risk_scores, alpha=0.3)
            
            # Find periods where EWMA > threshold
            high_risk_periods = []
            start_idx = None
            
            for i, ewma in enumerate(ewma_scores):
                if ewma > threshold:
                    if start_idx is None:
                        start_idx = i
                else:
                    if start_idx is not None:
                        # End of high risk period
                        end_idx = i - 1
                        duration = user_entry_list[end_idx].timestamp - user_entry_list[start_idx].timestamp
                        
                        if duration.total_seconds() / 3600 >= duration_hours:
                            high_risk_periods.append({
                                'start_time': user_entry_list[start_idx].timestamp.isoformat(),
                                'end_time': user_entry_list[end_idx].timestamp.isoformat(),
                                'duration_hours': duration.total_seconds() / 3600,
                                'avg_ewma': np.mean(ewma_scores[start_idx:end_idx+1])
                            })
                        
                        start_idx = None
            
            # Check if still in high risk period at end
            if start_idx is not None:
                end_idx = len(user_entry_list) - 1
                duration = user_entry_list[end_idx].timestamp - user_entry_list[start_idx].timestamp
                
                if duration.total_seconds() / 3600 >= duration_hours:
                    high_risk_periods.append({
                        'start_time': user_entry_list[start_idx].timestamp.isoformat(),
                        'end_time': user_entry_list[end_idx].timestamp.isoformat(),
                        'duration_hours': duration.total_seconds() / 3600,
                        'avg_ewma': np.mean(ewma_scores[start_idx:end_idx+1]),
                        'ongoing': True
                    })
            
            if high_risk_periods:
                detections.append({
                    'user': user,
                    'periods': high_risk_periods,
                    'total_periods': len(high_risk_periods)
                })
        
        return {
            'detections': detections,
            'threshold': threshold,
            'duration_hours': duration_hours,
            'total_users_detected': len(detections)
        }
    
    def _get_time_bucket(self, timestamp: datetime, bucket_size: str) -> datetime:
        """Get time bucket for timestamp"""
        if bucket_size == 'minute':
            return timestamp.replace(second=0, microsecond=0)
        elif bucket_size == 'hour':
            return timestamp.replace(minute=0, second=0, microsecond=0)
        elif bucket_size == 'day':
            return timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return timestamp.replace(minute=0, second=0, microsecond=0)
    
    def _empty_timeline(self) -> Dict[str, Any]:
        """Return empty timeline"""
        return {
            'timeline': [],
            'bucket_size': '',
            'total_buckets': 0,
            'start_time': None,
            'end_time': None
        }

