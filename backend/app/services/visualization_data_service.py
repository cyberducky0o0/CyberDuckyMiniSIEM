"""
Visualization Data Service
Generates data for statistical visualizations and charts
Supports: Risk trendlines, Z-score heatmaps, boxplots, scatter plots, density plots, EWMA control charts
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from app.models.log_entry import LogEntry
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.normalized_event_repository import NormalizedEventRepository
from app.services.statistical_analysis_service import StatisticalAnalysisService

logger = logging.getLogger(__name__)

class VisualizationDataService:
    """
    Service for generating visualization data for SOC analysts
    Provides data for advanced statistical charts and graphs
    """
    
    def __init__(self):
        self.log_entry_repo = LogEntryRepository()
        self.event_repo = NormalizedEventRepository()
        self.stats_service = StatisticalAnalysisService()
    
    def generate_risk_score_trendline(self, log_file_id: str, user: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate risk score trendline with moving average and threshold bands
        
        Args:
            log_file_id: Log file ID
            user: Optional user filter
        
        Returns:
            Dictionary with timestamps, risk_scores, moving_avg, upper_band, lower_band
        """
        # Get log entries
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if user:
            entries = [e for e in entries if e.username == user]
        
        if not entries:
            return self._empty_trendline()
        
        # Sort by timestamp
        entries = sorted(entries, key=lambda e: e.timestamp)
        
        # Extract data
        timestamps = [e.timestamp.isoformat() for e in entries]
        risk_scores = [e.risk_score or 0 for e in entries]
        
        # Calculate moving average
        moving_avg = self.stats_service.calculate_moving_average(risk_scores, window=10)
        
        # Calculate control limits
        control_limits = self.stats_service.calculate_control_limits(risk_scores, sigma=2.0)
        
        # Calculate EWMA
        ewma = self.stats_service.calculate_ewma(risk_scores)
        
        return {
            'timestamps': timestamps,
            'risk_scores': risk_scores,
            'moving_avg': moving_avg,
            'ewma': ewma,
            'upper_band': [control_limits['upper_limit']] * len(timestamps),
            'lower_band': [control_limits['lower_limit']] * len(timestamps),
            'mean': control_limits['mean'],
            'std_dev': control_limits['std_dev'],
            'count': len(entries)
        }
    
    def generate_z_score_heatmap(self, log_file_id: str, metric: str = 'risk_score') -> Dict[str, Any]:
        """
        Generate Z-score heatmap data (Users vs Time)
        Color intensity = deviation from normal
        
        Args:
            log_file_id: Log file ID
            metric: Metric to analyze (risk_score, bytes_uploaded, request_count)
        
        Returns:
            Dictionary with users, time_buckets, z_scores (2D array)
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return self._empty_heatmap()
        
        # Group by user and time bucket (hourly)
        user_time_data = defaultdict(lambda: defaultdict(list))
        
        for entry in entries:
            user = entry.username or 'unknown'
            time_bucket = entry.timestamp.replace(minute=0, second=0, microsecond=0)
            
            # Get metric value
            if metric == 'risk_score':
                value = entry.risk_score or 0
            elif metric == 'bytes_uploaded':
                value = entry.source_bytes or 0
            elif metric == 'request_count':
                value = 1  # Count requests
            else:
                value = entry.risk_score or 0
            
            user_time_data[user][time_bucket].append(value)
        
        # Aggregate by time bucket (sum or average)
        user_time_aggregated = {}
        for user, time_buckets in user_time_data.items():
            user_time_aggregated[user] = {}
            for time_bucket, values in time_buckets.items():
                if metric == 'request_count':
                    user_time_aggregated[user][time_bucket] = len(values)
                else:
                    user_time_aggregated[user][time_bucket] = np.mean(values)
        
        # Get all unique time buckets
        all_time_buckets = sorted(set(
            time_bucket 
            for user_data in user_time_aggregated.values() 
            for time_bucket in user_data.keys()
        ))
        
        # Get all users
        all_users = sorted(user_time_aggregated.keys())
        
        # Calculate Z-scores for each user
        z_score_matrix = []
        for user in all_users:
            user_values = []
            for time_bucket in all_time_buckets:
                value = user_time_aggregated[user].get(time_bucket, 0)
                user_values.append(value)
            
            # Calculate Z-scores for this user's time series
            z_scores = self.stats_service.calculate_z_scores_series(user_values)
            z_score_matrix.append(z_scores)
        
        return {
            'users': all_users,
            'time_buckets': [t.isoformat() for t in all_time_buckets],
            'z_scores': z_score_matrix,  # 2D array: users x time
            'metric': metric
        }
    
    def generate_boxplot_per_user(self, log_file_id: str, metric: str = 'risk_score') -> Dict[str, Any]:
        """
        Generate boxplot statistics per user
        Shows distribution of metric vs current value (outliers visible)
        
        Args:
            log_file_id: Log file ID
            metric: Metric to analyze
        
        Returns:
            Dictionary with user boxplot statistics
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'users': [], 'boxplots': []}
        
        # Group by user
        user_data = defaultdict(list)
        for entry in entries:
            user = entry.username or 'unknown'
            
            if metric == 'risk_score':
                value = entry.risk_score or 0
            elif metric == 'bytes_uploaded':
                value = entry.source_bytes or 0
            elif metric == 'bytes_downloaded':
                value = entry.destination_bytes or 0
            else:
                value = entry.risk_score or 0
            
            user_data[user].append(value)
        
        # Calculate boxplot stats for each user
        users = []
        boxplots = []
        
        for user in sorted(user_data.keys()):
            values = user_data[user]
            stats = self.stats_service.calculate_boxplot_stats(values)
            
            users.append(user)
            boxplots.append({
                'user': user,
                'min': stats['min'],
                'q1': stats['q1'],
                'median': stats['median'],
                'q3': stats['q3'],
                'max': stats['max'],
                'mean': stats['mean'],
                'std_dev': stats['std_dev'],
                'outliers': stats['outliers'],
                'outlier_count': stats['outlier_count'],
                'current_value': values[-1] if values else 0  # Most recent value
            })
        
        return {
            'users': users,
            'boxplots': boxplots,
            'metric': metric
        }
    
    def generate_anomaly_scatter_plot(self, log_file_id: str) -> Dict[str, Any]:
        """
        Generate scatter plot data
        X = risk score, Y = bytes uploaded, color = anomaly score
        
        Args:
            log_file_id: Log file ID
        
        Returns:
            Dictionary with scatter plot data
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'x': [], 'y': [], 'colors': [], 'labels': []}
        
        # Extract data
        risk_scores = [e.risk_score or 0 for e in entries]
        bytes_uploaded = [e.source_bytes or 0 for e in entries]
        
        # Calculate anomaly scores (combined Z-score)
        risk_z_scores = self.stats_service.calculate_z_scores_series(risk_scores)
        bytes_z_scores = self.stats_service.calculate_z_scores_series(bytes_uploaded)
        
        # Combined anomaly score (Euclidean distance in Z-score space)
        anomaly_scores = [
            np.sqrt(rz**2 + bz**2) 
            for rz, bz in zip(risk_z_scores, bytes_z_scores)
        ]
        
        # Create labels
        labels = [
            f"{e.username or 'unknown'} - {e.timestamp.strftime('%H:%M:%S')}"
            for e in entries
        ]
        
        return {
            'x': risk_scores,
            'y': bytes_uploaded,
            'colors': anomaly_scores,
            'labels': labels,
            'usernames': [e.username or 'unknown' for e in entries],
            'timestamps': [e.timestamp.isoformat() for e in entries]
        }
    
    def generate_density_plot(self, log_file_id: str, metric: str = 'risk_score', 
                             compare_user: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate density plot comparing normal vs current distribution
        
        Args:
            log_file_id: Log file ID
            metric: Metric to analyze
            compare_user: Optional user to compare against population
        
        Returns:
            Dictionary with density plot data
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if not entries:
            return {'normal': {}, 'current': {}}
        
        # Extract metric values
        if metric == 'risk_score':
            all_values = [e.risk_score or 0 for e in entries]
        elif metric == 'bytes_uploaded':
            all_values = [e.source_bytes or 0 for e in entries]
        else:
            all_values = [e.risk_score or 0 for e in entries]
        
        # Calculate density for all data (normal)
        normal_density = self.stats_service.calculate_density_distribution(all_values, bins=50)
        
        # If comparing user, calculate their density
        if compare_user:
            user_entries = [e for e in entries if e.username == compare_user]
            if metric == 'risk_score':
                user_values = [e.risk_score or 0 for e in user_entries]
            elif metric == 'bytes_uploaded':
                user_values = [e.source_bytes or 0 for e in user_entries]
            else:
                user_values = [e.risk_score or 0 for e in user_entries]
            
            current_density = self.stats_service.calculate_density_distribution(user_values, bins=50)
        else:
            # Use recent data as "current"
            recent_count = min(len(all_values) // 10, 100)
            current_values = all_values[-recent_count:]
            current_density = self.stats_service.calculate_density_distribution(current_values, bins=50)
        
        return {
            'normal': normal_density,
            'current': current_density,
            'metric': metric,
            'compare_user': compare_user
        }
    
    def generate_ewma_control_chart(self, log_file_id: str, metric: str = 'risk_score',
                                   user: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate EWMA control chart
        Shows mean, upper/lower control limits
        
        Args:
            log_file_id: Log file ID
            metric: Metric to analyze
            user: Optional user filter
        
        Returns:
            Dictionary with EWMA control chart data
        """
        entries = self.log_entry_repo.get_by_file(log_file_id)
        
        if user:
            entries = [e for e in entries if e.username == user]
        
        if not entries:
            return self._empty_control_chart()
        
        # Sort by timestamp
        entries = sorted(entries, key=lambda e: e.timestamp)
        
        # Extract metric values
        if metric == 'risk_score':
            values = [e.risk_score or 0 for e in entries]
        elif metric == 'bytes_uploaded':
            values = [e.source_bytes or 0 for e in entries]
        elif metric == 'request_count':
            # Group by time bucket and count
            time_buckets = defaultdict(int)
            for e in entries:
                bucket = e.timestamp.replace(minute=0, second=0, microsecond=0)
                time_buckets[bucket] += 1
            values = list(time_buckets.values())
            entries = [entries[0]]  # Dummy for timestamps
        else:
            values = [e.risk_score or 0 for e in entries]
        
        # Calculate EWMA
        ewma_values = self.stats_service.calculate_ewma(values, alpha=0.3)
        
        # Calculate control limits based on EWMA
        control_limits = self.stats_service.calculate_control_limits(ewma_values, sigma=2.0)
        
        # Timestamps
        timestamps = [e.timestamp.isoformat() for e in entries]
        
        return {
            'timestamps': timestamps,
            'values': values,
            'ewma': ewma_values,
            'mean': control_limits['mean'],
            'upper_limit': control_limits['upper_limit'],
            'lower_limit': control_limits['lower_limit'],
            'std_dev': control_limits['std_dev'],
            'metric': metric,
            'user': user
        }
    
    def _empty_trendline(self) -> Dict[str, Any]:
        """Return empty trendline data"""
        return {
            'timestamps': [],
            'risk_scores': [],
            'moving_avg': [],
            'ewma': [],
            'upper_band': [],
            'lower_band': [],
            'mean': 0,
            'std_dev': 0,
            'count': 0
        }
    
    def _empty_heatmap(self) -> Dict[str, Any]:
        """Return empty heatmap data"""
        return {
            'users': [],
            'time_buckets': [],
            'z_scores': [],
            'metric': ''
        }
    
    def _empty_control_chart(self) -> Dict[str, Any]:
        """Return empty control chart data"""
        return {
            'timestamps': [],
            'values': [],
            'ewma': [],
            'mean': 0,
            'upper_limit': 0,
            'lower_limit': 0,
            'std_dev': 0,
            'metric': '',
            'user': None
        }

