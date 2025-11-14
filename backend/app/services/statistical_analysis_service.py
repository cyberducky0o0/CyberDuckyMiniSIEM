"""
Statistical Analysis Service
Provides statistical calculations for anomaly detection and visualization
Includes: Z-score, EWMA, percentiles, correlation, moving averages, control charts
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
from scipy import stats
from app.models.log_entry import LogEntry
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.normalized_event_repository import NormalizedEventRepository

logger = logging.getLogger(__name__)

class StatisticalAnalysisService:
    """
    Statistical analysis service for SOC analysts
    Provides advanced statistical methods for anomaly detection
    """
    
    def __init__(self):
        self.log_entry_repo = LogEntryRepository()
        self.event_repo = NormalizedEventRepository()
        
        # Statistical thresholds
        self.Z_SCORE_THRESHOLD = 3.0
        self.PERCENTILE_THRESHOLD = 99
        self.EWMA_ALPHA = 0.3  # Smoothing factor for EWMA
        self.CONTROL_LIMIT_SIGMA = 2.0  # Control chart limits (2σ)
        self.CORRELATION_THRESHOLD = 0.7
    
    def calculate_z_score(self, values: List[float], current_value: float) -> float:
        """
        Calculate Z-score for a value
        Z-score = (value - mean) / std_dev
        
        Args:
            values: Historical values
            current_value: Current value to score
        
        Returns:
            Z-score (number of standard deviations from mean)
        """
        if not values or len(values) < 2:
            return 0.0
        
        mean = np.mean(values)
        std_dev = np.std(values)
        
        if std_dev == 0:
            return 0.0
        
        z_score = (current_value - mean) / std_dev
        return float(z_score)
    
    def calculate_z_scores_series(self, values: List[float]) -> List[float]:
        """
        Calculate Z-scores for entire series
        
        Args:
            values: Time series values
        
        Returns:
            List of Z-scores
        """
        if not values or len(values) < 2:
            return [0.0] * len(values)
        
        mean = np.mean(values)
        std_dev = np.std(values)
        
        if std_dev == 0:
            return [0.0] * len(values)
        
        z_scores = [(v - mean) / std_dev for v in values]
        return z_scores
    
    def calculate_ewma(self, values: List[float], alpha: Optional[float] = None) -> List[float]:
        """
        Calculate Exponentially Weighted Moving Average (EWMA)
        EWMA_t = α * value_t + (1 - α) * EWMA_{t-1}
        
        Args:
            values: Time series values
            alpha: Smoothing factor (0 < α < 1), default 0.3
        
        Returns:
            List of EWMA values
        """
        if not values:
            return []
        
        alpha = alpha or self.EWMA_ALPHA
        ewma_values = [values[0]]  # Initialize with first value
        
        for i in range(1, len(values)):
            ewma = alpha * values[i] + (1 - alpha) * ewma_values[-1]
            ewma_values.append(ewma)
        
        return ewma_values
    
    def calculate_control_limits(self, values: List[float], sigma: Optional[float] = None) -> Dict[str, float]:
        """
        Calculate control chart limits (mean ± σ)
        
        Args:
            values: Historical values
            sigma: Number of standard deviations for limits (default 2.0)
        
        Returns:
            Dictionary with mean, upper_limit, lower_limit
        """
        if not values or len(values) < 2:
            return {'mean': 0.0, 'upper_limit': 0.0, 'lower_limit': 0.0}
        
        sigma = sigma or self.CONTROL_LIMIT_SIGMA
        mean = np.mean(values)
        std_dev = np.std(values)
        
        return {
            'mean': float(mean),
            'upper_limit': float(mean + sigma * std_dev),
            'lower_limit': float(mean - sigma * std_dev),
            'std_dev': float(std_dev)
        }
    
    def calculate_percentile(self, values: List[float], percentile: int = 99) -> float:
        """
        Calculate percentile value
        
        Args:
            values: Historical values
            percentile: Percentile to calculate (0-100)
        
        Returns:
            Percentile value
        """
        if not values:
            return 0.0
        
        return float(np.percentile(values, percentile))
    
    def calculate_moving_average(self, values: List[float], window: int = 10) -> List[float]:
        """
        Calculate simple moving average
        
        Args:
            values: Time series values
            window: Window size for moving average
        
        Returns:
            List of moving average values
        """
        if not values or len(values) < window:
            return values
        
        moving_avg = []
        for i in range(len(values)):
            if i < window - 1:
                # Not enough data for full window, use available data
                moving_avg.append(np.mean(values[:i+1]))
            else:
                moving_avg.append(np.mean(values[i-window+1:i+1]))
        
        return moving_avg
    
    def calculate_correlation(self, series1: List[float], series2: List[float]) -> float:
        """
        Calculate Pearson correlation coefficient
        
        Args:
            series1: First time series
            series2: Second time series
        
        Returns:
            Correlation coefficient (-1 to 1)
        """
        if not series1 or not series2 or len(series1) != len(series2) or len(series1) < 2:
            return 0.0
        
        correlation, _ = stats.pearsonr(series1, series2)
        return float(correlation)
    
    def detect_outliers_iqr(self, values: List[float]) -> List[int]:
        """
        Detect outliers using Interquartile Range (IQR) method
        Outliers are values outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR]
        
        Args:
            values: Values to analyze
        
        Returns:
            List of indices of outliers
        """
        if not values or len(values) < 4:
            return []
        
        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        outliers = [i for i, v in enumerate(values) if v < lower_bound or v > upper_bound]
        return outliers
    
    def calculate_boxplot_stats(self, values: List[float]) -> Dict[str, Any]:
        """
        Calculate statistics for boxplot visualization
        
        Args:
            values: Values to analyze
        
        Returns:
            Dictionary with min, q1, median, q3, max, outliers
        """
        if not values:
            return {
                'min': 0, 'q1': 0, 'median': 0, 'q3': 0, 'max': 0,
                'outliers': [], 'mean': 0, 'std_dev': 0
            }
        
        sorted_values = sorted(values)
        outlier_indices = self.detect_outliers_iqr(values)
        outlier_values = [values[i] for i in outlier_indices]
        
        return {
            'min': float(np.min(values)),
            'q1': float(np.percentile(values, 25)),
            'median': float(np.median(values)),
            'q3': float(np.percentile(values, 75)),
            'max': float(np.max(values)),
            'mean': float(np.mean(values)),
            'std_dev': float(np.std(values)),
            'outliers': outlier_values,
            'outlier_count': len(outlier_values)
        }
    
    def calculate_density_distribution(self, values: List[float], bins: int = 50) -> Dict[str, Any]:
        """
        Calculate density distribution for density plot
        
        Args:
            values: Values to analyze
            bins: Number of bins for histogram
        
        Returns:
            Dictionary with histogram data and KDE
        """
        if not values:
            return {'bins': [], 'counts': [], 'density': []}
        
        # Calculate histogram
        counts, bin_edges = np.histogram(values, bins=bins)
        bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
        
        # Calculate kernel density estimate
        try:
            from scipy.stats import gaussian_kde
            kde = gaussian_kde(values)
            density = kde(bin_centers)
        except:
            density = counts / np.sum(counts)
        
        return {
            'bins': bin_centers.tolist(),
            'counts': counts.tolist(),
            'density': density.tolist() if isinstance(density, np.ndarray) else density,
            'mean': float(np.mean(values)),
            'std_dev': float(np.std(values))
        }
    
    def detect_burst(self, values: List[float], window: int = 10, threshold_sigma: float = 2.0) -> List[int]:
        """
        Detect bursts (sudden spikes) in time series
        Burst = value > moving_average + threshold_sigma * std_dev
        
        Args:
            values: Time series values
            window: Window size for moving average
            threshold_sigma: Number of standard deviations for threshold
        
        Returns:
            List of indices where bursts occur
        """
        if not values or len(values) < window:
            return []
        
        moving_avg = self.calculate_moving_average(values, window)
        bursts = []
        
        for i in range(window, len(values)):
            window_values = values[i-window:i]
            mean = np.mean(window_values)
            std_dev = np.std(window_values)
            
            if std_dev > 0:
                threshold = mean + threshold_sigma * std_dev
                if values[i] > threshold:
                    bursts.append(i)
        
        return bursts
    
    def calculate_rolling_statistics(self, values: List[float], window: int = 10) -> Dict[str, List[float]]:
        """
        Calculate rolling statistics (mean, std, min, max)
        
        Args:
            values: Time series values
            window: Window size
        
        Returns:
            Dictionary with rolling mean, std, min, max
        """
        if not values or len(values) < window:
            return {
                'rolling_mean': values,
                'rolling_std': [0.0] * len(values),
                'rolling_min': values,
                'rolling_max': values
            }
        
        rolling_mean = []
        rolling_std = []
        rolling_min = []
        rolling_max = []
        
        for i in range(len(values)):
            if i < window - 1:
                window_values = values[:i+1]
            else:
                window_values = values[i-window+1:i+1]
            
            rolling_mean.append(np.mean(window_values))
            rolling_std.append(np.std(window_values))
            rolling_min.append(np.min(window_values))
            rolling_max.append(np.max(window_values))
        
        return {
            'rolling_mean': rolling_mean,
            'rolling_std': rolling_std,
            'rolling_min': rolling_min,
            'rolling_max': rolling_max
        }
    
    def is_anomaly_z_score(self, values: List[float], current_value: float, threshold: Optional[float] = None) -> bool:
        """
        Check if current value is anomaly based on Z-score
        
        Args:
            values: Historical values
            current_value: Current value to check
            threshold: Z-score threshold (default 3.0)
        
        Returns:
            True if anomaly, False otherwise
        """
        threshold = threshold or self.Z_SCORE_THRESHOLD
        z_score = self.calculate_z_score(values, current_value)
        return abs(z_score) > threshold
    
    def is_anomaly_percentile(self, values: List[float], current_value: float, percentile: Optional[int] = None) -> bool:
        """
        Check if current value exceeds percentile threshold
        
        Args:
            values: Historical values
            current_value: Current value to check
            percentile: Percentile threshold (default 99)
        
        Returns:
            True if anomaly, False otherwise
        """
        percentile = percentile or self.PERCENTILE_THRESHOLD
        threshold = self.calculate_percentile(values, percentile)
        return current_value > threshold

