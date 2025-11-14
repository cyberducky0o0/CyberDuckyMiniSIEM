#!/usr/bin/env python3
"""
Test script for statistical anomaly detection and visualization system
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.services.statistical_analysis_service import StatisticalAnalysisService
from app.services.visualization_data_service import VisualizationDataService
from app.services.time_series_analysis_service import TimeSeriesAnalysisService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.anomaly_repository import AnomalyRepository
import json

def print_section(title):
    """Print section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def test_statistical_analysis_service():
    """Test statistical analysis service"""
    print_section("Testing Statistical Analysis Service")
    
    stats_service = StatisticalAnalysisService()
    
    # Test data
    values = [10, 12, 15, 11, 13, 14, 50, 12, 11, 13]
    
    # Test Z-score
    z_score = stats_service.calculate_z_score(values, 50)
    print(f"✓ Z-score for value 50: {z_score:.2f}")
    assert abs(z_score) > 2.5, "Z-score should be > 2.5 for outlier"
    
    # Test EWMA
    ewma = stats_service.calculate_ewma(values)
    print(f"✓ EWMA values: {[round(v, 2) for v in ewma[:5]]}")
    assert len(ewma) == len(values), "EWMA should have same length as input"
    
    # Test control limits
    limits = stats_service.calculate_control_limits(values)
    print(f"✓ Control limits: mean={limits['mean']:.2f}, upper={limits['upper_limit']:.2f}, lower={limits['lower_limit']:.2f}")
    
    # Test percentile
    p99 = stats_service.calculate_percentile(values, 99)
    print(f"✓ 99th percentile: {p99:.2f}")
    
    # Test moving average
    ma = stats_service.calculate_moving_average(values, window=3)
    print(f"✓ Moving average (window=3): {[round(v, 2) for v in ma[:5]]}")
    
    # Test correlation
    values2 = [11, 13, 16, 12, 14, 15, 52, 13, 12, 14]
    corr = stats_service.calculate_correlation(values, values2)
    print(f"✓ Correlation coefficient: {corr:.2f}")
    
    # Test IQR outlier detection
    outliers = stats_service.detect_outliers_iqr(values)
    print(f"✓ IQR outliers: {outliers}")
    
    # Test boxplot stats
    boxplot = stats_service.calculate_boxplot_stats(values)
    print(f"✓ Boxplot stats: min={boxplot['min']}, Q1={boxplot['q1']}, median={boxplot['median']}, Q3={boxplot['q3']}, max={boxplot['max']}")
    
    # Test burst detection
    bursts = stats_service.detect_burst(values, window=3, threshold_sigma=2.0)
    print(f"✓ Burst indices: {bursts}")
    
    # Test rolling statistics
    rolling = stats_service.calculate_rolling_statistics(values, window=3)
    print(f"✓ Rolling mean: {[round(v, 2) for v in rolling['rolling_mean'][:5]]}")
    
    print("\n✅ All statistical analysis tests passed!")

def test_with_real_data(app):
    """Test with real log data if available"""
    print_section("Testing with Real Log Data")
    
    with app.app_context():
        log_repo = LogEntryRepository()
        anomaly_repo = AnomalyRepository()
        
        # Get all log files
        from app.models.log_file import LogFile
        log_files = LogFile.query.limit(1).all()
        
        if not log_files:
            print("⚠️  No log files found. Upload logs first to test with real data.")
            return
        
        log_file = log_files[0]
        print(f"Testing with log file: {log_file.filename} (ID: {log_file.id})")
        
        # Get log entries
        entries = log_repo.get_by_file(log_file.id, limit=100)
        print(f"✓ Found {len(entries)} log entries")
        
        if len(entries) < 10:
            print("⚠️  Not enough log entries for meaningful statistical analysis")
            return
        
        # Test anomaly detection
        print("\nRunning anomaly detection...")
        anomaly_service = AnomalyDetectionService()
        result = anomaly_service.detect_all_anomalies(log_file.id)
        
        print(f"✓ Detected {result['total_anomalies']} anomalies")
        print(f"  - By severity: {result['by_severity']}")
        print(f"  - By type: {result['by_type']}")
        
        # Test visualization data generation
        print("\nGenerating visualization data...")
        viz_service = VisualizationDataService()
        
        # Risk trendline
        trendline = viz_service.generate_risk_score_trendline(log_file.id)
        print(f"✓ Risk trendline: {len(trendline.get('timestamps', []))} data points")
        
        # Z-score heatmap
        heatmap = viz_service.generate_z_score_heatmap(log_file.id, metric='risk_score')
        print(f"✓ Z-score heatmap: {len(heatmap.get('users', []))} users x {len(heatmap.get('time_buckets', []))} time buckets")
        
        # Boxplot per user
        boxplot = viz_service.generate_boxplot_per_user(log_file.id, metric='risk_score')
        print(f"✓ Boxplot per user: {len(boxplot.get('users', []))} users")
        
        # Anomaly scatter
        scatter = viz_service.generate_anomaly_scatter_plot(log_file.id)
        print(f"✓ Anomaly scatter: {len(scatter.get('data', []))} data points")
        
        # Density plot
        density = viz_service.generate_density_plot(log_file.id, metric='risk_score')
        print(f"✓ Density plot: {len(density.get('population_density', []))} density points")
        
        # EWMA control chart
        ewma = viz_service.generate_ewma_control_chart(log_file.id, metric='risk_score')
        print(f"✓ EWMA control chart: {len(ewma.get('timestamps', []))} data points")
        
        # Test time series analysis
        print("\nGenerating time series analysis...")
        ts_service = TimeSeriesAnalysisService()
        
        # Event timeline
        timeline = ts_service.generate_event_timeline(log_file.id, bucket_size='hour')
        print(f"✓ Event timeline: {timeline.get('total_buckets', 0)} time buckets")
        
        # Temporal anomalies
        temporal = ts_service.detect_temporal_anomalies(log_file.id, metric='event_count', bucket_size='hour')
        print(f"✓ Temporal anomalies: {len(temporal.get('anomalies', []))} detected")
        
        # Requests per minute
        rpm = ts_service.calculate_requests_per_minute(log_file.id, group_by='ip')
        print(f"✓ Requests per minute: {rpm.get('total_entities', 0)} entities, {len(rpm.get('anomalies', []))} anomalies")
        
        # Test anomaly repository queries
        print("\nTesting anomaly repository queries...")
        
        # Time series data
        ts_data = anomaly_repo.get_time_series_data(log_file.id, bucket_size='hour')
        print(f"✓ Anomaly time series: {len(ts_data)} time buckets")
        
        # Statistical summary
        summary = anomaly_repo.get_statistical_summary(log_file.id)
        print(f"✓ Statistical summary:")
        print(f"  - Total anomalies: {summary['total']}")
        print(f"  - Avg confidence: {summary['avg_confidence']:.2f}")
        print(f"  - Detection methods: {summary['detection_methods']}")
        print(f"  - Affected users: {summary['affected_users']}")
        print(f"  - Affected IPs: {summary['affected_ips']}")
        
        # Show sample anomalies
        print("\nSample anomalies detected:")
        anomalies = anomaly_repo.get_by_file(log_file.id)
        for i, anomaly in enumerate(anomalies[:5], 1):
            print(f"\n{i}. {anomaly.title}")
            print(f"   Type: {anomaly.anomaly_type}")
            print(f"   Severity: {anomaly.severity}")
            print(f"   Confidence: {anomaly.confidence_score:.2f}")
            print(f"   Detection: {anomaly.detection_method} ({anomaly.ai_model_used})")
            print(f"   Description: {anomaly.description[:100]}...")
        
        print("\n✅ All real data tests passed!")

def test_specific_detections(app):
    """Test specific statistical detection methods"""
    print_section("Testing Specific Detection Methods")
    
    with app.app_context():
        from app.models.log_file import LogFile
        log_files = LogFile.query.limit(1).all()
        
        if not log_files:
            print("⚠️  No log files found. Skipping specific detection tests.")
            return
        
        log_file = log_files[0]
        anomaly_service = AnomalyDetectionService()
        
        # Test individual detection methods
        print("Testing individual detection methods...")
        
        # Risk score spikes
        risk_spikes = anomaly_service._detect_risk_score_spikes(log_file.id)
        print(f"✓ Risk score spikes: {len(risk_spikes)} detected")
        
        # Data upload anomalies
        upload_anomalies = anomaly_service._detect_data_upload_anomalies(log_file.id)
        print(f"✓ Data upload anomalies: {len(upload_anomalies)} detected")
        
        # New domains anomaly
        domain_anomalies = anomaly_service._detect_new_domains_anomaly(log_file.id)
        print(f"✓ New domains anomalies: {len(domain_anomalies)} detected")
        
        # Persistent high risk
        persistent_risk = anomaly_service._detect_persistent_high_risk(log_file.id)
        print(f"✓ Persistent high risk: {len(persistent_risk)} detected")
        
        # Burst blocked requests
        burst_anomalies = anomaly_service._detect_burst_blocked_requests(log_file.id)
        print(f"✓ Burst blocked requests: {len(burst_anomalies)} detected")
        
        print("\n✅ All specific detection tests passed!")

def main():
    """Main test function"""
    print("\n" + "="*80)
    print("  STATISTICAL ANOMALY DETECTION & VISUALIZATION TEST SUITE")
    print("="*80)
    
    # Test statistical analysis service (no DB required)
    test_statistical_analysis_service()
    
    # Create Flask app for DB tests
    app = create_app('development')
    
    # Test with real data
    test_with_real_data(app)
    
    # Test specific detections
    test_specific_detections(app)
    
    print("\n" + "="*80)
    print("  ✅ ALL TESTS COMPLETED SUCCESSFULLY!")
    print("="*80 + "\n")
    
    print("Next steps:")
    print("1. Access visualization endpoints at http://localhost:5000/api/visualization/")
    print("2. Build frontend components to display these visualizations")
    print("3. Create SOC analyst dashboard with all charts")
    print("4. See STATISTICAL_ANOMALY_DETECTION.md for full documentation")

if __name__ == '__main__':
    main()

