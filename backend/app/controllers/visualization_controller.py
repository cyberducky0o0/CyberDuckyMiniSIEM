"""
Visualization Controller
Provides API endpoints for statistical visualizations and charts
"""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.visualization_data_service import VisualizationDataService
from app.services.time_series_analysis_service import TimeSeriesAnalysisService
from app.repositories.anomaly_repository import AnomalyRepository
import logging

logger = logging.getLogger(__name__)

visualization_bp = Blueprint('visualization', __name__, url_prefix='/api/visualization')

# Initialize services
viz_service = VisualizationDataService()
time_series_service = TimeSeriesAnalysisService()
anomaly_repo = AnomalyRepository()

@visualization_bp.route('/risk-trendline/<log_file_id>', methods=['GET'])
@jwt_required()
def get_risk_trendline(log_file_id: str):
    """
    Get risk score trendline with moving average and threshold bands
    
    Query params:
        - user: Optional username filter
    """
    try:
        user = request.args.get('user')
        data = viz_service.generate_risk_score_trendline(log_file_id, user=user)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating risk trendline: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/z-score-heatmap/<log_file_id>', methods=['GET'])
@jwt_required()
def get_z_score_heatmap(log_file_id: str):
    """
    Get Z-score heatmap (Users vs Time)
    
    Query params:
        - metric: Metric to analyze (risk_score, bytes_uploaded, request_count)
    """
    try:
        metric = request.args.get('metric', 'risk_score')
        data = viz_service.generate_z_score_heatmap(log_file_id, metric=metric)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating Z-score heatmap: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/boxplot-per-user/<log_file_id>', methods=['GET'])
@jwt_required()
def get_boxplot_per_user(log_file_id: str):
    """
    Get boxplot statistics per user
    
    Query params:
        - metric: Metric to analyze (risk_score, bytes_uploaded, bytes_downloaded)
    """
    try:
        metric = request.args.get('metric', 'risk_score')
        data = viz_service.generate_boxplot_per_user(log_file_id, metric=metric)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating boxplot: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/anomaly-scatter/<log_file_id>', methods=['GET'])
@jwt_required()
def get_anomaly_scatter(log_file_id: str):
    """
    Get anomaly scatter plot data
    X = risk score, Y = bytes uploaded, color = anomaly score
    """
    try:
        data = viz_service.generate_anomaly_scatter_plot(log_file_id)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating anomaly scatter: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/density-plot/<log_file_id>', methods=['GET'])
@jwt_required()
def get_density_plot(log_file_id: str):
    """
    Get density plot comparing normal vs current distribution
    
    Query params:
        - metric: Metric to analyze (risk_score, bytes_uploaded)
        - compare_user: Optional user to compare against population
    """
    try:
        metric = request.args.get('metric', 'risk_score')
        compare_user = request.args.get('compare_user')
        data = viz_service.generate_density_plot(log_file_id, metric=metric, compare_user=compare_user)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating density plot: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/ewma-control-chart/<log_file_id>', methods=['GET'])
@jwt_required()
def get_ewma_control_chart(log_file_id: str):
    """
    Get EWMA control chart
    
    Query params:
        - metric: Metric to analyze (risk_score, bytes_uploaded, request_count)
        - user: Optional username filter
    """
    try:
        metric = request.args.get('metric', 'risk_score')
        user = request.args.get('user')
        data = viz_service.generate_ewma_control_chart(log_file_id, metric=metric, user=user)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating EWMA control chart: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/event-timeline/<log_file_id>', methods=['GET'])
@jwt_required()
def get_event_timeline(log_file_id: str):
    """
    Get event timeline with temporal aggregations
    
    Query params:
        - bucket_size: Time bucket size (minute, hour, day)
    """
    try:
        bucket_size = request.args.get('bucket_size', 'hour')
        data = time_series_service.generate_event_timeline(log_file_id, bucket_size=bucket_size)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error generating event timeline: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/temporal-anomalies/<log_file_id>', methods=['GET'])
@jwt_required()
def get_temporal_anomalies(log_file_id: str):
    """
    Get temporal anomalies in event patterns
    
    Query params:
        - metric: Metric to analyze (event_count, avg_risk_score, total_bytes_uploaded)
        - bucket_size: Time bucket size (minute, hour, day)
    """
    try:
        metric = request.args.get('metric', 'event_count')
        bucket_size = request.args.get('bucket_size', 'hour')
        data = time_series_service.detect_temporal_anomalies(log_file_id, metric=metric, bucket_size=bucket_size)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error detecting temporal anomalies: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/user-activity-pattern/<log_file_id>/<username>', methods=['GET'])
@jwt_required()
def get_user_activity_pattern(log_file_id: str, username: str):
    """
    Get user activity pattern analysis
    """
    try:
        data = time_series_service.analyze_user_activity_pattern(log_file_id, username)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error analyzing user activity pattern: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/requests-per-minute/<log_file_id>', methods=['GET'])
@jwt_required()
def get_requests_per_minute(log_file_id: str):
    """
    Get requests per minute statistics
    
    Query params:
        - group_by: Group by 'ip' or 'user'
    """
    try:
        group_by = request.args.get('group_by', 'ip')
        data = time_series_service.calculate_requests_per_minute(log_file_id, group_by=group_by)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error calculating requests per minute: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/anomaly-time-series/<log_file_id>', methods=['GET'])
@jwt_required()
def get_anomaly_time_series(log_file_id: str):
    """
    Get anomaly time series data
    
    Query params:
        - bucket_size: Time bucket size (hour, day)
    """
    try:
        bucket_size = request.args.get('bucket_size', 'hour')
        data = anomaly_repo.get_time_series_data(log_file_id, bucket_size=bucket_size)
        return jsonify({'time_series': data}), 200
    except Exception as e:
        logger.error(f"Error getting anomaly time series: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/statistical-summary/<log_file_id>', methods=['GET'])
@jwt_required()
def get_statistical_summary(log_file_id: str):
    """
    Get comprehensive statistical summary for all visualizations
    """
    try:
        # Get anomaly statistics
        anomaly_stats = anomaly_repo.get_statistical_summary(log_file_id)
        
        # Get time series data
        timeline = time_series_service.generate_event_timeline(log_file_id, bucket_size='hour')
        
        # Get requests per minute
        rpm_data = time_series_service.calculate_requests_per_minute(log_file_id, group_by='ip')
        
        summary = {
            'anomaly_statistics': anomaly_stats,
            'timeline_summary': {
                'total_buckets': timeline.get('total_buckets', 0),
                'start_time': timeline.get('start_time'),
                'end_time': timeline.get('end_time')
            },
            'requests_per_minute': {
                'total_entities': rpm_data.get('total_entities', 0),
                'total_anomalies': len(rpm_data.get('anomalies', []))
            }
        }
        
        return jsonify(summary), 200
    except Exception as e:
        logger.error(f"Error getting statistical summary: {e}")
        return jsonify({'error': str(e)}), 500

@visualization_bp.route('/all-visualizations/<log_file_id>', methods=['GET'])
@jwt_required()
def get_all_visualizations(log_file_id: str):
    """
    Get all visualization data in one call (for dashboard)
    """
    try:
        data = {
            'risk_trendline': viz_service.generate_risk_score_trendline(log_file_id),
            'z_score_heatmap': viz_service.generate_z_score_heatmap(log_file_id, metric='risk_score'),
            'boxplot_per_user': viz_service.generate_boxplot_per_user(log_file_id, metric='risk_score'),
            'anomaly_scatter': viz_service.generate_anomaly_scatter_plot(log_file_id),
            'density_plot': viz_service.generate_density_plot(log_file_id, metric='risk_score'),
            'ewma_control_chart': viz_service.generate_ewma_control_chart(log_file_id, metric='risk_score'),
            'event_timeline': time_series_service.generate_event_timeline(log_file_id, bucket_size='hour'),
            'anomaly_time_series': {'time_series': anomaly_repo.get_time_series_data(log_file_id, bucket_size='hour')},
            'statistical_summary': anomaly_repo.get_statistical_summary(log_file_id)
        }
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error getting all visualizations: {e}")
        return jsonify({'error': str(e)}), 500

