"""
LLM Controller - API endpoints for LLM-powered analysis
Provides intelligent log analysis, risk scoring, and investigation reports
"""
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.llm_analysis_service import LLMAnalysisService
from app.services.ollama_service import OllamaService
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.anomaly_repository import AnomalyRepository

logger = logging.getLogger(__name__)

llm_bp = Blueprint('llm', __name__)

# Initialize services
llm_service = LLMAnalysisService()
ollama_service = OllamaService()
log_entry_repo = LogEntryRepository()
anomaly_repo = AnomalyRepository()


@llm_bp.route('/status', methods=['GET'])
@jwt_required()
def get_llm_status():
    """
    Get LLM service status
    
    Returns:
        Service status, available models, and configuration
    """
    try:
        is_available = ollama_service.is_available()
        models = ollama_service.list_models() if is_available else []
        
        return jsonify({
            'available': is_available,
            'models': models,
            'default_model': llm_service.model,
            'base_url': ollama_service.base_url
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting LLM status: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/classify/<log_entry_id>', methods=['POST'])
@jwt_required()
def classify_log_event(log_entry_id):
    """
    Classify a single log event using LLM
    
    Args:
        log_entry_id: Log entry ID
        
    Returns:
        Classification result (normal, suspicious, malicious)
    """
    try:
        log_entry = log_entry_repo.get_by_id(log_entry_id)
        if not log_entry:
            return jsonify({'error': 'Log entry not found'}), 404
        
        result = llm_service.classify_log_event(log_entry)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error classifying log event: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/risk-score/<log_entry_id>', methods=['POST'])
@jwt_required()
def score_risk(log_entry_id):
    """
    Score risk of a log event using LLM
    
    Args:
        log_entry_id: Log entry ID
        
    Request Body (optional):
        context: Additional context for risk scoring
        
    Returns:
        Risk score (0-100), severity, reasoning
    """
    try:
        log_entry = log_entry_repo.get_by_id(log_entry_id)
        if not log_entry:
            return jsonify({'error': 'Log entry not found'}), 404
        
        data = request.get_json() or {}
        context = data.get('context')
        
        result = llm_service.score_risk(log_entry, context)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error scoring risk: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/summarize/<log_file_id>', methods=['POST'])
@jwt_required()
def summarize_events(log_file_id):
    """
    Summarize log events using LLM
    
    Args:
        log_file_id: Log file ID
        
    Request Body (optional):
        max_entries: Maximum entries to summarize (default: 50)
        
    Returns:
        Summary text, key findings, threat level
    """
    try:
        data = request.get_json() or {}
        max_entries = data.get('max_entries', 50)
        
        log_entries = log_entry_repo.get_by_file(log_file_id, limit=max_entries)
        
        if not log_entries:
            return jsonify({'error': 'No log entries found'}), 404
        
        result = llm_service.summarize_events(log_entries, max_entries)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error summarizing events: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/analyze-anomaly/<anomaly_id>', methods=['POST'])
@jwt_required()
def analyze_anomaly(anomaly_id):
    """
    Analyze an anomaly using LLM
    
    Args:
        anomaly_id: Anomaly ID
        
    Returns:
        Analysis with explanation, recommendations, urgency
    """
    try:
        anomaly = anomaly_repo.get_by_id(anomaly_id)
        if not anomaly:
            return jsonify({'error': 'Anomaly not found'}), 404
        
        # Get associated log entry
        log_entry = None
        if anomaly.log_entry_id:
            log_entry = log_entry_repo.get_by_id(anomaly.log_entry_id)
        
        result = llm_service.analyze_anomaly(anomaly, log_entry)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error analyzing anomaly: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/detect-pattern/<log_file_id>', methods=['POST'])
@jwt_required()
def detect_attack_pattern(log_file_id):
    """
    Detect attack patterns in log events
    
    Args:
        log_file_id: Log file ID
        
    Request Body (optional):
        user: Filter by username
        ip: Filter by IP address
        limit: Maximum entries to analyze (default: 20)
        
    Returns:
        Pattern detection results with attack type, confidence, IOCs
    """
    try:
        data = request.get_json() or {}
        user = data.get('user')
        ip = data.get('ip')
        limit = data.get('limit', 20)
        
        # Get log entries
        if user:
            log_entries = log_entry_repo.get_by_user(log_file_id, user, limit=limit)
        elif ip:
            log_entries = log_entry_repo.get_by_ip(log_file_id, ip, limit=limit)
        else:
            log_entries = log_entry_repo.get_by_file(log_file_id, limit=limit)
        
        if not log_entries:
            return jsonify({'error': 'No log entries found'}), 404
        
        result = llm_service.detect_attack_pattern(log_entries)
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error detecting pattern: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/investigation-report', methods=['POST'])
@jwt_required()
def generate_investigation_report():
    """
    Generate comprehensive investigation report
    
    Request Body:
        log_file_id: Log file ID
        user: Username to investigate (optional)
        ip: IP address to investigate (optional)
        
    Returns:
        Investigation report with findings, timeline, recommendations
    """
    try:
        data = request.get_json()
        if not data or 'log_file_id' not in data:
            return jsonify({'error': 'log_file_id required'}), 400
        
        log_file_id = data['log_file_id']
        user = data.get('user')
        ip = data.get('ip')
        
        # Get anomalies
        anomalies = anomaly_repo.get_by_file(log_file_id, limit=100)
        if user:
            anomalies = [a for a in anomalies if a.affected_user == user]
        if ip:
            anomalies = [a for a in anomalies if a.affected_ip == ip]
        
        # Get log entries
        if user:
            log_entries = log_entry_repo.get_by_user(log_file_id, user, limit=100)
        elif ip:
            log_entries = log_entry_repo.get_by_ip(log_file_id, ip, limit=100)
        else:
            log_entries = log_entry_repo.get_by_file(log_file_id, limit=100)
        
        if not anomalies and not log_entries:
            return jsonify({'error': 'No data found for investigation'}), 404
        
        result = llm_service.generate_investigation_report(
            anomalies=anomalies,
            log_entries=log_entries,
            user=user,
            ip=ip
        )
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error generating investigation report: {e}")
        return jsonify({'error': str(e)}), 500


@llm_bp.route('/batch-classify/<log_file_id>', methods=['POST'])
@jwt_required()
def batch_classify(log_file_id):
    """
    Classify multiple log events in batch
    
    Args:
        log_file_id: Log file ID
        
    Request Body (optional):
        limit: Maximum entries to classify (default: 10)
        
    Returns:
        List of classification results
    """
    try:
        data = request.get_json() or {}
        limit = min(data.get('limit', 10), 50)  # Cap at 50 to avoid timeouts
        
        log_entries = log_entry_repo.get_by_file(log_file_id, limit=limit)
        
        if not log_entries:
            return jsonify({'error': 'No log entries found'}), 404
        
        results = []
        for entry in log_entries:
            try:
                classification = llm_service.classify_log_event(entry)
                results.append({
                    'log_entry_id': entry.id,
                    'username': entry.username,
                    'url': entry.url or entry.hostname,
                    'classification': classification
                })
            except Exception as e:
                logger.error(f"Error classifying entry {entry.id}: {e}")
                results.append({
                    'log_entry_id': entry.id,
                    'error': str(e)
                })
        
        return jsonify({
            'total': len(results),
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error in batch classification: {e}")
        return jsonify({'error': str(e)}), 500

