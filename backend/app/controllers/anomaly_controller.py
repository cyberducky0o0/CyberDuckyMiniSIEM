"""
Anomaly Controller
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.repositories.log_file_repository import LogFileRepository
from app.repositories.anomaly_repository import AnomalyRepository

anomaly_bp = Blueprint('anomalies', __name__)
log_file_repo = LogFileRepository()
anomaly_repo = AnomalyRepository()

@anomaly_bp.route('/<log_file_id>', methods=['GET'])
@jwt_required()
def get_anomalies(log_file_id):
    """Get all anomalies for a log file with pagination and filtering"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)

        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404

        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search = request.args.get('search', '')
        severity = request.args.get('severity', '')

        # Get anomalies based on severity filter
        if severity and severity != 'all':
            anomalies = anomaly_repo.get_by_severity(log_file_id, severity)
        else:
            anomalies = anomaly_repo.get_by_file(log_file_id)

        # Apply search filter
        if search:
            search_lower = search.lower()
            anomalies = [a for a in anomalies if (
                search_lower in a.title.lower() or
                search_lower in a.description.lower() or
                (a.affected_user and search_lower in a.affected_user.lower()) or
                (a.affected_ip and search_lower in a.affected_ip.lower()) or
                search_lower in a.anomaly_type.lower()
            )]

        total = len(anomalies)
        offset = (page - 1) * per_page
        anomalies_page = anomalies[offset:offset + per_page]

        return jsonify({
            'anomalies': [a.to_dict() for a in anomalies_page],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/detail/<anomaly_id>', methods=['GET'])
@jwt_required()
def get_anomaly(anomaly_id):
    """Get specific anomaly details"""
    try:
        user_id = get_jwt_identity()
        anomaly = anomaly_repo.get_by_id(anomaly_id)
        
        if not anomaly:
            return jsonify({'error': 'Anomaly not found'}), 404
        
        # Check authorization through log_file
        log_file = log_file_repo.get_by_id(anomaly.log_file_id)
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify(anomaly.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@anomaly_bp.route('/detail/<anomaly_id>', methods=['PATCH'])
@jwt_required()
def update_anomaly(anomaly_id):
    """Update anomaly (e.g., mark as false positive)"""
    try:
        user_id = get_jwt_identity()
        anomaly = anomaly_repo.get_by_id(anomaly_id)
        
        if not anomaly:
            return jsonify({'error': 'Anomaly not found'}), 404
        
        # Check authorization
        log_file = log_file_repo.get_by_id(anomaly.log_file_id)
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Update allowed fields
        if 'status' in data:
            anomaly.status = data['status']
        if 'notes' in data:
            anomaly.notes = data['notes']
        if 'assigned_to' in data:
            anomaly.assigned_to = data['assigned_to']
        
        anomaly_repo.save(anomaly)
        
        return jsonify(anomaly.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

