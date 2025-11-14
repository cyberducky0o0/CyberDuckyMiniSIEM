"""
Analysis Controller - SOC Analyst Dashboard Data
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.repositories.log_file_repository import LogFileRepository
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.anomaly_repository import AnomalyRepository

analysis_bp = Blueprint('analysis', __name__)
log_file_repo = LogFileRepository()
log_entry_repo = LogEntryRepository()
anomaly_repo = AnomalyRepository()

@analysis_bp.route('/<log_file_id>', methods=['GET'])
@jwt_required()
def get_analysis(log_file_id):
    """Get complete analysis for a log file"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404
        
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get statistics
        stats = log_entry_repo.get_statistics(log_file_id)
        anomaly_stats = anomaly_repo.get_statistics(log_file_id)
        
        # Get timeline data
        timeline = log_entry_repo.get_timeline_data(log_file_id, interval_minutes=5)
        
        # Get critical anomalies
        critical_anomalies = anomaly_repo.get_critical_anomalies(log_file_id)
        
        # Get high-risk entries
        high_risk_entries = log_entry_repo.get_high_risk_entries(log_file_id, risk_threshold=70)
        
        return jsonify({
            'log_file': log_file.to_dict(),
            'statistics': stats,
            'anomaly_statistics': anomaly_stats,
            'timeline': timeline,
            'critical_anomalies': [a.to_dict() for a in critical_anomalies[:10]],
            'high_risk_entries': [e.to_dict() for e in high_risk_entries[:20]]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/<log_file_id>/timeline', methods=['GET'])
@jwt_required()
def get_timeline(log_file_id):
    """Get timeline data"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404
        
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        interval_minutes = int(request.args.get('interval', 5))
        timeline = log_entry_repo.get_timeline_data(log_file_id, interval_minutes)
        
        return jsonify({'timeline': timeline}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/<log_file_id>/stats', methods=['GET'])
@jwt_required()
def get_stats(log_file_id):
    """Get statistics"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404
        
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        stats = log_entry_repo.get_statistics(log_file_id)
        anomaly_stats = anomaly_repo.get_statistics(log_file_id)
        
        return jsonify({
            'statistics': stats,
            'anomaly_statistics': anomaly_stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/<log_file_id>/entries', methods=['GET'])
@jwt_required()
def get_entries(log_file_id):
    """Get log entries with pagination and filtering"""
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
        filter_type = request.args.get('filter_type', 'all')

        # Calculate offset
        offset = (page - 1) * per_page

        # Get entries based on filter type
        if filter_type == 'threats':
            entries = log_entry_repo.get_threat_entries(log_file_id)
        elif filter_type == 'high_risk':
            entries = log_entry_repo.get_high_risk_entries(log_file_id)
        elif filter_type == 'bypassed':
            entries = log_entry_repo.get_bypassed_traffic(log_file_id)
        elif filter_type == 'blocked':
            entries = log_entry_repo.get_by_action(log_file_id, 'Blocked')
        elif filter_type == 'allowed':
            entries = log_entry_repo.get_by_action(log_file_id, 'Allowed')
        else:
            entries = log_entry_repo.get_by_file(log_file_id, limit=10000, offset=0)

        # Apply search filter
        if search:
            search_lower = search.lower()
            entries = [e for e in entries if (
                (e.username and search_lower in e.username.lower()) or
                (e.source_ip and search_lower in e.source_ip.lower()) or
                (e.destination_ip and search_lower in e.destination_ip.lower()) or
                (e.url and search_lower in e.url.lower()) or
                (e.threat_name and search_lower in e.threat_name.lower())
            )]

        total = len(entries)
        entries_page = entries[offset:offset + per_page]

        return jsonify({
            'entries': [e.to_dict() for e in entries_page],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/<log_file_id>/users', methods=['GET'])
@jwt_required()
def get_users(log_file_id):
    """Get unique users with pagination and search"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)

        if not log_file or log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search = request.args.get('search', '')

        users = log_entry_repo.get_unique_users_list(log_file_id)

        # Apply search
        if search:
            search_lower = search.lower()
            users = [u for u in users if search_lower in u['username'].lower()]

        total = len(users)
        offset = (page - 1) * per_page
        users_page = users[offset:offset + per_page]

        return jsonify({
            'users': users_page,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@analysis_bp.route('/<log_file_id>/ips', methods=['GET'])
@jwt_required()
def get_ips(log_file_id):
    """Get unique IPs with pagination and search"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)

        if not log_file or log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search = request.args.get('search', '')
        ip_type = request.args.get('ip_type', 'source')  # source or destination

        ips = log_entry_repo.get_unique_ips_list(log_file_id, ip_type)

        # Apply search
        if search:
            search_lower = search.lower()
            ips = [ip for ip in ips if search_lower in ip['ip_address'].lower()]

        total = len(ips)
        offset = (page - 1) * per_page
        ips_page = ips[offset:offset + per_page]

        return jsonify({
            'ips': ips_page,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

