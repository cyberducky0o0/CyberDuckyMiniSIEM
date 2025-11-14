"""
Dashboard Controller
Provides aggregated statistics and visualizations across all log files
"""
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.repositories.log_file_repository import LogFileRepository
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.anomaly_repository import AnomalyRepository
from sqlalchemy import func, desc
from app.models.log_entry import LogEntry
from app.models.anomaly import Anomaly
from app.extensions import db
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

# Initialize repositories
log_file_repo = LogFileRepository()
log_entry_repo = LogEntryRepository()
anomaly_repo = AnomalyRepository()

@dashboard_bp.route('/overview', methods=['GET'])
@jwt_required()
def get_dashboard_overview():
    """
    Get aggregated dashboard overview across all user's log files
    """
    try:
        user_id = get_jwt_identity()

        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401

        # Get all user's log files
        log_files = log_file_repo.get_by_user(user_id)

        if not log_files:
            log_files = []

        log_file_ids = [lf.id for lf in log_files if lf and lf.id]

        if not log_file_ids:
            return jsonify({
                'total_files': 0,
                'total_entries': 0,
                'total_anomalies': 0,
                'critical_anomalies': 0,
                'high_risk_entries': 0,
                'unique_users': 0,
                'unique_ips': 0,
                'threat_count': 0,
                'avg_risk_score': 0,
                'files_by_status': {},
                'recent_activity': []
            }), 200
        
        # Total entries across all files
        total_entries = db.session.query(func.count(LogEntry.id))\
            .filter(LogEntry.log_file_id.in_(log_file_ids)).scalar() or 0
        
        # Total anomalies
        total_anomalies = db.session.query(func.count(Anomaly.id))\
            .filter(Anomaly.log_file_id.in_(log_file_ids)).scalar() or 0
        
        # Critical anomalies
        critical_anomalies = db.session.query(func.count(Anomaly.id))\
            .filter(
                Anomaly.log_file_id.in_(log_file_ids),
                Anomaly.severity == 'critical'
            ).scalar() or 0
        
        # High risk entries
        high_risk_entries = db.session.query(func.count(LogEntry.id))\
            .filter(
                LogEntry.log_file_id.in_(log_file_ids),
                LogEntry.risk_score >= 70
            ).scalar() or 0
        
        # Unique users
        unique_users = db.session.query(func.count(func.distinct(LogEntry.username)))\
            .filter(
                LogEntry.log_file_id.in_(log_file_ids),
                LogEntry.username.isnot(None)
            ).scalar() or 0
        
        # Unique IPs
        unique_ips = db.session.query(func.count(func.distinct(LogEntry.source_ip)))\
            .filter(
                LogEntry.log_file_id.in_(log_file_ids),
                LogEntry.source_ip.isnot(None)
            ).scalar() or 0
        
        # Threat count
        threat_count = db.session.query(func.count(LogEntry.id))\
            .filter(
                LogEntry.log_file_id.in_(log_file_ids),
                LogEntry.threat_name.isnot(None)
            ).scalar() or 0
        
        # Average risk score
        avg_risk_score = db.session.query(func.avg(LogEntry.risk_score))\
            .filter(
                LogEntry.log_file_id.in_(log_file_ids),
                LogEntry.risk_score.isnot(None)
            ).scalar() or 0
        
        # Files by status
        files_by_status = {}
        for lf in log_files:
            status = lf.status
            files_by_status[status] = files_by_status.get(status, 0) + 1
        
        # Recent activity (last 10 files)
        recent_files = sorted(log_files, key=lambda x: x.created_at, reverse=True)[:10]
        recent_activity = [{
            'id': lf.id,
            'filename': lf.original_filename,
            'log_type': lf.log_type,
            'status': lf.status,
            'entries': lf.parsed_entries,
            'uploaded_at': lf.created_at.isoformat()
        } for lf in recent_files]
        
        return jsonify({
            'total_files': len(log_files),
            'total_entries': int(total_entries),
            'total_anomalies': int(total_anomalies),
            'critical_anomalies': int(critical_anomalies),
            'high_risk_entries': int(high_risk_entries),
            'unique_users': int(unique_users),
            'unique_ips': int(unique_ips),
            'threat_count': int(threat_count),
            'avg_risk_score': float(avg_risk_score),
            'files_by_status': files_by_status,
            'recent_activity': recent_activity
        }), 200

    except Exception as e:
        logger.error(f"Error getting dashboard overview: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/anomaly-trends', methods=['GET'])
@jwt_required()
def get_anomaly_trends():
    """
    Get anomaly trends over time across all files
    """
    try:
        user_id = get_jwt_identity()
        log_files = log_file_repo.get_by_user(user_id)
        log_file_ids = [lf.id for lf in log_files]

        if not log_file_ids:
            return jsonify({'time_series': [], 'by_severity': {}, 'by_type': []}), 200

        # Get anomalies grouped by hour
        anomalies = db.session.query(
            func.date_trunc('hour', Anomaly.detected_at).label('hour'),
            Anomaly.severity,
            func.count(Anomaly.id).label('count')
        ).filter(
            Anomaly.log_file_id.in_(log_file_ids)
        ).group_by('hour', Anomaly.severity)\
         .order_by('hour').all()

        # Organize by time bucket
        time_buckets = {}
        for hour, severity, count in anomalies:
            hour_str = hour.isoformat()
            if hour_str not in time_buckets:
                time_buckets[hour_str] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
            time_buckets[hour_str][severity] = int(count)
            time_buckets[hour_str]['total'] += int(count)

        # Convert to time series
        time_series = [
            {'timestamp': ts, **data}
            for ts, data in sorted(time_buckets.items())
        ]

        # By severity (total)
        by_severity = db.session.query(
            Anomaly.severity,
            func.count(Anomaly.id).label('count')
        ).filter(
            Anomaly.log_file_id.in_(log_file_ids)
        ).group_by(Anomaly.severity).all()

        severity_dict = {sev: int(count) for sev, count in by_severity}

        # By type (top 10)
        by_type = db.session.query(
            Anomaly.anomaly_type,
            func.count(Anomaly.id).label('count')
        ).filter(
            Anomaly.log_file_id.in_(log_file_ids)
        ).group_by(Anomaly.anomaly_type)\
         .order_by(desc('count'))\
         .limit(10).all()

        type_list = [{'type': atype, 'count': int(count)} for atype, count in by_type]

        return jsonify({
            'time_series': time_series,
            'by_severity': severity_dict,
            'by_type': type_list
        }), 200

    except Exception as e:
        logger.error(f"Error getting anomaly trends: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/top-threats', methods=['GET'])
@jwt_required()
def get_top_threats():
    """
    Get top threats across all files
    """
    try:
        user_id = get_jwt_identity()
        log_files = log_file_repo.get_by_user(user_id)
        log_file_ids = [lf.id for lf in log_files]

        if not log_file_ids:
            return jsonify({'threats': [], 'categories': [], 'users': [], 'ips': []}), 200

        # Top threats
        threats = db.session.query(
            LogEntry.threat_name,
            func.count(LogEntry.id).label('count'),
            func.avg(LogEntry.risk_score).label('avg_risk')
        ).filter(
            LogEntry.log_file_id.in_(log_file_ids),
            LogEntry.threat_name.isnot(None)
        ).group_by(LogEntry.threat_name)\
         .order_by(desc('count'))\
         .limit(10).all()

        threat_list = [{
            'name': name,
            'count': int(count),
            'avg_risk': float(avg_risk) if avg_risk else 0
        } for name, count, avg_risk in threats]

        # Top risky categories
        categories = db.session.query(
            LogEntry.url_category,
            func.count(LogEntry.id).label('count'),
            func.avg(LogEntry.risk_score).label('avg_risk')
        ).filter(
            LogEntry.log_file_id.in_(log_file_ids),
            LogEntry.url_category.isnot(None)
        ).group_by(LogEntry.url_category)\
         .order_by(desc('avg_risk'))\
         .limit(10).all()

        category_list = [{
            'category': cat,
            'count': int(count),
            'avg_risk': float(avg_risk) if avg_risk else 0
        } for cat, count, avg_risk in categories]

        # Top risky users
        users = db.session.query(
            LogEntry.username,
            func.count(LogEntry.id).label('count'),
            func.avg(LogEntry.risk_score).label('avg_risk'),
            func.max(LogEntry.risk_score).label('max_risk')
        ).filter(
            LogEntry.log_file_id.in_(log_file_ids),
            LogEntry.username.isnot(None)
        ).group_by(LogEntry.username)\
         .order_by(desc('avg_risk'))\
         .limit(10).all()

        user_list = [{
            'username': user,
            'count': int(count),
            'avg_risk': float(avg_risk) if avg_risk else 0,
            'max_risk': float(max_risk) if max_risk else 0
        } for user, count, avg_risk, max_risk in users]

        # Top risky IPs
        ips = db.session.query(
            LogEntry.source_ip,
            func.count(LogEntry.id).label('count'),
            func.avg(LogEntry.risk_score).label('avg_risk'),
            func.max(LogEntry.risk_score).label('max_risk')
        ).filter(
            LogEntry.log_file_id.in_(log_file_ids),
            LogEntry.source_ip.isnot(None)
        ).group_by(LogEntry.source_ip)\
         .order_by(desc('avg_risk'))\
         .limit(10).all()

        ip_list = [{
            'ip': ip,
            'count': int(count),
            'avg_risk': float(avg_risk) if avg_risk else 0,
            'max_risk': float(max_risk) if max_risk else 0
        } for ip, count, avg_risk, max_risk in ips]

        return jsonify({
            'threats': threat_list,
            'categories': category_list,
            'users': user_list,
            'ips': ip_list
        }), 200

    except Exception as e:
        logger.error(f"Error getting top threats: {e}")
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/all-files-stats', methods=['GET'])
@jwt_required()
def get_all_files_stats():
    """
    Get detailed statistics for all user's log files
    Returns list of files with anomaly counts, severity breakdown, and risk scores
    """
    try:
        user_id = get_jwt_identity()

        # Get all user's log files
        log_files = log_file_repo.get_by_user(user_id)

        if not log_files:
            return jsonify({'files': []}), 200

        files_with_stats = []

        for lf in log_files:
            # Get anomaly counts by severity
            anomaly_counts = db.session.query(
                Anomaly.severity,
                func.count(Anomaly.id).label('count')
            ).filter(
                Anomaly.log_file_id == lf.id
            ).group_by(Anomaly.severity).all()

            severity_dict = {sev: count for sev, count in anomaly_counts}
            total_anomalies = sum(severity_dict.values())

            # Get average risk score
            avg_risk = db.session.query(
                func.avg(LogEntry.risk_score)
            ).filter(
                LogEntry.log_file_id == lf.id,
                LogEntry.risk_score.isnot(None)
            ).scalar() or 0

            # Get threat count
            threat_count = db.session.query(
                func.count(LogEntry.id)
            ).filter(
                LogEntry.log_file_id == lf.id,
                LogEntry.threat_name.isnot(None)
            ).scalar() or 0

            files_with_stats.append({
                'id': lf.id,
                'filename': lf.original_filename,
                'log_type': lf.log_type,
                'status': lf.status,
                'total_entries': lf.parsed_entries or 0,
                'anomaly_count': total_anomalies,
                'critical_count': severity_dict.get('critical', 0),
                'high_count': severity_dict.get('high', 0),
                'medium_count': severity_dict.get('medium', 0),
                'low_count': severity_dict.get('low', 0),
                'avg_risk_score': float(avg_risk),
                'threat_count': threat_count,
                'uploaded_at': lf.created_at.isoformat() if lf.created_at else None
            })

        # Sort by upload date (most recent first)
        files_with_stats.sort(key=lambda x: x['uploaded_at'], reverse=True)

        return jsonify({'files': files_with_stats}), 200

    except Exception as e:
        logger.error(f"Error getting all files stats: {e}")
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/unified-analysis', methods=['GET'])
@jwt_required()
def get_unified_analysis():
    """
    Get unified analysis across all files with optional filters
    Query params: username, ip, threat_name, category, min_risk
    """
    try:
        user_id = get_jwt_identity()
        log_files = log_file_repo.get_by_user(user_id)
        log_file_ids = [lf.id for lf in log_files]

        if not log_file_ids:
            return jsonify({
                'log_entries': [],
                'anomalies': [],
                'statistics': {},
                'filters_applied': {}
            }), 200

        from flask import request

        # Get filter parameters
        username_filter = request.args.get('username')
        ip_filter = request.args.get('ip')
        threat_filter = request.args.get('threat_name')
        category_filter = request.args.get('category')
        min_risk = request.args.get('min_risk', type=float)

        # Build query for log entries
        query = LogEntry.query.filter(LogEntry.log_file_id.in_(log_file_ids))

        filters_applied = {}

        if username_filter:
            query = query.filter(LogEntry.username == username_filter)
            filters_applied['username'] = username_filter

        if ip_filter:
            query = query.filter(LogEntry.source_ip == ip_filter)
            filters_applied['ip'] = ip_filter

        if threat_filter:
            query = query.filter(LogEntry.threat_name == threat_filter)
            filters_applied['threat_name'] = threat_filter

        if category_filter:
            query = query.filter(LogEntry.url_category == category_filter)
            filters_applied['category'] = category_filter

        if min_risk:
            query = query.filter(LogEntry.risk_score >= min_risk)
            filters_applied['min_risk'] = min_risk

        # Get entries (limit to 100 for performance)
        entries = query.order_by(desc(LogEntry.timestamp)).limit(100).all()

        # Get anomalies for these entries
        entry_ids = [e.id for e in entries]
        anomalies = []
        if entry_ids:
            anomalies = Anomaly.query.filter(
                Anomaly.log_entry_id.in_(entry_ids)
            ).order_by(desc(Anomaly.severity), desc(Anomaly.confidence_score)).limit(50).all()

        # Calculate statistics
        total_count = query.count()
        avg_risk = db.session.query(func.avg(LogEntry.risk_score)).filter(
            LogEntry.id.in_(entry_ids) if entry_ids else False
        ).scalar() or 0

        high_risk_count = db.session.query(func.count(LogEntry.id)).filter(
            LogEntry.id.in_(entry_ids) if entry_ids else False,
            LogEntry.risk_score >= 70
        ).scalar() or 0

        # Get file breakdown
        file_breakdown = db.session.query(
            LogEntry.log_file_id,
            func.count(LogEntry.id).label('count')
        ).filter(
            LogEntry.id.in_(entry_ids) if entry_ids else False
        ).group_by(LogEntry.log_file_id).all()

        file_breakdown_dict = {}
        for file_id, count in file_breakdown:
            log_file = next((lf for lf in log_files if lf.id == file_id), None)
            if log_file:
                file_breakdown_dict[log_file.original_filename] = count

        return jsonify({
            'log_entries': [e.to_dict() for e in entries],
            'anomalies': [a.to_dict() for a in anomalies],
            'statistics': {
                'total_count': total_count,
                'avg_risk_score': float(avg_risk),
                'high_risk_count': high_risk_count,
                'anomaly_count': len(anomalies),
                'file_breakdown': file_breakdown_dict
            },
            'filters_applied': filters_applied
        }), 200

    except Exception as e:
        logger.error(f"Error getting unified analysis: {e}")
        return jsonify({'error': str(e)}), 500
