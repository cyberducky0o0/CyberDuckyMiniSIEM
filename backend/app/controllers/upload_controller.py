"""
Upload Controller
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.file_storage_service import FileStorageService
from app.services.log_parser_service import LogParserService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.repositories.log_file_repository import LogFileRepository
import logging

upload_bp = Blueprint('upload', __name__)
file_storage_service = FileStorageService()
log_parser_service = LogParserService()
anomaly_detection_service = AnomalyDetectionService()
log_file_repo = LogFileRepository()

logger = logging.getLogger(__name__)

@upload_bp.route('', methods=['POST'])
@jwt_required()
def upload_file():
    """Upload a log file"""
    try:
        user_id = get_jwt_identity()
        
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        log_type = request.form.get('log_type', 'zscaler')
        
        # Save file
        log_file = file_storage_service.save_uploaded_file(file, user_id, log_type)
        
        # Start parsing (in production, this would be async with Celery)
        try:
            parse_result = log_parser_service.parse_log_file(log_file.id)
            logger.info(f"Parsed {parse_result['parsed_count']} entries from {log_file.id}")
            
            # Run anomaly detection
            anomaly_result = anomaly_detection_service.detect_all_anomalies(log_file.id)
            logger.info(f"Detected {anomaly_result['total_anomalies']} anomalies in {log_file.id}")
            
        except Exception as e:
            logger.error(f"Error processing file {log_file.id}: {e}")
            # File is saved, but processing failed - user can retry
        
        # Refresh log_file to get updated stats
        log_file = log_file_repo.get_by_id(log_file.id)
        
        return jsonify({
            'message': 'File uploaded and processed successfully',
            'log_file': log_file.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@upload_bp.route('/<log_file_id>', methods=['GET'])
@jwt_required()
def get_upload(log_file_id):
    """Get upload status"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404
        
        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify(log_file.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@upload_bp.route('', methods=['GET'])
@jwt_required()
def list_uploads():
    """List user's uploads"""
    try:
        user_id = get_jwt_identity()
        log_files = log_file_repo.get_by_user(user_id)
        
        return jsonify({
            'log_files': [lf.to_dict() for lf in log_files]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@upload_bp.route('/<log_file_id>', methods=['DELETE'])
@jwt_required()
def delete_upload(log_file_id):
    """Delete upload"""
    try:
        user_id = get_jwt_identity()
        success = file_storage_service.delete_file(log_file_id, user_id)

        if success:
            return jsonify({'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'error': 'Failed to delete file'}), 500

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@upload_bp.route('/<log_file_id>/reprocess', methods=['POST'])
@jwt_required()
def reprocess_upload(log_file_id):
    """Reprocess a log file (re-parse and re-run anomaly detection)"""
    try:
        user_id = get_jwt_identity()
        log_file = log_file_repo.get_by_id(log_file_id)

        if not log_file:
            return jsonify({'error': 'Log file not found'}), 404

        if log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Delete existing log entries and anomalies
        from app.models.log_entry import LogEntry
        from app.models.anomaly import Anomaly
        from app.extensions import db

        # IMPORTANT: Delete anomalies first due to foreign key constraint on log_entries
        Anomaly.query.filter_by(log_file_id=log_file_id).delete()
        LogEntry.query.filter_by(log_file_id=log_file_id).delete()
        db.session.commit()

        logger.info(f"Reprocessing log file {log_file_id}")

        # Reset log file status
        log_file_repo.update(
            log_file,
            status='pending',
            total_entries=0,
            parsed_entries=0,
            failed_entries=0,
            processed_at=None,
            error_message=None
        )

        # Re-parse the file
        try:
            parse_result = log_parser_service.parse_log_file(log_file.id)
            logger.info(f"Re-parsed {parse_result['parsed_count']} entries from {log_file.id}")

            # Re-run anomaly detection
            anomaly_result = anomaly_detection_service.detect_all_anomalies(log_file.id)
            logger.info(f"Re-detected {anomaly_result['total_anomalies']} anomalies in {log_file.id}")

        except Exception as e:
            logger.error(f"Error reprocessing file {log_file.id}: {e}")
            return jsonify({'error': f'Reprocessing failed: {str(e)}'}), 500

        # Refresh log_file to get updated stats
        log_file = log_file_repo.get_by_id(log_file.id)

        return jsonify({
            'message': 'File reprocessed successfully',
            'log_file': log_file.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Reprocess error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

