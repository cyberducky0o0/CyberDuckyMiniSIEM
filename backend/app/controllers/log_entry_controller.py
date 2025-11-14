"""
Log Entry Controller - Individual log entry access
"""
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.repositories.log_entry_repository import LogEntryRepository
from app.repositories.log_file_repository import LogFileRepository

log_entry_bp = Blueprint('log_entries', __name__)
log_entry_repo = LogEntryRepository()
log_file_repo = LogFileRepository()

@log_entry_bp.route('/<log_entry_id>', methods=['GET'])
@jwt_required()
def get_log_entry(log_entry_id):
    """Get a single log entry by ID"""
    try:
        user_id = get_jwt_identity()
        log_entry = log_entry_repo.get_by_id(log_entry_id)
        
        if not log_entry:
            return jsonify({'error': 'Log entry not found'}), 404
        
        # Check authorization through log_file
        log_file = log_file_repo.get_by_id(log_entry.log_file_id)
        if not log_file or log_file.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        return jsonify(log_entry.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

