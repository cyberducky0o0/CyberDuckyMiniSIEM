"""
LogFile model - represents uploaded log files
"""
from app.extensions import db
from datetime import datetime
import uuid

class LogFile(db.Model):
    __tablename__ = 'log_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64), index=True)
    log_type = db.Column(db.String(50), nullable=False, default='zscaler')  # zscaler, apache, etc.
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)  # pending, processing, completed, failed
    error_message = db.Column(db.Text)
    total_entries = db.Column(db.Integer, default=0)
    parsed_entries = db.Column(db.Integer, default=0)
    failed_entries = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    
    # Relationships
    log_entries = db.relationship('LogEntry', backref='log_file', lazy='dynamic', cascade='all, delete-orphan')
    anomalies = db.relationship('Anomaly', backref='log_file', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'filename': self.original_filename,  # Use original filename for display
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'log_type': self.log_type,
            'upload_status': self.status,  # Frontend expects 'upload_status'
            'status': self.status,  # Keep for backward compatibility
            'error_message': self.error_message,
            'total_entries': self.total_entries,
            'parsed_entries': self.parsed_entries,
            'failed_entries': self.failed_entries,
            'uploaded_at': self.created_at.isoformat() if self.created_at else None,  # Frontend expects 'uploaded_at'
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None
        }
    
    def __repr__(self):
        return f'<LogFile {self.filename} ({self.status})>'

