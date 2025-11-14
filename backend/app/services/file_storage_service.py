"""
File Storage Service
"""
import os
import hashlib
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import current_app
from app.models.log_file import LogFile
from app.repositories.log_file_repository import LogFileRepository

class FileStorageService:
    """Service for file storage operations"""
    
    def __init__(self):
        self.log_file_repo = LogFileRepository()
    
    def save_uploaded_file(self, file: FileStorage, user_id: str, 
                          log_type: str = 'zscaler') -> LogFile:
        """
        Save uploaded file and create database record
        
        Args:
            file: Uploaded file
            user_id: User ID
            log_type: Type of log file
            
        Returns:
            Created LogFile record
            
        Raises:
            ValueError: If file is invalid
        """
        # Validate file
        if not file or not file.filename:
            raise ValueError("No file provided")
        
        if not self._allowed_file(file.filename):
            raise ValueError("Invalid file type. Allowed: .log, .txt, .csv")
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        file_hash = self._calculate_hash(file)
        
        # Check for duplicate - only for the same user
        existing = self.log_file_repo.get_by_hash(file_hash)
        if existing and existing.user_id == user_id:
            # Return existing file instead of error - user can reprocess if needed
            return existing
        
        unique_filename = f"{file_hash}_{original_filename}"
        
        # Save file
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        
        file.seek(0)  # Reset after hash calculation
        file.save(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Create database record
        log_file = self.log_file_repo.create(
            user_id=user_id,
            filename=unique_filename,
            original_filename=original_filename,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            log_type=log_type,
            status='pending'
        )
        
        return log_file
    
    def _allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed"""
        allowed = current_app.config['ALLOWED_EXTENSIONS']
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed
    
    def _calculate_hash(self, file: FileStorage) -> str:
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        for chunk in iter(lambda: file.read(4096), b''):
            sha256.update(chunk)
        return sha256.hexdigest()
    
    def delete_file(self, log_file_id: str, user_id: str) -> bool:
        """Delete log file"""
        log_file = self.log_file_repo.get_by_id(log_file_id)
        
        if not log_file:
            raise ValueError("Log file not found")
        
        if log_file.user_id != user_id:
            raise ValueError("Unauthorized")
        
        # Delete physical file
        if os.path.exists(log_file.file_path):
            os.remove(log_file.file_path)
        
        # Delete database record (cascade will delete entries and anomalies)
        return self.log_file_repo.delete(log_file)

