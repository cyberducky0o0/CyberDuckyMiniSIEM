"""
LogFile repository
"""
from typing import List
from app.models.log_file import LogFile
from app.repositories.base_repository import BaseRepository

class LogFileRepository(BaseRepository[LogFile]):
    """Repository for LogFile model"""
    
    def __init__(self):
        super().__init__(LogFile)
    
    def get_by_user(self, user_id: str, limit: int = 100) -> List[LogFile]:
        """Get log files by user"""
        return self.model.query.filter_by(user_id=user_id)\
            .order_by(self.model.created_at.desc())\
            .limit(limit).all()
    
    def get_by_status(self, status: str, limit: int = 100) -> List[LogFile]:
        """Get log files by status"""
        return self.model.query.filter_by(status=status)\
            .order_by(self.model.created_at.desc())\
            .limit(limit).all()
    
    def get_by_hash(self, file_hash: str) -> LogFile:
        """Get log file by hash"""
        return self.model.query.filter_by(file_hash=file_hash).first()

