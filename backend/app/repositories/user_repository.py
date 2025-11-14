"""
User repository
"""
from typing import Optional
from app.models.user import User
from app.repositories.base_repository import BaseRepository

class UserRepository(BaseRepository[User]):
    """Repository for User model"""
    
    def __init__(self):
        super().__init__(User)
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.model.query.filter_by(email=email).first()
    
    def email_exists(self, email: str) -> bool:
        """Check if email exists"""
        return self.model.query.filter_by(email=email).count() > 0

