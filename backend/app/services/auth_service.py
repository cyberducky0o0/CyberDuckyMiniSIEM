"""
Authentication Service
"""
from typing import Dict, Any
from app.models.user import User
from app.repositories.user_repository import UserRepository
from flask_jwt_extended import create_access_token, create_refresh_token

class AuthService:
    """Service for authentication operations"""
    
    def __init__(self):
        self.user_repo = UserRepository()
    
    def register(self, email: str, password: str, first_name: str = None, 
                 last_name: str = None) -> User:
        """
        Register a new user
        
        Args:
            email: User email
            password: User password
            first_name: User first name
            last_name: User last name
            
        Returns:
            Created user
            
        Raises:
            ValueError: If email already exists or validation fails
        """
        # Validate email
        if not email or '@' not in email:
            raise ValueError("Invalid email address")
        
        # Check if email exists
        if self.user_repo.email_exists(email):
            raise ValueError("Email already registered")
        
        # Validate password
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        # Create user
        user = User(
            email=email.lower(),
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        
        return self.user_repo.save(user)
    
    def login(self, email: str, password: str) -> Dict[str, Any]:
        """
        Login user and return tokens
        
        Args:
            email: User email
            password: User password
            
        Returns:
            Dictionary with access_token, refresh_token, and user data
            
        Raises:
            ValueError: If credentials are invalid
        """
        user = self.user_repo.get_by_email(email.lower())
        
        if not user:
            raise ValueError("Invalid credentials")
        
        if not user.check_password(password):
            raise ValueError("Invalid credentials")
        
        if not user.is_active:
            raise ValueError("Account is disabled")
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }
    
    def get_user_by_id(self, user_id: str) -> User:
        """Get user by ID"""
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        return user

