"""
Base repository pattern implementation
"""
from typing import TypeVar, Generic, List, Optional, Dict, Any
from app.extensions import db

T = TypeVar('T')

class BaseRepository(Generic[T]):
    """Base repository with common CRUD operations"""
    
    def __init__(self, model: type[T]):
        self.model = model
    
    def get_by_id(self, id: str) -> Optional[T]:
        """Get entity by ID"""
        return self.model.query.get(id)
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[T]:
        """Get all entities with pagination"""
        return self.model.query.limit(limit).offset(offset).all()
    
    def create(self, **kwargs) -> T:
        """Create new entity"""
        instance = self.model(**kwargs)
        db.session.add(instance)
        db.session.commit()
        return instance
    
    def update(self, instance: T, **kwargs) -> T:
        """Update entity"""
        for key, value in kwargs.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
        db.session.commit()
        return instance
    
    def delete(self, instance: T) -> bool:
        """Delete entity"""
        try:
            db.session.delete(instance)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False
    
    def save(self, instance: T) -> T:
        """Save entity"""
        db.session.add(instance)
        db.session.commit()
        return instance
    
    def bulk_create(self, instances: List[T]) -> List[T]:
        """Bulk create entities"""
        db.session.bulk_save_objects(instances)
        db.session.commit()
        return instances
    
    def count(self, **filters) -> int:
        """Count entities with optional filters"""
        query = self.model.query
        for key, value in filters.items():
            if hasattr(self.model, key):
                query = query.filter(getattr(self.model, key) == value)
        return query.count()

