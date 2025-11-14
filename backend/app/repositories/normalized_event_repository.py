"""
NormalizedEvent repository with cross-source correlation queries
Enables SOC analysts to correlate events across multiple log sources
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy import func, desc, and_, or_
from app.models.normalized_event_model import NormalizedEventModel
from app.repositories.base_repository import BaseRepository
from app.extensions import db

class NormalizedEventRepository(BaseRepository[NormalizedEventModel]):
    """Repository for NormalizedEvent with cross-source correlation queries"""
    
    def __init__(self):
        super().__init__(NormalizedEventModel)
    
    # ========== Basic Queries ==========
    
    def get_by_file(self, log_file_id: str, limit: int = 1000, offset: int = 0) -> List[NormalizedEventModel]:
        """Get normalized events by file"""
        return self.model.query.filter_by(log_file_id=log_file_id)\
            .order_by(self.model.timestamp.desc())\
            .limit(limit).offset(offset).all()
    
    def get_by_source(self, observer_vendor: str, limit: int = 1000) -> List[NormalizedEventModel]:
        """Get events from a specific log source (e.g., 'zscaler', 'crowdstrike')"""
        return self.model.query.filter_by(observer_vendor=observer_vendor)\
            .order_by(self.model.timestamp.desc())\
            .limit(limit).all()
    
    # ========== Correlation Queries ==========
    
    def get_by_user(self, username: str, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """
        Get all events for a user across ALL log sources
        Critical for UEBA and cross-source correlation
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            self.model.user_name == username,
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_by_source_ip(self, ip_address: str, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """
        Get all events from a source IP across ALL log sources
        Critical for threat hunting and lateral movement detection
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            self.model.source_ip == ip_address,
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_by_device(self, device_id: str, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """
        Get all events from a device across ALL log sources
        Critical for endpoint investigation
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            or_(
                self.model.device_id == device_id,
                self.model.device_hostname == device_id
            ),
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_by_domain(self, domain: str, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """
        Get all events related to a domain across ALL log sources
        Critical for C2 detection and threat hunting
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            or_(
                self.model.destination_domain.like(f'%{domain}%'),
                self.model.url_domain.like(f'%{domain}%')
            ),
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    # ========== Threat Detection Queries ==========
    
    def get_high_severity_events(self, severity_threshold: int = 70, limit: int = 1000) -> List[NormalizedEventModel]:
        """Get high severity events across all sources"""
        return self.model.query.filter(
            self.model.event_severity >= severity_threshold
        ).order_by(desc(self.model.event_severity), desc(self.model.timestamp)).limit(limit).all()
    
    def get_failed_events(self, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """Get all failed events (failed logins, blocked connections, etc.)"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            self.model.event_outcome == 'failure',
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_threat_events(self, time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """Get events with threat indicators"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        return self.model.query.filter(
            self.model.threat_indicator_value.isnot(None),
            self.model.timestamp >= cutoff_time
        ).order_by(self.model.timestamp.desc()).all()
    
    # ========== Aggregation Queries for Metrics ==========
    
    def get_event_count_by_user(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Get event count per user across all sources"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        results = db.session.query(
            self.model.user_name,
            func.count(self.model.id).label('event_count')
        ).filter(
            self.model.user_name.isnot(None),
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.user_name)\
         .order_by(desc('event_count')).all()
        
        return [{'user': r[0], 'count': r[1]} for r in results]
    
    def get_event_count_by_source_ip(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Get event count per source IP across all sources"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        results = db.session.query(
            self.model.source_ip,
            func.count(self.model.id).label('event_count')
        ).filter(
            self.model.source_ip.isnot(None),
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.source_ip)\
         .order_by(desc('event_count')).all()
        
        return [{'ip': r[0], 'count': r[1]} for r in results]
    
    def get_event_count_by_category(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Get event count by category across all sources"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        results = db.session.query(
            self.model.event_category,
            func.count(self.model.id).label('event_count')
        ).filter(
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.event_category)\
         .order_by(desc('event_count')).all()
        
        return [{'category': r[0], 'count': r[1]} for r in results]
    
    def get_event_count_by_source(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Get event count by log source (vendor)"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        results = db.session.query(
            self.model.observer_vendor,
            self.model.observer_product,
            func.count(self.model.id).label('event_count')
        ).filter(
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.observer_vendor, self.model.observer_product)\
         .order_by(desc('event_count')).all()
        
        return [{'vendor': r[0], 'product': r[1], 'count': r[2]} for r in results]
    
    # ========== Advanced Correlation Queries ==========
    
    def find_user_geo_anomalies(self, time_window_minutes: int = 30) -> List[Dict[str, Any]]:
        """
        Find users appearing in multiple countries within a short time window
        Classic impossible travel detection
        """
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        # Get users with multiple distinct countries in time window
        results = db.session.query(
            self.model.user_name,
            func.count(func.distinct(self.model.source_geo_country)).label('country_count'),
            func.array_agg(func.distinct(self.model.source_geo_country)).label('countries')
        ).filter(
            self.model.user_name.isnot(None),
            self.model.source_geo_country.isnot(None),
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.user_name)\
         .having(func.count(func.distinct(self.model.source_geo_country)) > 1).all()
        
        return [{'user': r[0], 'country_count': r[1], 'countries': r[2]} for r in results]
    
    def find_high_volume_users(self, time_window_hours: int = 1, threshold: int = 1000) -> List[Dict[str, Any]]:
        """
        Find users with unusually high event counts
        Potential compromised accounts or data exfiltration
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        results = db.session.query(
            self.model.user_name,
            func.count(self.model.id).label('event_count'),
            func.sum(self.model.source_bytes + self.model.destination_bytes).label('total_bytes')
        ).filter(
            self.model.user_name.isnot(None),
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.user_name)\
         .having(func.count(self.model.id) > threshold)\
         .order_by(desc('event_count')).all()
        
        return [{'user': r[0], 'event_count': r[1], 'total_bytes': r[2] or 0} for r in results]
    
    def find_failed_login_patterns(self, time_window_minutes: int = 10, threshold: int = 5) -> List[Dict[str, Any]]:
        """
        Find potential brute force attacks
        Multiple failed authentication events in short time
        """
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        
        results = db.session.query(
            self.model.user_name,
            self.model.source_ip,
            func.count(self.model.id).label('failed_count')
        ).filter(
            self.model.event_category == 'authentication',
            self.model.event_outcome == 'failure',
            self.model.timestamp >= cutoff_time
        ).group_by(self.model.user_name, self.model.source_ip)\
         .having(func.count(self.model.id) >= threshold)\
         .order_by(desc('failed_count')).all()
        
        return [{'user': r[0], 'source_ip': r[1], 'failed_count': r[2]} for r in results]
    
    def get_timeline_for_investigation(self, 
                                      user: Optional[str] = None,
                                      ip: Optional[str] = None,
                                      device: Optional[str] = None,
                                      time_window_hours: int = 24) -> List[NormalizedEventModel]:
        """
        Get complete timeline for investigation
        Combines user, IP, and device activity across all sources
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        filters = [self.model.timestamp >= cutoff_time]
        
        if user:
            filters.append(self.model.user_name == user)
        if ip:
            filters.append(or_(
                self.model.source_ip == ip,
                self.model.destination_ip == ip
            ))
        if device:
            filters.append(or_(
                self.model.device_id == device,
                self.model.device_hostname == device
            ))
        
        return self.model.query.filter(and_(*filters))\
            .order_by(self.model.timestamp.asc()).all()

