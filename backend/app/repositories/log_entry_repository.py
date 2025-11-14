"""
LogEntry repository with SOC-focused queries
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import func, desc
from app.models.log_entry import LogEntry
from app.repositories.base_repository import BaseRepository
from app.extensions import db

class LogEntryRepository(BaseRepository[LogEntry]):
    """Repository for LogEntry model with SOC analyst queries"""
    
    def __init__(self):
        super().__init__(LogEntry)
    
    def get_by_file(self, log_file_id: str, limit: int = 1000, offset: int = 0) -> List[LogEntry]:
        """Get log entries by file"""
        return self.model.query.filter_by(log_file_id=log_file_id)\
            .order_by(self.model.timestamp.desc())\
            .limit(limit).offset(offset).all()
    
    def get_high_risk_entries(self, log_file_id: str, risk_threshold: int = 70) -> List[LogEntry]:
        """Get high risk log entries"""
        return self.model.query.filter(
            self.model.log_file_id == log_file_id,
            self.model.risk_score >= risk_threshold
        ).order_by(desc(self.model.risk_score)).all()
    
    def get_threat_entries(self, log_file_id: str) -> List[LogEntry]:
        """Get entries with detected threats"""
        return self.model.query.filter(
            self.model.log_file_id == log_file_id,
            self.model.threat_name.isnot(None)
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_by_user(self, log_file_id: str, username: str) -> List[LogEntry]:
        """Get entries by username"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            username=username
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_by_ip(self, log_file_id: str, ip_address: str) -> List[LogEntry]:
        """Get entries by source IP"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            source_ip=ip_address
        ).order_by(self.model.timestamp.desc()).all()
    
    def get_bypassed_traffic(self, log_file_id: str) -> List[LogEntry]:
        """Get bypassed traffic entries"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            bypassed_traffic=True
        ).order_by(self.model.timestamp.desc()).all()

    def get_by_action(self, log_file_id: str, action: str) -> List[LogEntry]:
        """Get entries by action (Blocked, Allowed, etc.)"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            action=action
        ).order_by(self.model.timestamp.desc()).all()

    def get_unique_users_list(self, log_file_id: str) -> List[Dict[str, Any]]:
        """Get list of unique users with their request counts"""
        users = db.session.query(
            self.model.username,
            func.count(self.model.id).label('request_count'),
            func.max(self.model.timestamp).label('last_seen')
        ).filter(
            self.model.log_file_id == log_file_id,
            self.model.username.isnot(None)
        ).group_by(self.model.username)\
         .order_by(desc('request_count')).all()

        return [
            {
                'username': user,
                'request_count': count,
                'last_seen': last_seen.isoformat() if last_seen else None
            }
            for user, count, last_seen in users
        ]

    def get_unique_ips_list(self, log_file_id: str, ip_type: str = 'source') -> List[Dict[str, Any]]:
        """Get list of unique IPs with their request counts"""
        ip_field = self.model.source_ip if ip_type == 'source' else self.model.destination_ip

        ips = db.session.query(
            ip_field,
            func.count(self.model.id).label('request_count'),
            func.max(self.model.timestamp).label('last_seen')
        ).filter(
            self.model.log_file_id == log_file_id,
            ip_field.isnot(None)
        ).group_by(ip_field)\
         .order_by(desc('request_count')).all()

        return [
            {
                'ip_address': ip,
                'request_count': count,
                'last_seen': last_seen.isoformat() if last_seen else None
            }
            for ip, count, last_seen in ips
        ]
    
    def get_statistics(self, log_file_id: str) -> Dict[str, Any]:
        """Get statistics for a log file"""
        total = self.model.query.filter_by(log_file_id=log_file_id).count()

        # Threat statistics
        threats = self.model.query.filter(
            self.model.log_file_id == log_file_id,
            self.model.threat_name.isnot(None)
        ).count()

        # High risk count
        high_risk = self.model.query.filter(
            self.model.log_file_id == log_file_id,
            self.model.risk_score >= 70
        ).count()

        # Bypassed traffic count
        bypassed = self.model.query.filter_by(
            log_file_id=log_file_id,
            bypassed_traffic=True
        ).count()

        # Unique users
        unique_users = db.session.query(func.count(func.distinct(self.model.username)))\
            .filter(self.model.log_file_id == log_file_id)\
            .scalar()

        # Unique IPs (source)
        unique_ips = db.session.query(func.count(func.distinct(self.model.source_ip)))\
            .filter(self.model.log_file_id == log_file_id)\
            .scalar()

        # Unique destination IPs
        unique_dest_ips = db.session.query(func.count(func.distinct(self.model.destination_ip)))\
            .filter(
                self.model.log_file_id == log_file_id,
                self.model.destination_ip.isnot(None)
            ).scalar()

        # Action statistics (blocked vs allowed)
        action_stats = db.session.query(
            self.model.action,
            func.count(self.model.id).label('count')
        ).filter(
            self.model.log_file_id == log_file_id,
            self.model.action.isnot(None)
        ).group_by(self.model.action).all()

        # Calculate blocked and allowed counts
        blocked_count = sum(count for action, count in action_stats if action and 'block' in action.lower())
        allowed_count = sum(count for action, count in action_stats if action and 'allow' in action.lower())

        # Data volume (bytes transferred)
        total_bytes_sent = db.session.query(func.sum(self.model.source_bytes))\
            .filter(self.model.log_file_id == log_file_id)\
            .scalar() or 0

        total_bytes_received = db.session.query(func.sum(self.model.destination_bytes))\
            .filter(self.model.log_file_id == log_file_id)\
            .scalar() or 0

        # Top URL categories
        top_categories = db.session.query(
            self.model.url_category,
            func.count(self.model.id).label('count')
        ).filter(
            self.model.log_file_id == log_file_id,
            self.model.url_category.isnot(None)
        ).group_by(self.model.url_category)\
         .order_by(desc('count'))\
         .limit(10).all()

        # Top users by request count
        top_users = db.session.query(
            self.model.username,
            func.count(self.model.id).label('count')
        ).filter(
            self.model.log_file_id == log_file_id,
            self.model.username.isnot(None)
        ).group_by(self.model.username)\
         .order_by(desc('count'))\
         .limit(10).all()

        return {
            'total_entries': total,
            'threat_count': threats,
            'high_risk_count': high_risk,
            'bypassed_count': bypassed,
            'unique_users': unique_users,
            'unique_source_ips': unique_ips,
            'unique_dest_ips': unique_dest_ips,
            'blocked_count': blocked_count,
            'allowed_count': allowed_count,
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_received': total_bytes_received,
            'total_bytes': total_bytes_sent + total_bytes_received,
            'top_categories': [{'category': cat, 'count': count} for cat, count in top_categories],
            'top_users': [{'username': user, 'count': count} for user, count in top_users],
            'action_breakdown': [{'action': action, 'count': count} for action, count in action_stats]
        }
    
    def get_timeline_data(self, log_file_id: str, interval_minutes: int = 5) -> List[Dict[str, Any]]:
        """Get timeline data grouped by time intervals"""
        # This is a simplified version - in production you'd use database-specific functions
        entries = self.model.query.filter_by(log_file_id=log_file_id)\
            .order_by(self.model.timestamp).all()
        
        if not entries:
            return []
        
        # Group by time intervals
        timeline = {}
        for entry in entries:
            if entry.timestamp:
                # Round to interval
                interval_key = entry.timestamp.replace(
                    minute=(entry.timestamp.minute // interval_minutes) * interval_minutes,
                    second=0,
                    microsecond=0
                )
                
                if interval_key not in timeline:
                    timeline[interval_key] = {
                        'timestamp': interval_key.isoformat(),
                        'count': 0,
                        'high_risk_count': 0,
                        'threat_count': 0
                    }
                
                timeline[interval_key]['count'] += 1
                if entry.risk_score and entry.risk_score >= 70:
                    timeline[interval_key]['high_risk_count'] += 1
                if entry.threat_name:
                    timeline[interval_key]['threat_count'] += 1
        
        return sorted(timeline.values(), key=lambda x: x['timestamp'])

