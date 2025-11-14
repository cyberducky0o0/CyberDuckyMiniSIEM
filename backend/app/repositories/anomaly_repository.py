"""
Anomaly repository
"""
from typing import List, Dict, Any
from collections import defaultdict
from sqlalchemy import func, desc
from app.models.anomaly import Anomaly
from app.repositories.base_repository import BaseRepository
from app.extensions import db

class AnomalyRepository(BaseRepository[Anomaly]):
    """Repository for Anomaly model"""
    
    def __init__(self):
        super().__init__(Anomaly)
    
    def get_by_file(self, log_file_id: str, limit: int = None) -> List[Anomaly]:
        """Get anomalies by log file"""
        query = self.model.query.filter_by(log_file_id=log_file_id)\
            .order_by(desc(self.model.severity), desc(self.model.confidence_score))

        if limit:
            query = query.limit(limit)

        return query.all()
    
    def get_by_severity(self, log_file_id: str, severity: str) -> List[Anomaly]:
        """Get anomalies by severity"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            severity=severity
        ).order_by(desc(self.model.confidence_score)).all()
    
    def get_critical_anomalies(self, log_file_id: str) -> List[Anomaly]:
        """Get critical and high severity anomalies"""
        return self.model.query.filter(
            self.model.log_file_id == log_file_id,
            self.model.severity.in_(['critical', 'high'])
        ).order_by(desc(self.model.confidence_score)).all()
    
    def get_by_type(self, log_file_id: str, anomaly_type: str) -> List[Anomaly]:
        """Get anomalies by type"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            anomaly_type=anomaly_type
        ).all()
    
    def get_statistics(self, log_file_id: str) -> Dict[str, Any]:
        """Get anomaly statistics"""
        total = self.model.query.filter_by(log_file_id=log_file_id).count()
        
        # By severity
        by_severity = db.session.query(
            self.model.severity,
            func.count(self.model.id).label('count')
        ).filter_by(log_file_id=log_file_id)\
         .group_by(self.model.severity).all()
        
        # By type
        by_type = db.session.query(
            self.model.anomaly_type,
            func.count(self.model.id).label('count')
        ).filter_by(log_file_id=log_file_id)\
         .group_by(self.model.anomaly_type)\
         .order_by(desc('count')).all()
        
        return {
            'total': total,
            'by_severity': {sev: count for sev, count in by_severity},
            'by_type': [{'type': atype, 'count': count} for atype, count in by_type]
        }

    def get_time_series_data(self, log_file_id: str, bucket_size: str = 'hour') -> List[Dict[str, Any]]:
        """
        Get anomaly time series data for visualization

        Args:
            log_file_id: Log file ID
            bucket_size: Time bucket size ('hour', 'day')

        Returns:
            List of time buckets with anomaly counts
        """
        if not log_file_id:
            return []

        anomalies = self.get_by_file(log_file_id)

        if not anomalies:
            return []

        # Group by time bucket
        from collections import defaultdict
        time_buckets = defaultdict(lambda: {
            'count': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'types': defaultdict(int)
        })

        for anomaly in anomalies:
            if not anomaly or not anomaly.detected_at:
                continue

            if bucket_size == 'hour':
                bucket = anomaly.detected_at.replace(minute=0, second=0, microsecond=0)
            else:  # day
                bucket = anomaly.detected_at.replace(hour=0, minute=0, second=0, microsecond=0)

            time_buckets[bucket]['count'] += 1

            # Safely increment severity count
            severity = anomaly.severity or 'low'
            if severity in time_buckets[bucket]:
                time_buckets[bucket][severity] += 1

            # Safely increment type count
            if anomaly.anomaly_type:
                time_buckets[bucket]['types'][anomaly.anomaly_type] += 1

        # Convert to list
        result = []
        for bucket in sorted(time_buckets.keys()):
            data = time_buckets[bucket]
            result.append({
                'time_bucket': bucket.isoformat(),
                'total_anomalies': data['count'],
                'critical': data['critical'],
                'high': data['high'],
                'medium': data['medium'],
                'low': data['low'],
                'top_type': max(data['types'].items(), key=lambda x: x[1])[0] if data['types'] else None
            })

        return result

    def get_by_user(self, log_file_id: str, username: str) -> List[Anomaly]:
        """Get anomalies for a specific user"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            affected_user=username
        ).order_by(desc(self.model.detected_at)).all()

    def get_by_ip(self, log_file_id: str, ip_address: str) -> List[Anomaly]:
        """Get anomalies for a specific IP address"""
        return self.model.query.filter_by(
            log_file_id=log_file_id,
            affected_ip=ip_address
        ).order_by(desc(self.model.detected_at)).all()

    def get_statistical_summary(self, log_file_id: str) -> Dict[str, Any]:
        """
        Get statistical summary of anomalies for visualization

        Returns:
            Dictionary with statistical metrics
        """
        if not log_file_id:
            return {
                'total': 0,
                'avg_confidence': 0,
                'detection_methods': {},
                'ai_models': {},
                'affected_users': 0,
                'affected_ips': 0
            }

        anomalies = self.get_by_file(log_file_id)

        if not anomalies:
            return {
                'total': 0,
                'avg_confidence': 0,
                'detection_methods': {},
                'ai_models': {},
                'affected_users': 0,
                'affected_ips': 0
            }

        # Calculate statistics safely
        confidence_scores = [a.confidence_score for a in anomalies if a and a.confidence_score is not None]
        detection_methods = defaultdict(int)
        ai_models = defaultdict(int)
        affected_users = set()
        affected_ips = set()

        for anomaly in anomalies:
            if not anomaly:
                continue

            if anomaly.detection_method:
                detection_methods[anomaly.detection_method] += 1
            if anomaly.ai_model_used:
                ai_models[anomaly.ai_model_used] += 1
            if anomaly.affected_user:
                affected_users.add(anomaly.affected_user)
            if anomaly.affected_ip:
                affected_ips.add(anomaly.affected_ip)

        return {
            'total': len(anomalies),
            'avg_confidence': round(sum(confidence_scores) / len(confidence_scores), 2) if confidence_scores else 0,
            'detection_methods': dict(detection_methods),
            'ai_models': dict(ai_models),
            'affected_users': len(affected_users),
            'affected_ips': len(affected_ips)
        }

