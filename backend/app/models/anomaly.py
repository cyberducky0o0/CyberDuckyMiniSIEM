"""
Anomaly model - represents detected anomalies and threats
"""
from app.extensions import db
from datetime import datetime
import uuid

class Anomaly(db.Model):
    __tablename__ = 'anomalies'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Support both legacy LogEntry and new NormalizedEvent
    log_entry_id = db.Column(db.String(36), db.ForeignKey('log_entries.id'), nullable=True, index=True)
    normalized_event_id = db.Column(db.String(36), db.ForeignKey('normalized_events.id'), nullable=True, index=True)

    log_file_id = db.Column(db.String(36), db.ForeignKey('log_files.id'), nullable=False, index=True)
    
    # Anomaly Classification
    anomaly_type = db.Column(db.String(100), nullable=False, index=True)
    # Types: threat_detected, rate_limit_exceeded, geo_anomaly, pattern_anomaly,
    #        data_exfiltration, bypassed_traffic, high_risk_category, etc.
    
    severity = db.Column(db.String(20), nullable=False, index=True)  # critical, high, medium, low
    confidence_score = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    
    # Description
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)  # What SOC analyst should do
    
    # AI/ML Attribution
    detection_method = db.Column(db.String(50))  # statistical, ml, rule_based, llm
    ai_model_used = db.Column(db.String(100))  # z_score, isolation_forest, gpt4, etc.
    ai_explanation = db.Column(db.Text)  # Natural language explanation from LLM
    
    # Context and Metadata
    affected_user = db.Column(db.String(255), index=True)
    affected_device = db.Column(db.String(255), index=True)
    affected_ip = db.Column(db.String(45), index=True)
    threat_indicators = db.Column(db.JSON)  # Additional threat indicators
    
    # Status and Workflow
    status = db.Column(db.String(20), default='open', index=True)  # open, investigating, resolved, false_positive
    assigned_to = db.Column(db.String(255))
    notes = db.Column(db.Text)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'log_entry_id': self.log_entry_id,
            'normalized_event_id': self.normalized_event_id,
            'log_file_id': self.log_file_id,
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'title': self.title,
            'description': self.description,
            'recommendation': self.recommendation,
            'detection_method': self.detection_method,
            'ai_model_used': self.ai_model_used,
            'ai_explanation': self.ai_explanation,
            'affected_user': self.affected_user,
            'affected_device': self.affected_device,
            'affected_ip': self.affected_ip,
            'threat_indicators': self.threat_indicators,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }
    
    def __repr__(self):
        return f'<Anomaly {self.anomaly_type} - {self.severity} ({self.confidence_score:.2f})>'

