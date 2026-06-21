"""
Alert model for storing security alerts
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from datetime import datetime
from .database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)  # Low, Medium, High, Critical
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String(20), default='active', index=True)  # active, investigating, resolved
    description = Column(Text)
    source_ip = Column(String(45), index=True)
    username = Column(String(100), index=True)
    affected_resource = Column(String(255))
    detection_rule = Column(String(100))
    mitre_attack_id = Column(String(50))  # MITRE ATT&CK technique ID
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'description': self.description,
            'source_ip': self.source_ip,
            'username': self.username,
            'affected_resource': self.affected_resource,
            'detection_rule': self.detection_rule,
            'mitre_attack_id': self.mitre_attack_id,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'resolution_notes': self.resolution_notes,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Made with Bob
