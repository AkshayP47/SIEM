"""
Incident model for tracking security incidents
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime
from .database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'), index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)  # Low, Medium, High, Critical
    status = Column(String(20), default='open', index=True)  # open, investigating, resolved, closed
    assigned_to = Column(String(100), index=True)
    created_by = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    notes = Column(Text)
    
    def to_dict(self):
        """Convert incident to dictionary"""
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'notes': self.notes
        }

# Made with Bob
