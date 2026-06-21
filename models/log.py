"""
Log model for storing security events
"""
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from .database import Base


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(100), index=True)
    source_ip = Column(String(45), index=True)  # IPv6 support
    hostname = Column(String(255))
    event_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    message = Column(Text)
    raw_log = Column(Text)  # Store original log for reference
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert log to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'username': self.username,
            'source_ip': self.source_ip,
            'hostname': self.hostname,
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'raw_log': self.raw_log,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Made with Bob
