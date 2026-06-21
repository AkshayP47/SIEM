"""
Detection engine with security rules
"""
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict
import threading


class DetectionEngine:
    """
    Security detection engine that analyzes logs and generates alerts
    """
    
    def __init__(self):
        self.recent_events = defaultdict(list)
        self.lock = threading.Lock()
        
    def analyze_log(self, log: Dict, db_session) -> List[Dict]:
        """
        Analyze a log entry and return any alerts generated
        
        Args:
            log: Normalized log dictionary
            db_session: Database session for querying
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        # Run all detection rules
        alerts.extend(self._detect_brute_force(log, db_session))
        alerts.extend(self._detect_port_scan(log, db_session))
        alerts.extend(self._detect_suspicious_login(log))
        alerts.extend(self._detect_excessive_failures(log, db_session))
        alerts.extend(self._detect_privilege_escalation(log))
        
        return alerts
    
    def _detect_brute_force(self, log: Dict, db_session) -> List[Dict]:
        """
        Detect brute force attacks
        Rule: More than 5 failed logins from same IP within 2 minutes
        """
        alerts = []
        
        if log.get('event_type') != 'failed_authentication':
            return alerts
        
        source_ip = log.get('source_ip')
        if not source_ip:
            return alerts
        
        # Query recent failed logins from same IP
        from models.log import Log
        two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)
        
        failed_logins = db_session.query(Log).filter(
            Log.source_ip == source_ip,
            Log.event_type == 'failed_authentication',
            Log.timestamp >= two_minutes_ago
        ).count()
        
        if failed_logins >= 5:
            alerts.append({
                'alert_type': 'Brute Force Attack',
                'severity': 'high',
                'description': f'Detected {failed_logins} failed login attempts from {source_ip} within 2 minutes',
                'source_ip': source_ip,
                'username': log.get('username'),
                'detection_rule': 'brute_force_detection',
                'mitre_attack_id': 'T1110'  # Brute Force
            })
        
        return alerts
    
    def _detect_port_scan(self, log: Dict, db_session) -> List[Dict]:
        """
        Detect port scanning
        Rule: Same IP accesses more than 20 ports within 60 seconds
        """
        alerts = []
        
        if log.get('event_type') != 'network_connection' and log.get('event_type') != 'port_scan':
            return alerts
        
        source_ip = log.get('source_ip')
        if not source_ip:
            return alerts
        
        # Query recent network connections from same IP
        from models.log import Log
        one_minute_ago = datetime.utcnow() - timedelta(seconds=60)
        
        connections = db_session.query(Log).filter(
            Log.source_ip == source_ip,
            Log.event_type.in_(['network_connection', 'port_scan']),
            Log.timestamp >= one_minute_ago
        ).count()
        
        if connections >= 20:
            alerts.append({
                'alert_type': 'Port Scan Detected',
                'severity': 'high',
                'description': f'Detected {connections} connection attempts from {source_ip} within 60 seconds',
                'source_ip': source_ip,
                'detection_rule': 'port_scan_detection',
                'mitre_attack_id': 'T1046'  # Network Service Scanning
            })
        
        return alerts
    
    def _detect_suspicious_login(self, log: Dict) -> List[Dict]:
        """
        Detect suspicious login times
        Rule: Login occurs outside business hours (9 AM - 6 PM)
        """
        alerts = []
        
        if log.get('event_type') != 'successful_authentication':
            return alerts
        
        # Parse timestamp
        try:
            timestamp_str = log.get('timestamp')
            if isinstance(timestamp_str, str):
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
            
            hour = timestamp.hour
            
            # Check if outside business hours (9 AM - 6 PM)
            if hour < 9 or hour >= 18:
                alerts.append({
                    'alert_type': 'Suspicious Login Time',
                    'severity': 'medium',
                    'description': f'Login detected outside business hours at {timestamp.strftime("%H:%M")}',
                    'source_ip': log.get('source_ip'),
                    'username': log.get('username'),
                    'detection_rule': 'suspicious_login_time',
                    'mitre_attack_id': 'T1078'  # Valid Accounts
                })
        except Exception:
            pass
        
        return alerts
    
    def _detect_excessive_failures(self, log: Dict, db_session) -> List[Dict]:
        """
        Detect excessive failed logins for a user
        Rule: User fails authentication more than 10 times in 5 minutes
        """
        alerts = []
        
        if log.get('event_type') != 'failed_authentication':
            return alerts
        
        username = log.get('username')
        if not username:
            return alerts
        
        # Query recent failed logins for same user
        from models.log import Log
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
        
        failed_logins = db_session.query(Log).filter(
            Log.username == username,
            Log.event_type == 'failed_authentication',
            Log.timestamp >= five_minutes_ago
        ).count()
        
        if failed_logins >= 10:
            alerts.append({
                'alert_type': 'Excessive Failed Logins',
                'severity': 'medium',
                'description': f'User {username} has {failed_logins} failed login attempts in 5 minutes',
                'username': username,
                'source_ip': log.get('source_ip'),
                'detection_rule': 'excessive_failures',
                'mitre_attack_id': 'T1110'  # Brute Force
            })
        
        return alerts
    
    def _detect_privilege_escalation(self, log: Dict) -> List[Dict]:
        """
        Detect privilege escalation attempts
        Rule: User role changes to admin or sudo commands
        """
        alerts = []
        
        if log.get('event_type') == 'privilege_escalation':
            alerts.append({
                'alert_type': 'Privilege Escalation Detected',
                'severity': 'critical',
                'description': f'Privilege escalation detected: {log.get("message")}',
                'username': log.get('username'),
                'source_ip': log.get('source_ip'),
                'hostname': log.get('hostname'),
                'detection_rule': 'privilege_escalation',
                'mitre_attack_id': 'T1548'  # Abuse Elevation Control Mechanism
            })
        
        # Check for sudo or admin keywords
        message = log.get('message', '').lower()
        if any(keyword in message for keyword in ['sudo', 'admin', 'root', 'privilege']):
            if log.get('event_type') == 'system_event':
                alerts.append({
                    'alert_type': 'Potential Privilege Escalation',
                    'severity': 'high',
                    'description': f'Potential privilege escalation activity: {log.get("message")}',
                    'username': log.get('username'),
                    'source_ip': log.get('source_ip'),
                    'hostname': log.get('hostname'),
                    'detection_rule': 'privilege_escalation',
                    'mitre_attack_id': 'T1548'
                })
        
        return alerts

# Made with Bob
