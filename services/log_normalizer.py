"""
Log normalization service - converts various log formats to standard format
"""
import re
from datetime import datetime
from typing import Dict, Optional
import json


class LogNormalizer:
    """
    Normalizes logs from different sources into a common format
    """
    
    @staticmethod
    def normalize(raw_log: str, log_source: str = 'generic') -> Dict:
        """
        Normalize a raw log entry into standard format
        
        Args:
            raw_log: Raw log string
            log_source: Source type (auth, system, network, etc.)
            
        Returns:
            Normalized log dictionary
        """
        if log_source == 'auth':
            return LogNormalizer._normalize_auth_log(raw_log)
        elif log_source == 'system':
            return LogNormalizer._normalize_system_log(raw_log)
        elif log_source == 'network':
            return LogNormalizer._normalize_network_log(raw_log)
        elif log_source == 'json':
            return LogNormalizer._normalize_json_log(raw_log)
        else:
            return LogNormalizer._normalize_generic_log(raw_log)
    
    @staticmethod
    def _normalize_auth_log(raw_log: str) -> Dict:
        """Normalize authentication logs"""
        normalized = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': None,
            'source_ip': None,
            'hostname': None,
            'event_type': 'authentication',
            'severity': 'info',
            'message': raw_log
        }
        
        # Extract username
        username_match = re.search(r'user[=:\s]+([a-zA-Z0-9_\-\.]+)', raw_log, re.IGNORECASE)
        if username_match:
            normalized['username'] = username_match.group(1)
        
        # Extract IP address
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
        if ip_match:
            normalized['source_ip'] = ip_match.group(1)
        
        # Extract hostname
        hostname_match = re.search(r'host[=:\s]+([a-zA-Z0-9_\-\.]+)', raw_log, re.IGNORECASE)
        if hostname_match:
            normalized['hostname'] = hostname_match.group(1)
        
        # Determine severity based on keywords
        if any(word in raw_log.lower() for word in ['failed', 'failure', 'denied', 'invalid']):
            normalized['severity'] = 'warning'
            normalized['event_type'] = 'failed_authentication'
        elif any(word in raw_log.lower() for word in ['success', 'accepted', 'granted']):
            normalized['severity'] = 'info'
            normalized['event_type'] = 'successful_authentication'
        
        return normalized
    
    @staticmethod
    def _normalize_system_log(raw_log: str) -> Dict:
        """Normalize system logs"""
        normalized = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': None,
            'source_ip': None,
            'hostname': None,
            'event_type': 'system_event',
            'severity': 'info',
            'message': raw_log
        }
        
        # Extract hostname
        hostname_match = re.search(r'^([a-zA-Z0-9_\-\.]+)\s', raw_log)
        if hostname_match:
            normalized['hostname'] = hostname_match.group(1)
        
        # Determine severity
        if any(word in raw_log.lower() for word in ['error', 'critical', 'fatal']):
            normalized['severity'] = 'high'
        elif any(word in raw_log.lower() for word in ['warning', 'warn']):
            normalized['severity'] = 'medium'
        
        # Determine event type
        if 'privilege' in raw_log.lower() or 'sudo' in raw_log.lower():
            normalized['event_type'] = 'privilege_escalation'
            normalized['severity'] = 'high'
        elif 'file' in raw_log.lower():
            normalized['event_type'] = 'file_access'
        
        return normalized
    
    @staticmethod
    def _normalize_network_log(raw_log: str) -> Dict:
        """Normalize network logs"""
        normalized = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': None,
            'source_ip': None,
            'hostname': None,
            'event_type': 'network_connection',
            'severity': 'info',
            'message': raw_log
        }
        
        # Extract source IP
        ip_match = re.search(r'src[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log, re.IGNORECASE)
        if ip_match:
            normalized['source_ip'] = ip_match.group(1)
        
        # Extract port
        port_match = re.search(r'port[=:\s]+(\d+)', raw_log, re.IGNORECASE)
        if port_match:
            normalized['message'] = f"{raw_log} [Port: {port_match.group(1)}]"
        
        # Detect port scan
        if 'scan' in raw_log.lower():
            normalized['event_type'] = 'port_scan'
            normalized['severity'] = 'high'
        
        return normalized
    
    @staticmethod
    def _normalize_json_log(raw_log: str) -> Dict:
        """Normalize JSON formatted logs"""
        try:
            log_data = json.loads(raw_log)
            normalized = {
                'timestamp': log_data.get('timestamp', datetime.utcnow().isoformat()),
                'username': log_data.get('username') or log_data.get('user'),
                'source_ip': log_data.get('source_ip') or log_data.get('ip'),
                'hostname': log_data.get('hostname') or log_data.get('host'),
                'event_type': log_data.get('event_type', 'generic'),
                'severity': log_data.get('severity', 'info'),
                'message': log_data.get('message', raw_log)
            }
            return normalized
        except json.JSONDecodeError:
            return LogNormalizer._normalize_generic_log(raw_log)
    
    @staticmethod
    def _normalize_generic_log(raw_log: str) -> Dict:
        """Normalize generic logs"""
        normalized = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': None,
            'source_ip': None,
            'hostname': None,
            'event_type': 'generic',
            'severity': 'info',
            'message': raw_log
        }
        
        # Try to extract IP address
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
        if ip_match:
            normalized['source_ip'] = ip_match.group(1)
        
        return normalized

# Made with Bob
