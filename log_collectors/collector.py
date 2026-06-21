"""
Log collection module
"""
import os
from typing import List, Dict
from datetime import datetime
from services.log_normalizer import LogNormalizer


class LogCollector:
    """
    Collects logs from various sources
    """
    
    def __init__(self):
        self.normalizer = LogNormalizer()
    
    def collect_from_file(self, file_path: str, log_source: str = 'generic') -> List[Dict]:
        """
        Collect logs from a file
        
        Args:
            file_path: Path to log file
            log_source: Type of log source (auth, system, network, etc.)
            
        Returns:
            List of normalized log dictionaries
        """
        logs = []
        
        if not os.path.exists(file_path):
            return logs
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        normalized_log = self.normalizer.normalize(line, log_source)
                        logs.append(normalized_log)
        except Exception as e:
            print(f"Error reading log file {file_path}: {e}")
        
        return logs
    
    def collect_from_api(self, log_data: Dict) -> Dict:
        """
        Collect log from API endpoint
        
        Args:
            log_data: Log data from API
            
        Returns:
            Normalized log dictionary
        """
        # If already in normalized format, return as is
        if all(key in log_data for key in ['timestamp', 'event_type', 'severity', 'message']):
            return log_data
        
        # Otherwise, normalize it
        raw_log = log_data.get('raw_log', str(log_data))
        log_source = log_data.get('source', 'generic')
        
        return self.normalizer.normalize(raw_log, log_source)
    
    def collect_system_logs(self) -> List[Dict]:
        """
        Collect system logs (platform-specific)
        
        Returns:
            List of normalized log dictionaries
        """
        logs = []
        
        # Windows Event Logs
        if os.name == 'nt':
            # Note: Requires pywin32 for full implementation
            # This is a placeholder for demonstration
            pass
        
        # Linux/Unix logs
        else:
            common_log_paths = [
                '/var/log/auth.log',
                '/var/log/secure',
                '/var/log/syslog',
                '/var/log/messages'
            ]
            
            for log_path in common_log_paths:
                if os.path.exists(log_path):
                    try:
                        # Read last 100 lines
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()[-100:]
                            for line in lines:
                                line = line.strip()
                                if line:
                                    if 'auth' in log_path:
                                        normalized = self.normalizer.normalize(line, 'auth')
                                    else:
                                        normalized = self.normalizer.normalize(line, 'system')
                                    logs.append(normalized)
                    except PermissionError:
                        print(f"Permission denied: {log_path}")
                    except Exception as e:
                        print(f"Error reading {log_path}: {e}")
        
        return logs

# Made with Bob
