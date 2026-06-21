"""
Log simulator for generating sample security events
"""
import random
from datetime import datetime, timedelta
from typing import List, Dict


class LogSimulator:
    """
    Generates realistic security log events for testing
    """
    
    def __init__(self):
        self.usernames = ['admin', 'john.doe', 'jane.smith', 'bob.wilson', 'alice.brown', 
                         'charlie.davis', 'eve.johnson', 'mallory.white', 'trudy.black']
        self.ip_addresses = ['192.168.1.100', '192.168.1.101', '192.168.1.102', 
                            '10.0.0.50', '10.0.0.51', '172.16.0.10',
                            '203.0.113.45', '198.51.100.23', '192.0.2.100']
        self.hostnames = ['workstation-01', 'workstation-02', 'server-01', 'server-02',
                         'laptop-01', 'laptop-02', 'db-server', 'web-server']
        self.ports = [22, 80, 443, 3306, 5432, 8080, 8443, 3389, 21, 23, 25, 110, 143]
    
    def generate_failed_login(self, count: int = 1) -> List[Dict]:
        """Generate failed login attempts"""
        logs = []
        for _ in range(count):
            username = random.choice(self.usernames)
            ip = random.choice(self.ip_addresses)
            hostname = random.choice(self.hostnames)
            
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=random.randint(0, 300))).isoformat(),
                'username': username,
                'source_ip': ip,
                'hostname': hostname,
                'event_type': 'failed_authentication',
                'severity': 'warning',
                'message': f'Failed login attempt for user {username} from {ip}'
            }
            logs.append(log)
        return logs
    
    def generate_successful_login(self, count: int = 1) -> List[Dict]:
        """Generate successful login events"""
        logs = []
        for _ in range(count):
            username = random.choice(self.usernames)
            ip = random.choice(self.ip_addresses)
            hostname = random.choice(self.hostnames)
            
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=random.randint(0, 300))).isoformat(),
                'username': username,
                'source_ip': ip,
                'hostname': hostname,
                'event_type': 'successful_authentication',
                'severity': 'info',
                'message': f'Successful login for user {username} from {ip}'
            }
            logs.append(log)
        return logs
    
    def generate_port_scan(self, count: int = 1) -> List[Dict]:
        """Generate port scan events"""
        logs = []
        attacker_ip = random.choice(self.ip_addresses)
        
        for _ in range(count):
            port = random.choice(self.ports)
            hostname = random.choice(self.hostnames)
            
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=random.randint(0, 60))).isoformat(),
                'username': None,
                'source_ip': attacker_ip,
                'hostname': hostname,
                'event_type': 'port_scan',
                'severity': 'high',
                'message': f'Port scan detected from {attacker_ip} targeting port {port} on {hostname}'
            }
            logs.append(log)
        return logs
    
    def generate_file_access(self, count: int = 1) -> List[Dict]:
        """Generate file access events"""
        logs = []
        files = ['/etc/passwd', '/etc/shadow', '/var/log/auth.log', 
                '/home/user/.ssh/id_rsa', '/root/.bash_history',
                'C:\\Windows\\System32\\config\\SAM', 'C:\\Users\\Admin\\Documents\\passwords.txt']
        
        for _ in range(count):
            username = random.choice(self.usernames)
            hostname = random.choice(self.hostnames)
            file = random.choice(files)
            
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=random.randint(0, 300))).isoformat(),
                'username': username,
                'source_ip': None,
                'hostname': hostname,
                'event_type': 'file_access',
                'severity': 'medium',
                'message': f'User {username} accessed file {file} on {hostname}'
            }
            logs.append(log)
        return logs
    
    def generate_privilege_escalation(self, count: int = 1) -> List[Dict]:
        """Generate privilege escalation events"""
        logs = []
        for _ in range(count):
            username = random.choice(self.usernames)
            hostname = random.choice(self.hostnames)
            ip = random.choice(self.ip_addresses)
            
            actions = [
                f'User {username} executed sudo command on {hostname}',
                f'User {username} changed to root user on {hostname}',
                f'User {username} modified /etc/sudoers on {hostname}',
                f'User {username} added to administrators group on {hostname}'
            ]
            
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=random.randint(0, 300))).isoformat(),
                'username': username,
                'source_ip': ip,
                'hostname': hostname,
                'event_type': 'privilege_escalation',
                'severity': 'critical',
                'message': random.choice(actions)
            }
            logs.append(log)
        return logs
    
    def generate_brute_force_attack(self) -> List[Dict]:
        """Generate a brute force attack scenario"""
        logs = []
        attacker_ip = random.choice(self.ip_addresses)
        target_user = random.choice(self.usernames)
        hostname = random.choice(self.hostnames)
        
        # Generate 10 failed attempts
        for i in range(10):
            log = {
                'timestamp': (datetime.utcnow() - timedelta(seconds=120-i*10)).isoformat(),
                'username': target_user,
                'source_ip': attacker_ip,
                'hostname': hostname,
                'event_type': 'failed_authentication',
                'severity': 'warning',
                'message': f'Failed login attempt {i+1} for user {target_user} from {attacker_ip}'
            }
            logs.append(log)
        
        return logs
    
    def generate_suspicious_login(self) -> List[Dict]:
        """Generate suspicious login outside business hours"""
        logs = []
        username = random.choice(self.usernames)
        ip = random.choice(self.ip_addresses)
        hostname = random.choice(self.hostnames)
        
        # Generate login at 2 AM
        suspicious_time = datetime.utcnow().replace(hour=2, minute=random.randint(0, 59))
        
        log = {
            'timestamp': suspicious_time.isoformat(),
            'username': username,
            'source_ip': ip,
            'hostname': hostname,
            'event_type': 'successful_authentication',
            'severity': 'info',
            'message': f'Login for user {username} from {ip} at {suspicious_time.strftime("%H:%M")}'
        }
        logs.append(log)
        
        return logs
    
    def generate_mixed_scenario(self, num_logs: int = 50) -> List[Dict]:
        """Generate a mixed scenario with various events"""
        logs = []
        
        # 60% normal logins
        logs.extend(self.generate_successful_login(int(num_logs * 0.6)))
        
        # 20% failed logins
        logs.extend(self.generate_failed_login(int(num_logs * 0.2)))
        
        # 10% file access
        logs.extend(self.generate_file_access(int(num_logs * 0.1)))
        
        # 5% port scans
        logs.extend(self.generate_port_scan(int(num_logs * 0.05)))
        
        # 5% privilege escalation
        logs.extend(self.generate_privilege_escalation(int(num_logs * 0.05)))
        
        # Sort by timestamp
        logs.sort(key=lambda x: x['timestamp'])
        
        return logs

# Made with Bob
