#!/usr/bin/env python3
"""
Standalone Log Uploader for Mini SIEM
Supports: Windows Event Logs (.evtx, .e0), Text logs, CSV logs, JSON logs
Usage: python log_uploader.py <log_file_path>
"""

import sys
import os
import json
import csv
import re
import requests
from datetime import datetime
from typing import List, Dict, Optional
import xml.etree.ElementTree as ET


class LogUploader:
    """Standalone log uploader that converts various formats and uploads to Mini SIEM"""
    
    def __init__(self, siem_url: str = "http://localhost:8000"):
        self.siem_url = siem_url
        self.api_endpoint = f"{siem_url}/api/logs/ingest"
        self.uploaded_count = 0
        self.failed_count = 0
        
    def upload_file(self, file_path: str) -> None:
        """Main method to upload any log file"""
        if not os.path.exists(file_path):
            print(f"❌ Error: File not found: {file_path}")
            return
            
        print(f"📁 Processing file: {file_path}")
        print(f"🔗 Target SIEM: {self.siem_url}")
        print("-" * 60)
        
        # Detect file type and process accordingly
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ['.evtx', '.e0']:
            self._process_evtx(file_path)
        elif file_ext == '.csv':
            self._process_csv(file_path)
        elif file_ext == '.json':
            self._process_json(file_path)
        elif file_ext in ['.txt', '.log']:
            self._process_text(file_path)
        elif file_ext == '.xml':
            self._process_xml(file_path)
        else:
            print(f"⚠️  Unknown file type: {file_ext}")
            print("Attempting to process as text file...")
            self._process_text(file_path)
        
        print("-" * 60)
        print(f"✅ Successfully uploaded: {self.uploaded_count} logs")
        if self.failed_count > 0:
            print(f"❌ Failed to upload: {self.failed_count} logs")
    
    def _process_evtx(self, file_path: str) -> None:
        """Process Windows Event Log files (.evtx, .e0)"""
        try:
            import Evtx.Evtx as evtx  # type: ignore[import-untyped]
            import Evtx.Views as e_views  # type: ignore[import-untyped]
            
            print("📊 Processing Windows Event Log (EVTX format)...")
            
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        # Parse XML record
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        
                        # Extract event data
                        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                        system = root.find('ns:System', ns)
                        
                        if system is not None:
                            event_id = system.find('ns:EventID', ns)
                            time_created = system.find('ns:TimeCreated', ns)
                            computer = system.find('ns:Computer', ns)
                            level = system.find('ns:Level', ns)
                            
                            # Extract event data
                            event_data = root.find('ns:EventData', ns)
                            message = ""
                            username = None
                            source_ip = None
                            
                            if event_data is not None:
                                for data in event_data.findall('ns:Data', ns):
                                    name = data.get('Name', '')
                                    value = data.text or ''
                                    message += f"{name}: {value}; "
                                    
                                    # Extract username
                                    if 'user' in name.lower() or 'account' in name.lower():
                                        username = value
                                    
                                    # Extract IP
                                    if 'ip' in name.lower() or 'address' in name.lower():
                                        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value)
                                        if ip_match:
                                            source_ip = ip_match.group(0)
                            
                            # Determine severity
                            level_val = int(level.text) if level is not None and level.text else 4
                            severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'info'}
                            severity = severity_map.get(level_val, 'info')
                            
                            # Determine event type
                            event_id_val = event_id.text if event_id is not None and event_id.text else 'unknown'
                            event_type = self._map_windows_event_type(event_id_val)
                            
                            # Create log entry
                            log_entry = {
                                'timestamp': time_created.get('SystemTime') if time_created is not None else datetime.utcnow().isoformat(),
                                'username': username,
                                'source_ip': source_ip,
                                'hostname': computer.text if computer is not None else None,
                                'event_type': event_type,
                                'severity': severity,
                                'message': f"EventID {event_id_val}: {message.strip()}"
                            }
                            
                            self._send_log(log_entry)
                    
                    except Exception as e:
                        print(f"⚠️  Error parsing record: {e}")
                        self.failed_count += 1
                        
        except ImportError:
            print("❌ Error: python-evtx library not installed")
            print("Install it with: pip install python-evtx")
            print("\nAlternatively, export your .evtx file to CSV/TXT format first:")
            print("1. Open Event Viewer")
            print("2. Right-click log → Save All Events As...")
            print("3. Choose 'Text (Tab Delimited)' or 'CSV' format")
            print("4. Run this script again with the exported file")
        except Exception as e:
            print(f"❌ Error processing EVTX file: {e}")
    
    def _process_csv(self, file_path: str) -> None:
        """Process CSV log files"""
        print("📊 Processing CSV file...")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Try to map CSV columns to log fields
                    log_entry = {
                        'timestamp': row.get('timestamp') or row.get('time') or row.get('Date and Time') or datetime.utcnow().isoformat(),
                        'username': row.get('username') or row.get('user') or row.get('User'),
                        'source_ip': row.get('source_ip') or row.get('ip') or row.get('Source'),
                        'hostname': row.get('hostname') or row.get('host') or row.get('Computer'),
                        'event_type': row.get('event_type') or row.get('type') or row.get('Level') or 'generic',
                        'severity': row.get('severity') or self._map_severity(row.get('Level', 'info')),
                        'message': row.get('message') or row.get('Message') or row.get('Description') or str(row)
                    }
                    
                    self._send_log(log_entry)
                    
        except Exception as e:
            print(f"❌ Error processing CSV file: {e}")
    
    def _process_json(self, file_path: str) -> None:
        """Process JSON log files"""
        print("📊 Processing JSON file...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Handle both single object and array of objects
                logs = data if isinstance(data, list) else [data]
                
                for log_data in logs:
                    log_entry = {
                        'timestamp': log_data.get('timestamp') or log_data.get('time') or datetime.utcnow().isoformat(),
                        'username': log_data.get('username') or log_data.get('user'),
                        'source_ip': log_data.get('source_ip') or log_data.get('ip'),
                        'hostname': log_data.get('hostname') or log_data.get('host'),
                        'event_type': log_data.get('event_type') or log_data.get('type') or 'generic',
                        'severity': log_data.get('severity') or 'info',
                        'message': log_data.get('message') or str(log_data)
                    }
                    
                    self._send_log(log_entry)
                    
        except Exception as e:
            print(f"❌ Error processing JSON file: {e}")
    
    def _process_text(self, file_path: str) -> None:
        """Process text/log files"""
        print("📊 Processing text file...")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse the line
                    log_entry = self._parse_text_line(line)
                    self._send_log(log_entry)
                    
        except Exception as e:
            print(f"❌ Error processing text file: {e}")
    
    def _process_xml(self, file_path: str) -> None:
        """Process XML log files"""
        print("📊 Processing XML file...")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Try to find event elements
            for event in root.findall('.//Event'):
                log_entry = {
                    'timestamp': event.findtext('.//TimeCreated') or datetime.utcnow().isoformat(),
                    'username': event.findtext('.//User'),
                    'source_ip': None,
                    'hostname': event.findtext('.//Computer'),
                    'event_type': 'generic',
                    'severity': 'info',
                    'message': event.findtext('.//Message') or ET.tostring(event, encoding='unicode')
                }
                
                self._send_log(log_entry)
                
        except Exception as e:
            print(f"❌ Error processing XML file: {e}")
    
    def _parse_text_line(self, line: str) -> Dict:
        """Parse a text log line and extract fields"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': None,
            'source_ip': None,
            'hostname': None,
            'event_type': 'generic',
            'severity': 'info',
            'message': line
        }
        
        # Extract IP address
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            log_entry['source_ip'] = ip_match.group(1)
        
        # Extract username
        username_match = re.search(r'user[=:\s]+([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
        if username_match:
            log_entry['username'] = username_match.group(1)
        
        # Extract hostname
        hostname_match = re.search(r'host[=:\s]+([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
        if hostname_match:
            log_entry['hostname'] = hostname_match.group(1)
        
        # Determine event type and severity
        line_lower = line.lower()
        if any(word in line_lower for word in ['failed', 'failure', 'denied', 'invalid']):
            log_entry['event_type'] = 'failed_authentication'
            log_entry['severity'] = 'warning'
        elif any(word in line_lower for word in ['success', 'accepted', 'granted']):
            log_entry['event_type'] = 'successful_authentication'
            log_entry['severity'] = 'info'
        elif 'scan' in line_lower:
            log_entry['event_type'] = 'port_scan'
            log_entry['severity'] = 'high'
        elif any(word in line_lower for word in ['error', 'critical', 'fatal']):
            log_entry['severity'] = 'high'
        
        return log_entry
    
    def _map_windows_event_type(self, event_id: str) -> str:
        """Map Windows Event ID to event type"""
        event_map = {
            '4624': 'successful_authentication',
            '4625': 'failed_authentication',
            '4648': 'successful_authentication',
            '4672': 'privilege_escalation',
            '4720': 'user_created',
            '4726': 'user_deleted',
            '4732': 'group_membership_change',
            '4688': 'process_creation',
            '4689': 'process_termination',
            '5140': 'file_access',
            '5145': 'file_access',
        }
        return event_map.get(event_id, 'windows_event')
    
    def _map_severity(self, level: str) -> str:
        """Map various severity levels to standard format"""
        level_lower = str(level).lower()
        if level_lower in ['critical', 'fatal', 'error', '1', '2']:
            return 'critical'
        elif level_lower in ['warning', 'warn', '3']:
            return 'high'
        elif level_lower in ['information', 'info', '4']:
            return 'info'
        else:
            return 'info'
    
    def _send_log(self, log_entry: Dict) -> None:
        """Send a log entry to Mini SIEM"""
        try:
            response = requests.post(
                self.api_endpoint,
                json=log_entry,
                timeout=5
            )
            
            if response.status_code == 200:
                self.uploaded_count += 1
                if self.uploaded_count % 10 == 0:
                    print(f"✓ Uploaded {self.uploaded_count} logs...")
            else:
                self.failed_count += 1
                print(f"⚠️  Failed to upload log: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Error: Cannot connect to Mini SIEM at {self.siem_url}")
            print("Make sure Mini SIEM is running: python app.py")
            sys.exit(1)
        except Exception as e:
            self.failed_count += 1
            print(f"⚠️  Error sending log: {e}")


def main():
    """Main entry point"""
    print("=" * 60)
    print("🔐 Mini SIEM - Standalone Log Uploader")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\n❌ Error: No log file specified")
        print("\nUsage:")
        print("  python log_uploader.py <log_file_path> [siem_url]")
        print("\nExamples:")
        print("  python log_uploader.py windows_events.evtx")
        print("  python log_uploader.py auth.log")
        print("  python log_uploader.py events.csv")
        print("  python log_uploader.py logs.json")
        print("  python log_uploader.py system.log http://192.168.1.100:8000")
        print("\nSupported formats:")
        print("  - Windows Event Logs (.evtx, .e0)")
        print("  - CSV files (.csv)")
        print("  - JSON files (.json)")
        print("  - Text/Log files (.txt, .log)")
        print("  - XML files (.xml)")
        sys.exit(1)
    
    log_file = sys.argv[1]
    siem_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
    
    uploader = LogUploader(siem_url)
    uploader.upload_file(log_file)
    
    print("\n✅ Upload complete!")
    print(f"📊 View logs at: {siem_url}/logs")


if __name__ == "__main__":
    main()

# Made with Bob
