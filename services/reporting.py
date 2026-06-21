"""
Reporting service for generating security reports
"""
from datetime import datetime, timedelta
from typing import List, Dict
import csv
import io
from fpdf import FPDF


class ReportGenerator:
    """
    Generates security reports in various formats
    """
    
    def __init__(self, db_session):
        self.db = db_session
    
    def generate_daily_report(self, date: datetime = None) -> Dict:
        """Generate daily security report"""
        if date is None:
            date = datetime.utcnow()
        
        start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timedelta(days=1)
        
        return self._generate_report(start_date, end_date, "Daily Report")
    
    def generate_weekly_report(self, date: datetime = None) -> Dict:
        """Generate weekly security report"""
        if date is None:
            date = datetime.utcnow()
        
        start_date = date - timedelta(days=7)
        end_date = date
        
        return self._generate_report(start_date, end_date, "Weekly Report")
    
    def generate_incident_report(self, incident_id: int) -> Dict:
        """Generate incident-specific report"""
        from models.incident import Incident
        from models.alert import Alert
        from models.log import Log
        
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return {'error': 'Incident not found'}
        
        # Get related alert
        alert = None
        if incident.alert_id:
            alert = self.db.query(Alert).filter(Alert.id == incident.alert_id).first()
        
        # Get related logs
        related_logs = []
        if alert:
            related_logs = self.db.query(Log).filter(
                Log.source_ip == alert.source_ip,
                Log.timestamp >= incident.created_at - timedelta(hours=1),
                Log.timestamp <= incident.created_at + timedelta(hours=1)
            ).all()
        
        report = {
            'report_type': 'Incident Report',
            'generated_at': datetime.utcnow().isoformat(),
            'incident': incident.to_dict() if incident else None,
            'alert': alert.to_dict() if alert else None,
            'related_logs': [log.to_dict() for log in related_logs],
            'summary': {
                'incident_id': incident_id,
                'severity': incident.severity,
                'status': incident.status,
                'related_logs_count': len(related_logs)
            }
        }
        
        return report
    
    def _generate_report(self, start_date: datetime, end_date: datetime, report_type: str) -> Dict:
        """Generate report for a date range"""
        from models.log import Log
        from models.alert import Alert
        
        # Query logs
        logs = self.db.query(Log).filter(
            Log.timestamp >= start_date,
            Log.timestamp < end_date
        ).all()
        
        # Query alerts
        alerts = self.db.query(Alert).filter(
            Alert.timestamp >= start_date,
            Alert.timestamp < end_date
        ).all()
        
        # Calculate statistics
        total_logs = len(logs)
        total_alerts = len(alerts)
        
        # Count by severity
        alert_severity_counts = {}
        for alert in alerts:
            severity = alert.severity
            alert_severity_counts[severity] = alert_severity_counts.get(severity, 0) + 1
        
        # Count by event type
        event_type_counts = {}
        for log in logs:
            event_type = log.event_type
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        # Top attacking IPs
        ip_counts = {}
        for log in logs:
            if log.source_ip and log.event_type in ['failed_authentication', 'port_scan']:
                ip_counts[log.source_ip] = ip_counts.get(log.source_ip, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top targeted users
        user_counts = {}
        for log in logs:
            if log.username and log.event_type == 'failed_authentication':
                user_counts[log.username] = user_counts.get(log.username, 0) + 1
        
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        report = {
            'report_type': report_type,
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {
                'total_logs': total_logs,
                'total_alerts': total_alerts,
                'critical_alerts': alert_severity_counts.get('critical', 0),
                'high_alerts': alert_severity_counts.get('high', 0),
                'medium_alerts': alert_severity_counts.get('medium', 0),
                'low_alerts': alert_severity_counts.get('low', 0)
            },
            'event_types': event_type_counts,
            'top_attacking_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'top_targeted_users': [{'username': user, 'count': count} for user, count in top_users],
            'alerts': [alert.to_dict() for alert in alerts[:50]]  # Limit to 50 most recent
        }
        
        return report
    
    def export_to_csv(self, report: Dict) -> str:
        """Export report to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Report Type', report['report_type']])
        writer.writerow(['Generated At', report['generated_at']])
        writer.writerow([])
        
        # Write summary
        writer.writerow(['Summary'])
        for key, value in report['summary'].items():
            writer.writerow([key.replace('_', ' ').title(), value])
        writer.writerow([])
        
        # Write top attacking IPs
        if 'top_attacking_ips' in report:
            writer.writerow(['Top Attacking IPs'])
            writer.writerow(['IP Address', 'Count'])
            for item in report['top_attacking_ips']:
                writer.writerow([item['ip'], item['count']])
            writer.writerow([])
        
        # Write top targeted users
        if 'top_targeted_users' in report:
            writer.writerow(['Top Targeted Users'])
            writer.writerow(['Username', 'Count'])
            for item in report['top_targeted_users']:
                writer.writerow([item['username'], item['count']])
        
        return output.getvalue()
    
    def export_to_pdf(self, report: Dict) -> bytes:
        """Export report to PDF format"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        
        # Title
        pdf.cell(0, 10, report['report_type'], 0, 1, 'C')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 10, f"Generated: {report['generated_at']}", 0, 1, 'C')
        pdf.ln(10)
        
        # Summary
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Summary', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for key, value in report['summary'].items():
            pdf.cell(0, 8, f"{key.replace('_', ' ').title()}: {value}", 0, 1)
        
        pdf.ln(5)
        
        # Top Attacking IPs
        if 'top_attacking_ips' in report and report['top_attacking_ips']:
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Top Attacking IPs', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            for item in report['top_attacking_ips'][:10]:
                pdf.cell(0, 8, f"{item['ip']}: {item['count']} attempts", 0, 1)
            
            pdf.ln(5)
        
        # Top Targeted Users
        if 'top_targeted_users' in report and report['top_targeted_users']:
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Top Targeted Users', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            for item in report['top_targeted_users'][:10]:
                pdf.cell(0, 8, f"{item['username']}: {item['count']} failed attempts", 0, 1)
        
        return pdf.output(dest='S').encode('latin-1')

# Made with Bob
