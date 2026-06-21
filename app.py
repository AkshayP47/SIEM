"""
Mini SIEM - Main Application
FastAPI-based Security Information and Event Management System
"""
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import Optional, List
import json
import io

# Import models and services
from models.database import get_db, init_db
from models.log import Log
from models.alert import Alert
from models.user import User
from models.incident import Incident
from services.auth import AuthService, security
from services.log_normalizer import LogNormalizer
from services.reporting import ReportGenerator
from log_collectors.collector import LogCollector
from log_collectors.simulator import LogSimulator
from detection_engine.rules import DetectionEngine

# Initialize FastAPI app
app = FastAPI(
    title="Mini SIEM",
    description="Security Information and Event Management System",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Initialize services
auth_service = AuthService()
log_normalizer = LogNormalizer()
log_collector = LogCollector()
log_simulator = LogSimulator()
detection_engine = DetectionEngine()


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database and create default admin user"""
    init_db()
    db = next(get_db())
    auth_service.create_default_admin(db)
    print("Mini SIEM started successfully!")
    print("Default credentials: username=admin, password=admin123")


# ============================================================================
# Authentication Routes
# ============================================================================

@app.post("/api/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    """User login endpoint"""
    try:
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        
        user = auth_service.authenticate_user(db, username, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        access_token = auth_service.create_access_token(data={"sub": user.username})
        
        return {
            'access_token': access_token,
            'token_type': 'bearer',
            'user': user.to_dict()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/auth/me")
async def get_current_user_info(credentials = Depends(security), db: Session = Depends(get_db)):
    """Get current user information"""
    user = auth_service.get_current_user(credentials, db)
    return user.to_dict()


# ============================================================================
# Log Management Routes
# ============================================================================

@app.post("/api/logs/ingest")
async def ingest_log(request: Request, db: Session = Depends(get_db)):
    """Ingest a log entry via API"""
    try:
        log_data = await request.json()
        
        # Normalize log
        normalized_log = log_collector.collect_from_api(log_data)
        
        # Save to database
        log_entry = Log(
            timestamp=datetime.fromisoformat(normalized_log['timestamp'].replace('Z', '+00:00')),
            username=normalized_log.get('username'),
            source_ip=normalized_log.get('source_ip'),
            hostname=normalized_log.get('hostname'),
            event_type=normalized_log.get('event_type'),
            severity=normalized_log.get('severity'),
            message=normalized_log.get('message'),
            raw_log=json.dumps(log_data)
        )
        db.add(log_entry)
        db.commit()
        
        # Run detection engine
        alerts = detection_engine.analyze_log(normalized_log, db)
        
        # Save alerts
        for alert_data in alerts:
            alert = Alert(
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                description=alert_data['description'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                detection_rule=alert_data.get('detection_rule'),
                mitre_attack_id=alert_data.get('mitre_attack_id')
            )
            db.add(alert)
        
        db.commit()
        
        return {
            'status': 'success',
            'log_id': log_entry.id,
            'alerts_generated': len(alerts)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/logs")
async def get_logs(
    skip: int = 0,
    limit: int = 100,
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get logs with filtering"""
    query = db.query(Log)
    
    if username:
        query = query.filter(Log.username.contains(username))
    if source_ip:
        query = query.filter(Log.source_ip == source_ip)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    if severity:
        query = query.filter(Log.severity == severity)
    if start_date:
        query = query.filter(Log.timestamp >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(Log.timestamp <= datetime.fromisoformat(end_date))
    
    total = query.count()
    logs = query.order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        'total': total,
        'logs': [log.to_dict() for log in logs]
    }


# ============================================================================
# Alert Management Routes
# ============================================================================

@app.get("/api/alerts")
async def get_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get alerts with filtering"""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type.contains(alert_type))
    
    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        'total': total,
        'alerts': [alert.to_dict() for alert in alerts]
    }


@app.put("/api/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    request: Request,
    credentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Resolve an alert"""
    user = auth_service.get_current_user(credentials, db)
    data = await request.json()
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Update alert status and resolution details
    alert.status = 'resolved'  # type: ignore[assignment]
    alert.resolved_at = datetime.utcnow()  # type: ignore[assignment]
    alert.resolved_by = user.username  # type: ignore[assignment]
    alert.resolution_notes = data.get('notes', '')  # type: ignore[assignment]
    
    db.commit()
    
    return alert.to_dict()


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(
    alert_id: int,
    credentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Delete an alert"""
    user = auth_service.get_current_user(credentials, db)
    
    if user.role != 'admin':  # type: ignore[comparison-overlap]
        raise HTTPException(status_code=403, detail="Only admins can delete alerts")
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(alert)
    db.commit()
    
    return {'status': 'success', 'message': 'Alert deleted'}


# ============================================================================
# Dashboard Routes
# ============================================================================

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    # Total logs
    total_logs = db.query(Log).count()
    
    # Total alerts
    total_alerts = db.query(Alert).count()
    
    # Critical alerts
    critical_alerts = db.query(Alert).filter(Alert.severity == 'critical').count()
    
    # Active alerts
    active_alerts = db.query(Alert).filter(Alert.status == 'active').count()
    
    # Recent alerts (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_alerts = db.query(Alert).filter(Alert.timestamp >= yesterday).count()
    
    # Alert trend (last 7 days)
    alert_trend = []
    for i in range(7):
        day_start = datetime.utcnow().replace(hour=0, minute=0, second=0) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        count = db.query(Alert).filter(
            Alert.timestamp >= day_start,
            Alert.timestamp < day_end
        ).count()
        alert_trend.append({
            'date': day_start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    alert_trend.reverse()
    
    # Event type distribution
    event_types = db.query(Log.event_type, func.count(Log.id)).group_by(Log.event_type).all()
    event_distribution = [{'type': et[0], 'count': et[1]} for et in event_types]
    
    # Severity distribution
    severities = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_distribution = [{'severity': s[0], 'count': s[1]} for s in severities]
    
    # Top attacking IPs
    top_ips = db.query(Log.source_ip, func.count(Log.id)).filter(
        Log.event_type.in_(['failed_authentication', 'port_scan']),
        Log.source_ip.isnot(None)
    ).group_by(Log.source_ip).order_by(func.count(Log.id).desc()).limit(10).all()
    
    top_attacking_ips = [{'ip': ip[0], 'count': ip[1]} for ip in top_ips]
    
    # Top targeted users
    top_users = db.query(Log.username, func.count(Log.id)).filter(
        Log.event_type == 'failed_authentication',
        Log.username.isnot(None)
    ).group_by(Log.username).order_by(func.count(Log.id).desc()).limit(10).all()
    
    top_targeted_users = [{'username': u[0], 'count': u[1]} for u in top_users]
    
    return {
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'active_alerts': active_alerts,
        'recent_alerts': recent_alerts,
        'alert_trend': alert_trend,
        'event_distribution': event_distribution,
        'severity_distribution': severity_distribution,
        'top_attacking_ips': top_attacking_ips,
        'top_targeted_users': top_targeted_users
    }


# ============================================================================
# Incident Management Routes
# ============================================================================

@app.get("/api/incidents")
async def get_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get incidents"""
    query = db.query(Incident)
    
    if status:
        query = query.filter(Incident.status == status)
    
    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        'total': total,
        'incidents': [incident.to_dict() for incident in incidents]
    }


@app.post("/api/incidents")
async def create_incident(
    request: Request,
    credentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Create a new incident"""
    user = auth_service.get_current_user(credentials, db)
    data = await request.json()
    
    incident = Incident(
        alert_id=data.get('alert_id'),
        title=data['title'],
        description=data.get('description'),
        severity=data['severity'],
        status='open',
        created_by=user.username,
        notes=data.get('notes')
    )
    
    db.add(incident)
    db.commit()
    
    return incident.to_dict()


@app.put("/api/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    request: Request,
    credentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Update an incident"""
    user = auth_service.get_current_user(credentials, db)
    data = await request.json()
    
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if 'status' in data:
        incident.status = data['status']  # type: ignore[assignment]
        if data['status'] == 'resolved':
            incident.resolved_at = datetime.utcnow()  # type: ignore[assignment]
    
    if 'notes' in data:
        incident.notes = data['notes']  # type: ignore[assignment]
    
    if 'assigned_to' in data:
        incident.assigned_to = data['assigned_to']  # type: ignore[assignment]
    
    # Note: updated_at has onupdate trigger, but we set it explicitly for immediate effect
    incident.updated_at = datetime.utcnow()  # type: ignore[assignment]
    
    db.commit()
    
    return incident.to_dict()


# ============================================================================
# Reporting Routes
# ============================================================================

@app.get("/api/reports/daily")
async def generate_daily_report(db: Session = Depends(get_db)):
    """Generate daily report"""
    report_gen = ReportGenerator(db)
    report = report_gen.generate_daily_report()
    return report


@app.get("/api/reports/weekly")
async def generate_weekly_report(db: Session = Depends(get_db)):
    """Generate weekly report"""
    report_gen = ReportGenerator(db)
    report = report_gen.generate_weekly_report()
    return report


@app.get("/api/reports/incident/{incident_id}")
async def generate_incident_report(incident_id: int, db: Session = Depends(get_db)):
    """Generate incident report"""
    report_gen = ReportGenerator(db)
    report = report_gen.generate_incident_report(incident_id)
    return report


@app.get("/api/reports/export/csv")
async def export_report_csv(report_type: str = 'daily', db: Session = Depends(get_db)):
    """Export report as CSV"""
    report_gen = ReportGenerator(db)
    
    if report_type == 'daily':
        report = report_gen.generate_daily_report()
    elif report_type == 'weekly':
        report = report_gen.generate_weekly_report()
    else:
        raise HTTPException(status_code=400, detail="Invalid report type")
    
    csv_data = report_gen.export_to_csv(report)
    
    return StreamingResponse(
        io.StringIO(csv_data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={report_type}_report.csv"}
    )


@app.get("/api/reports/export/pdf")
async def export_report_pdf(report_type: str = 'daily', db: Session = Depends(get_db)):
    """Export report as PDF"""
    report_gen = ReportGenerator(db)
    
    if report_type == 'daily':
        report = report_gen.generate_daily_report()
    elif report_type == 'weekly':
        report = report_gen.generate_weekly_report()
    else:
        raise HTTPException(status_code=400, detail="Invalid report type")
    
    pdf_data = report_gen.export_to_pdf(report)
    
    return StreamingResponse(
        io.BytesIO(pdf_data),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={report_type}_report.pdf"}
    )


# ============================================================================
# Simulator Routes
# ============================================================================

@app.post("/api/simulator/generate")
async def generate_sample_logs(
    request: Request,
    credentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Generate sample logs for testing"""
    data = await request.json()
    scenario = data.get('scenario', 'mixed')
    count = data.get('count', 50)
    
    logs = []
    
    if scenario == 'brute_force':
        logs = log_simulator.generate_brute_force_attack()
    elif scenario == 'port_scan':
        logs = log_simulator.generate_port_scan(25)
    elif scenario == 'suspicious_login':
        logs = log_simulator.generate_suspicious_login()
    elif scenario == 'privilege_escalation':
        logs = log_simulator.generate_privilege_escalation(5)
    else:
        logs = log_simulator.generate_mixed_scenario(count)
    
    # Save logs to database
    alerts_generated = 0
    for log_data in logs:
        log_entry = Log(
            timestamp=datetime.fromisoformat(log_data['timestamp'].replace('Z', '+00:00')),
            username=log_data.get('username'),
            source_ip=log_data.get('source_ip'),
            hostname=log_data.get('hostname'),
            event_type=log_data.get('event_type'),
            severity=log_data.get('severity'),
            message=log_data.get('message'),
            raw_log=json.dumps(log_data)
        )
        db.add(log_entry)
        db.flush()
        
        # Run detection engine
        alerts = detection_engine.analyze_log(log_data, db)
        
        # Save alerts
        for alert_data in alerts:
            alert = Alert(
                alert_type=alert_data['alert_type'],
                severity=alert_data['severity'],
                description=alert_data['description'],
                source_ip=alert_data.get('source_ip'),
                username=alert_data.get('username'),
                detection_rule=alert_data.get('detection_rule'),
                mitre_attack_id=alert_data.get('mitre_attack_id')
            )
            db.add(alert)
            alerts_generated += 1
    
    db.commit()
    
    return {
        'status': 'success',
        'logs_generated': len(logs),
        'alerts_generated': alerts_generated
    }


# ============================================================================
# Web Interface Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Login page"""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Logs explorer page"""
    return templates.TemplateResponse("logs.html", {"request": request})


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Alerts page"""
    return templates.TemplateResponse("alerts.html", {"request": request})


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request):
    """Incidents page"""
    return templates.TemplateResponse("incidents.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Reports page"""
    return templates.TemplateResponse("reports.html", {"request": request})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Made with Bob
