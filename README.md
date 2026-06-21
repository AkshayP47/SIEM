# Mini SIEM - Security Information and Event Management System

A lightweight, Python-based SIEM platform that runs directly on your host machine without Docker. Built with FastAPI, SQLite, and modern web technologies.

![Mini SIEM](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.12-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

## 🚀 Features

### Core Functionality
- **Log Collection**: Collect logs from files, API endpoints, and system sources
- **Log Normalization**: Convert logs from various formats into a standardized structure
- **Detection Engine**: Real-time security threat detection with multiple rules
- **Alert Management**: Create, view, resolve, and track security alerts
- **Incident Management**: Track and manage security incidents
- **Dashboard**: Real-time security monitoring with interactive charts
- **Reporting**: Generate daily, weekly, and incident-specific reports (PDF/CSV)
- **Authentication**: Secure user authentication with JWT tokens

### Detection Rules
1. **Brute Force Detection**: Detects >5 failed logins from same IP within 2 minutes
2. **Port Scan Detection**: Detects >20 port access attempts from same IP within 60 seconds
3. **Suspicious Login Detection**: Flags logins outside business hours (9 AM - 6 PM)
4. **Excessive Failed Logins**: Detects >10 failed logins for same user within 5 minutes
5. **Privilege Escalation Detection**: Detects sudo/admin privilege changes

### MITRE ATT&CK Mapping
- T1110: Brute Force
- T1046: Network Service Scanning
- T1078: Valid Accounts
- T1548: Abuse Elevation Control Mechanism

## 📋 Requirements

- Python 3.12 or higher
- Windows, Linux, or macOS
- 2GB RAM minimum
- 500MB disk space

## 🔧 Installation

### Step 1: Clone or Download

```bash
cd mini_siem
```

### Step 2: Create Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run the Application

```bash
python app.py
```

The application will start on `http://localhost:8000`

## 🎯 Quick Start

### 1. Login
- Open your browser and navigate to `http://localhost:8000`
- Default credentials:
  - **Username**: `admin`
  - **Password**: `admin123`

### 2. Generate Sample Data
- Go to the Dashboard
- Click "Generate Sample Data"
- Select a scenario (Mixed Events, Brute Force, Port Scan, etc.)
- Click "Generate"

### 3. Explore Features
- **Dashboard**: View security overview and statistics
- **Logs**: Search and filter security logs
- **Alerts**: View and manage security alerts
- **Incidents**: Create and track security incidents
- **Reports**: Generate and export security reports

## 📁 Project Structure

```
mini_siem/
├── app.py                      # Main FastAPI application
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── database/                   # SQLite database storage
│   └── siem.db                # Database file (auto-created)
│
├── models/                     # Database models
│   ├── __init__.py
│   ├── database.py            # Database configuration
│   ├── log.py                 # Log model
│   ├── alert.py               # Alert model
│   ├── user.py                # User model
│   └── incident.py            # Incident model
│
├── services/                   # Business logic services
│   ├── auth.py                # Authentication service
│   ├── log_normalizer.py      # Log normalization
│   └── reporting.py           # Report generation
│
├── detection_engine/           # Security detection rules
│   └── rules.py               # Detection rules implementation
│
├── log_collectors/             # Log collection modules
│   ├── collector.py           # Log collector
│   └── simulator.py           # Sample data generator
│
├── templates/                  # HTML templates
│   ├── base.html              # Base template
│   ├── login.html             # Login page
│   ├── dashboard.html         # Dashboard
│   ├── logs.html              # Log explorer
│   ├── alerts.html            # Alerts page
│   ├── incidents.html         # Incidents page
│   └── reports.html           # Reports page
│
├── static/                     # Static files
│   ├── css/
│   │   └── style.css          # Custom styles
│   └── js/
│       └── common.js          # Common JavaScript
│
└── reports/                    # Generated reports (auto-created)
```

## 🔐 Security Features

### Authentication
- JWT-based authentication
- Password hashing with bcrypt
- Session management
- Role-based access control (Admin, Analyst, Viewer)

### Log Security
- All logs stored in SQLite database
- Normalized log format for consistency
- Raw log preservation for forensics
- Timestamp tracking for all events

## 📊 API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user info

### Logs
- `POST /api/logs/ingest` - Ingest a log entry
- `GET /api/logs` - Get logs with filtering

### Alerts
- `GET /api/alerts` - Get alerts with filtering
- `PUT /api/alerts/{id}/resolve` - Resolve an alert
- `DELETE /api/alerts/{id}` - Delete an alert

### Incidents
- `GET /api/incidents` - Get incidents
- `POST /api/incidents` - Create incident
- `PUT /api/incidents/{id}` - Update incident

### Reports
- `GET /api/reports/daily` - Generate daily report
- `GET /api/reports/weekly` - Generate weekly report
- `GET /api/reports/incident/{id}` - Generate incident report
- `GET /api/reports/export/csv` - Export report as CSV
- `GET /api/reports/export/pdf` - Export report as PDF

### Simulator
- `POST /api/simulator/generate` - Generate sample logs

## 🎨 Dashboard Features

### Statistics Cards
- Total Logs
- Total Alerts
- Critical Alerts
- Active Alerts

### Charts
- Alert Trend (Last 7 Days) - Line chart
- Severity Distribution - Doughnut chart
- Event Type Distribution - Bar chart
- Top Attacking IPs - Horizontal bar chart

### Tables
- Top Targeted Users with risk levels

## 🔍 Log Explorer

### Filters
- Username
- Source IP
- Event Type
- Severity
- Date Range

### Features
- Pagination
- Log detail view
- Real-time search
- Export capabilities

## ⚠️ Alert Management

### Alert Properties
- Alert Type
- Severity (Critical, High, Medium, Low)
- Status (Active, Investigating, Resolved)
- Source IP
- Username
- MITRE ATT&CK ID
- Detection Rule

### Actions
- View alert details
- Resolve alerts with notes
- Filter by severity/status
- Auto-refresh every 30 seconds

## 🐛 Incident Management

### Incident Properties
- Title
- Description
- Severity
- Status (Open, Investigating, Resolved, Closed)
- Assigned To
- Created By
- Notes

### Actions
- Create incidents
- Update incident status
- Add investigation notes
- Link to alerts

## 📈 Reporting

### Report Types
1. **Daily Report**: Security events from today
2. **Weekly Report**: Security events from last 7 days
3. **Incident Report**: Detailed report for specific incident

### Export Formats
- CSV (Comma-Separated Values)
- PDF (Portable Document Format)

### Report Contents
- Summary statistics
- Top attacking IPs
- Top targeted users
- Recent alerts
- Event distribution

## 🛠️ Configuration

### Change Default Admin Password
After first login, create a new admin user and delete the default one.

### Database Location
The SQLite database is stored in `database/siem.db`. To reset:
```bash
rm database/siem.db
python app.py  # Will recreate with default admin
```

### Port Configuration
To change the default port (8000), edit `app.py`:
```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=YOUR_PORT)
```

## 🧪 Testing

### Generate Test Data
1. Login to the dashboard
2. Click "Generate Sample Data"
3. Choose a scenario:
   - **Mixed Events**: Realistic mix of events
   - **Brute Force**: Simulates brute force attack
   - **Port Scan**: Simulates port scanning
   - **Suspicious Login**: Login outside business hours
   - **Privilege Escalation**: Sudo/admin activities

### Manual Log Ingestion
Use the API to ingest custom logs:
```bash
curl -X POST http://localhost:8000/api/logs/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "timestamp": "2024-01-01T12:00:00Z",
    "username": "testuser",
    "source_ip": "192.168.1.100",
    "event_type": "failed_authentication",
    "severity": "warning",
    "message": "Failed login attempt"
  }'
```

## 🚨 Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/macOS
lsof -ti:8000 | xargs kill -9
```

### Database Locked
Stop all running instances of the application and restart.

### Import Errors
Ensure all dependencies are installed:
```bash
pip install -r requirements.txt --upgrade
```

## 📝 Log Format

### Normalized Log Structure
```json
{
  "timestamp": "ISO 8601 format",
  "username": "string or null",
  "source_ip": "IP address or null",
  "hostname": "string or null",
  "event_type": "string",
  "severity": "critical|high|medium|low|info",
  "message": "string"
}
```

### Supported Event Types
- `authentication`
- `failed_authentication`
- `successful_authentication`
- `port_scan`
- `privilege_escalation`
- `file_access`
- `system_event`
- `network_connection`

## 🤝 Contributing

This is a learning project. Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Improve documentation

## 📄 License

MIT License - Feel free to use this project for learning and development.

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- Bootstrap for the UI components
- Chart.js for data visualization
- SQLAlchemy for database ORM

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Check application logs in the console

## 🔮 Future Enhancements

- [ ] Real-time log streaming
- [ ] Email notifications for critical alerts
- [ ] Integration with external SIEM tools
- [ ] Machine learning-based anomaly detection
- [ ] GeoIP location tracking
- [ ] Custom detection rules via UI
- [ ] Multi-user collaboration features
- [ ] Advanced search with Elasticsearch
- [ ] Mobile-responsive improvements
- [ ] Dark mode theme

---

**Built with ❤️ for cybersecurity learning and development**"# SIEM" 
