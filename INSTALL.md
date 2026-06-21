# Mini SIEM - Installation Guide

## Quick Installation (5 Minutes)

### Prerequisites
- Python 3.12+ installed
- pip package manager
- Terminal/Command Prompt access

### Step-by-Step Installation

#### 1. Navigate to Project Directory
```bash
cd mini_siem
```

#### 2. Create Virtual Environment (Recommended)

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

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

This will install:
- FastAPI (Web framework)
- Uvicorn (ASGI server)
- SQLAlchemy (Database ORM)
- Jinja2 (Template engine)
- Python-Jose (JWT tokens)
- Passlib (Password hashing)
- Pandas (Data processing)
- ReportLab/FPDF2 (PDF generation)
- And other dependencies

#### 4. Run the Application
```bash
python app.py
```

You should see:
```
INFO:     Started server process
INFO:     Waiting for application startup.
Mini SIEM started successfully!
Default credentials: username=admin, password=admin123
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

#### 5. Access the Application
Open your browser and go to:
```
http://localhost:8000
```

#### 6. Login
Use the default credentials:
- **Username**: `admin`
- **Password**: `admin123`

## Verification Steps

### 1. Check Dashboard
- After login, you should see the dashboard with 4 statistics cards
- All values should be 0 initially

### 2. Generate Sample Data
- Click "Generate Sample Data" button
- Select "Mixed Events (Realistic)"
- Set count to 50
- Click "Generate"
- You should see a success message

### 3. Verify Data
- Dashboard should now show statistics
- Navigate to "Logs" to see generated logs
- Navigate to "Alerts" to see detected threats
- Charts should display data

## Troubleshooting

### Issue: Port 8000 Already in Use

**Windows:**
```bash
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

**Linux/macOS:**
```bash
lsof -ti:8000 | xargs kill -9
```

Or change the port in `app.py`:
```python
uvicorn.run(app, host="0.0.0.0", port=8080)  # Use port 8080
```

### Issue: Module Not Found

Ensure virtual environment is activated and dependencies are installed:
```bash
pip install -r requirements.txt --upgrade
```

### Issue: Permission Denied (Linux/macOS)

Use `sudo` or check file permissions:
```bash
chmod +x app.py
```

### Issue: Database Locked

Stop all running instances:
```bash
# Find process
ps aux | grep python

# Kill process
kill -9 <PID>
```

## Directory Structure After Installation

```
mini_siem/
├── app.py                      ✓ Main application
├── requirements.txt            ✓ Dependencies
├── README.md                   ✓ Documentation
├── INSTALL.md                  ✓ This file
│
├── database/
│   └── siem.db                 ✓ Created on first run
│
├── models/                     ✓ Database models
├── services/                   ✓ Business logic
├── detection_engine/           ✓ Security rules
├── log_collectors/             ✓ Log collection
├── templates/                  ✓ HTML pages
├── static/                     ✓ CSS/JS files
└── reports/                    ✓ Generated reports
```

## Next Steps

1. **Change Default Password**
   - Create a new admin user
   - Delete the default admin

2. **Explore Features**
   - Generate different attack scenarios
   - Create incidents
   - Generate reports

3. **Customize**
   - Modify detection rules in `detection_engine/rules.py`
   - Adjust thresholds for alerts
   - Add custom log sources

4. **Production Deployment**
   - Change SECRET_KEY in `services/auth.py`
   - Use environment variables for configuration
   - Set up proper logging
   - Configure firewall rules
   - Use HTTPS with reverse proxy (nginx/Apache)

## System Requirements

### Minimum
- CPU: 1 core
- RAM: 2GB
- Disk: 500MB
- OS: Windows 10, Ubuntu 20.04, macOS 10.15+

### Recommended
- CPU: 2+ cores
- RAM: 4GB
- Disk: 2GB
- OS: Windows 11, Ubuntu 22.04, macOS 12+

## Performance Tips

1. **Database Optimization**
   - Regularly clean old logs
   - Index frequently queried fields
   - Use pagination for large datasets

2. **Memory Management**
   - Limit log retention period
   - Archive old data
   - Monitor memory usage

3. **Network**
   - Use local network for better performance
   - Enable compression for API responses
   - Cache static files

## Security Recommendations

1. **Change Default Credentials**
   ```python
   # After first login, create new admin and delete default
   ```

2. **Update SECRET_KEY**
   ```python
   # In services/auth.py
   SECRET_KEY = "your-secure-random-key-here"
   ```

3. **Enable HTTPS**
   - Use reverse proxy (nginx/Apache)
   - Obtain SSL certificate
   - Redirect HTTP to HTTPS

4. **Firewall Configuration**
   ```bash
   # Allow only necessary ports
   ufw allow 8000/tcp
   ```

5. **Regular Updates**
   ```bash
   pip install -r requirements.txt --upgrade
   ```

## Uninstallation

To completely remove Mini SIEM:

1. **Deactivate Virtual Environment**
   ```bash
   deactivate
   ```

2. **Remove Directory**
   ```bash
   cd ..
   rm -rf mini_siem  # Linux/macOS
   rmdir /s mini_siem  # Windows
   ```

## Support

For issues:
1. Check this installation guide
2. Review README.md
3. Check application logs in terminal
4. Verify all dependencies are installed

## Success Indicators

✓ Application starts without errors
✓ Can access http://localhost:8000
✓ Can login with default credentials
✓ Dashboard loads successfully
✓ Can generate sample data
✓ Logs and alerts are visible
✓ Charts display correctly
✓ Can generate reports

---

**Installation Complete! 🎉**

You now have a fully functional Mini SIEM platform running on your machine.