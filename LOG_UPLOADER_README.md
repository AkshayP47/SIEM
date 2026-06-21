How to Use log_uploader.py with Real System Logs
For Windows (Your Current System):
1. Export Windows Event Logs
# Open PowerShell as Administrator

# Export Security logs
wevtutil epl Security C:\logs\Security.evtx

# Export System logs
wevtutil epl System C:\logs\System.evtx

# Export Application logs
wevtutil epl Application C:\logs\Application.evtx

# Or use Event Viewer GUI:
# 1. Open Event Viewer (eventvwr.msc)
# 2. Right-click on Security/System/Application
# 3. Save All Events As... → Choose .evtx format

2. Upload to Mini SIEM
# Start Mini SIEM first
cd mini_siem
python app.py

# In another terminal, upload the logs
python log_uploader.py C:\logs\Security.evtx
python log_uploader.py C:\logs\System.evtx
python log_uploader.py C:\logs\Application.evtx

For Your Forensic Image (jeoevidence.e01):
# 1. Mount the .e01 image using FTK Imager or Arsenal Image Mounter
# 2. Navigate to: [MountedDrive]\Windows\System32\winevt\Logs\
# 3. Copy .evtx files to a local folder
# 4. Upload them:

python log_uploader.py D:\extracted_logs\Security.evtx
python log_uploader.py D:\extracted_logs\System.evtx

For Other Log Formats:
# Text logs (auth.log, syslog, custom logs)
python log_uploader.py C:\logs\application.log

# CSV logs
python log_uploader.py C:\logs\access_logs.csv

# JSON logs
python log_uploader.py C:\logs\api_logs.json

# IIS logs
python log_uploader.py C:\inetpub\logs\LogFiles\W3SVC1\u_ex231221.log

Real-Time Monitoring (Quick Script):
Create monitor_logs.py:

import time
import subprocess
import os

while True:
    # Export latest Windows logs every 5 minutes
    os.system('wevtutil epl Security C:\\temp\\Security.evtx /ow:true')
    
    # Upload to SIEM
    subprocess.run(['python', 'log_uploader.py', 'C:\\temp\\Security.evtx'])
    
    print("Logs uploaded. Waiting 5 minutes...")
    time.sleep(300)  # Wait 5 minutes









# Mini SIEM Log Uploader

A standalone Python script to upload various log formats to Mini SIEM.

## Features

✅ **Supports Multiple Formats:**
- Windows Event Logs (.evtx, .e0)
- CSV files (.csv)
- JSON files (.json)
- Text/Log files (.txt, .log)
- XML files (.xml)

✅ **Automatic Conversion:**
- Parses different log formats
- Extracts usernames, IPs, hostnames
- Maps event types and severity levels
- Sends to Mini SIEM API

✅ **Standalone:**
- No need to modify Mini SIEM code
- Works independently
- Can be run from anywhere

## Installation

### 1. Install Required Libraries

```bash
pip install requests
```

### 2. For Windows Event Log Support (Optional)

```bash
pip install python-evtx
```

**Note:** If you don't install `python-evtx`, you can still use the script with other formats, or export your .evtx files to CSV/TXT first.

## Usage

### Basic Usage

```bash
python log_uploader.py <log_file_path>
```

### With Custom SIEM URL

```bash
python log_uploader.py <log_file_path> <siem_url>
```

## Examples

### Upload Windows Event Log

```bash
python log_uploader.py Security.evtx
```

### Upload CSV File

```bash
python log_uploader.py auth_logs.csv
```

### Upload Text Log

```bash
python log_uploader.py system.log
```

### Upload JSON Logs

```bash
python log_uploader.py events.json
```

### Upload to Remote SIEM

```bash
python log_uploader.py logs.txt http://192.168.1.100:8000
```

## Exporting Windows Event Logs

If you don't have `python-evtx` installed, export your Windows Event Logs first:

### Method 1: Export as Text (Recommended)

1. Open **Event Viewer** (eventvwr.msc)
2. Navigate to the log you want (e.g., Security, System, Application)
3. Right-click → **Save All Events As...**
4. Choose format: **Text (Tab Delimited) (*.txt)**
5. Save the file
6. Run: `python log_uploader.py exported_events.txt`

### Method 2: Export as CSV

1. Open **Event Viewer**
2. Right-click log → **Save All Events As...**
3. Choose format: **CSV (Comma Delimited) (*.csv)**
4. Save the file
5. Run: `python log_uploader.py exported_events.csv`

### Method 3: Export as XML

1. Open **Event Viewer**
2. Right-click log → **Save All Events As...**
3. Choose format: **XML**
4. Save the file
5. Run: `python log_uploader.py exported_events.xml`

## Supported Log Formats

### CSV Format

The script automatically detects common column names:
- `timestamp`, `time`, `Date and Time`
- `username`, `user`, `User`
- `source_ip`, `ip`, `Source`
- `hostname`, `host`, `Computer`
- `event_type`, `type`, `Level`
- `message`, `Message`, `Description`

### JSON Format

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "username": "john.doe",
  "source_ip": "192.168.1.100",
  "hostname": "workstation-01",
  "event_type": "failed_authentication",
  "severity": "warning",
  "message": "Failed login attempt"
}
```

Or array of logs:
```json
[
  { "timestamp": "...", "message": "..." },
  { "timestamp": "...", "message": "..." }
]
```

### Text/Log Format

Any text file with one log entry per line. The script will:
- Extract IP addresses automatically
- Detect usernames (user=, user:, etc.)
- Identify hostnames (host=, host:, etc.)
- Classify event types (failed login, port scan, etc.)
- Determine severity levels

Example:
```
2024-01-01 12:00:00 Failed login for user john.doe from 192.168.1.100
2024-01-01 12:01:00 Successful authentication for user admin from 10.0.0.1
```

## Windows Event ID Mapping

The script automatically maps common Windows Event IDs:

| Event ID | Event Type |
|----------|------------|
| 4624 | Successful Authentication |
| 4625 | Failed Authentication |
| 4648 | Successful Authentication (Explicit Credentials) |
| 4672 | Privilege Escalation |
| 4720 | User Created |
| 4726 | User Deleted |
| 4732 | Group Membership Change |
| 4688 | Process Creation |
| 5140 | File Access |
| 5145 | File Access (Network Share) |

## Troubleshooting

### Error: Cannot connect to Mini SIEM

**Problem:** `Cannot connect to Mini SIEM at http://localhost:8000`

**Solution:**
1. Make sure Mini SIEM is running:
   ```bash
   cd mini_siem
   python app.py
   ```
2. Check the URL is correct (use `localhost:8000` not `0.0.0.0:8000`)
3. If SIEM is on another machine, use: `python log_uploader.py logs.txt http://192.168.1.100:8000`

### Error: python-evtx not installed

**Problem:** `Error: python-evtx library not installed`

**Solution:**
- Install it: `pip install python-evtx`
- OR export your .evtx file to CSV/TXT format first (see above)

### Error: File not found

**Problem:** `Error: File not found: mylog.txt`

**Solution:**
- Check the file path is correct
- Use absolute path: `python log_uploader.py C:\Users\YourName\Desktop\logs.txt`
- Or navigate to the directory first: `cd C:\Users\YourName\Desktop` then `python log_uploader.py logs.txt`

### Slow Upload

**Problem:** Uploading large files is slow

**Solution:**
- The script uploads logs one by one for reliability
- For very large files (>10,000 events), consider splitting them
- Progress is shown every 10 logs

## Output Example

```
============================================================
🔐 Mini SIEM - Standalone Log Uploader
============================================================
📁 Processing file: Security.evtx
🔗 Target SIEM: http://localhost:8000
------------------------------------------------------------
📊 Processing Windows Event Log (EVTX format)...
✓ Uploaded 10 logs...
✓ Uploaded 20 logs...
✓ Uploaded 30 logs...
------------------------------------------------------------
✅ Successfully uploaded: 35 logs
❌ Failed to upload: 0 logs

✅ Upload complete!
📊 View logs at: http://localhost:8000/logs
```

## Advanced Usage

### Batch Upload Multiple Files

Windows:
```batch
for %f in (*.log) do python log_uploader.py %f
```

Linux/Mac:
```bash
for file in *.log; do python log_uploader.py "$file"; done
```

### Schedule Automatic Uploads

**Windows Task Scheduler:**
1. Create a batch file `upload_logs.bat`:
   ```batch
   @echo off
   cd C:\path\to\script
   python log_uploader.py C:\path\to\logs\Security.evtx
   ```
2. Schedule it in Task Scheduler

**Linux Cron:**
```bash
# Add to crontab (crontab -e)
0 * * * * /usr/bin/python3 /path/to/log_uploader.py /var/log/auth.log
```

## Security Notes

- The script sends logs over HTTP by default
- For production, use HTTPS: `https://your-siem.com:8000`
- Ensure proper network security between uploader and SIEM
- Consider authentication if exposing SIEM API publicly

## Support

For issues or questions:
1. Check this README
2. Verify Mini SIEM is running
3. Test with a small sample file first
4. Check the console output for error messages

## License

This script is part of the Mini SIEM project.