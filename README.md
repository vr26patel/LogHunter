# 🛡️ LogHunter - Real-Time Security Log Analyzer

LogHunter is a lightweight cybersecurity tool that analyzes Linux system logs and detects potential attack patterns in real time.

It works like a **mini SIEM (Security Information and Event Management)** system and displays alerts on a live web dashboard.

---

## 🚀 Features

* 🔍 Detects **SSH Brute Force Attacks**
* 💉 Detects **SQL Injection Attempts**
* ⚠️ Detects **Cross-Site Scripting (XSS)**
* 📁 Detects **Directory Traversal Attacks**
* 🧰 Detects **Security Scanners (Nmap, SQLMap, etc.)**
* 🔐 Detects **Privilege Escalation Attempts**
* 📊 Live **Web Dashboard with Alerts & Stats**
* 🔄 Automatic scanning every 60 seconds
* 🎭 Demo alerts when no real logs are found

---

## ⚙️ Tech Stack

* Python
* Flask
* Regular Expressions (Regex)
* Linux System Logs
* Multithreading

---

## 📦 Installation

```bash
git clone https://github.com/vr26patel/LogHunter.git
cd LogHunter
pip install flask
```

---

## 🖥️ How to Run

```bash
sudo python3 loghunter.py
```

Open in browser:

```
http://localhost:5000
```

---

## 🧠 How It Works

1. Reads Linux system log files (auth logs, Apache logs)
2. Matches log entries using predefined regex attack patterns
3. Generates alerts with severity levels (Critical, High, Medium)
4. Displays alerts on a live dashboard
5. Runs continuously with automatic background scanning

---

## ⚠️ Notes

* Some log files require **sudo permissions**
* On systems like Kali Linux, logs may differ (journalctl instead of auth.log)
* Demo alerts are generated if no real attack logs are found

---

## 🎯 Future Improvements

* Real-time log streaming (live monitoring)
* GeoIP tracking of attacker IP addresses
* Automatic IP blocking (like fail2ban)
* Email / Telegram alerts
* Cloud deployment (AWS / VPS)

---

## 👨‍💻 Author

**VR (vr26patel)**
Cybersecurity Enthusiast

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!
