# **Windows-Threat-Detection-using-Sysmon-Logs
**
 # 🛡️ Windows Threat Detector (Sysmon-Based)

A Python-based threat detection engine that analyzes Sysmon logs to identify suspicious activities such as malware execution, persistence mechanisms, and file-based attacks.

## 🚀 Features

- 📄 Sysmon log parsing (XML)
- 🔍 Detection of suspicious activities:
  - Encoded PowerShell execution
  - Registry persistence (Run keys)
  - Suspicious file drops
- 🧠 MITRE ATT&CK mapping
- 📊 Structured alert output (JSON)

---

## 🏗️ Architecture

Sysmon Logs → Parser → Detection Rules → Alerts → JSON Output

---

## 🧪 Sample Output

[ALERT]
Type: Suspicious PowerShell Execution
Severity: HIGH
MITRE: T1059


---

## 🛠️ Tech Stack

- Python
- Sysmon Logs
- MITRE ATT&CK Framework

---

## 📂 Project Structure
main.py # Execution engine
parser.py # Log parser
rules.py # Detection rules


---

## 📌 Future Improvements

- Real-time log monitoring
- Support for EVTX logs
- Dashboard visualization
- Advanced detection rules

---

## 🧠 Learning Outcome

This project simulates a mini SIEM detection pipeline and demonstrates how SOC analysts detect threats using log analysis.
